use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

pub const DB_FILE: &str = "users.db";

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS users (
    user_name   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    salt        TEXT    NOT NULL,
    pass_phrase TEXT    NOT NULL,
    is_admin    BOOLEAN NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    user_name     TEXT    NOT NULL REFERENCES users(user_name) ON DELETE CASCADE,
    cookie_string TEXT    NOT NULL UNIQUE,
    timestamp     INTEGER NOT NULL,
    created       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_name)";

/// Per-connection setup for a file database: a busy timeout (set first so
/// the WAL pragma also waits) and WAL journal mode, which puts live data in
/// users.db-wal/-shm as well — required for Litestream backups.
fn configure(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    let mode: String =
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get::<_, String>(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
            Some(format!(
                "WAL journal mode could not be enabled (got {mode:?})"
            )),
        ));
    }
    Ok(())
}

/// Foreign keys, a write busy timeout, and every table the file should have.
fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(&format!(
        "PRAGMA busy_timeout = 5000;\nPRAGMA foreign_keys = ON;\n{SCHEMA}"
    ))
}

/// True for sqlite's "no such table" error (vs. locking or corruption).
fn is_no_table(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(_, Some(m)) if m.contains("no such table"))
}

fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

/// Remove all whitespace and lower-case the phrase.
pub fn normalize_phrase(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

pub const MIN_PHRASE_CHARS: usize = 20;

/// Problems with a pass phrase under the policy, or None if it is acceptable.
pub fn phrase_problem(phrase: &str) -> Option<String> {
    let chars: Vec<char> = phrase.chars().filter(|c| !c.is_whitespace()).collect();
    let mut problems = Vec::new();
    if chars.len() < MIN_PHRASE_CHARS {
        problems.push(format!(
            "at least {MIN_PHRASE_CHARS} non-whitespace characters (has {})",
            chars.len()
        ));
    }
    if !chars.iter().any(|c| c.is_ascii_digit()) {
        problems.push("a number".to_string());
    }
    if !chars.iter().any(|c| c.is_ascii_punctuation()) {
        problems.push("a punctuation character".to_string());
    }
    if problems.is_empty() {
        None
    } else {
        Some(format!("is too weak: needs {}", problems.join(", ")))
    }
}

/// 16 random bytes as hex; a fresh per-user salt for `add-user`.
pub fn new_salt() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Argon2id parameters: OWASP's 12 MiB / t=3, p=1 option, chosen because the
/// target server has ~67 MB free.
const ARGON2_M_COST_KIB: u32 = 12 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const ARGON2_OUT_LEN: usize = 32;

/// Fixed salt hashed for unknown user names so lookup time is uniform.
const DUMMY_SALT: &str = "00000000000000000000000000000000";

/// Argon2id (version 0x13) of the normalized phrase with the per-user salt,
/// as lowercase hex; this is what is stored in the database.
pub fn hash_phrase(salt: &str, phrase: &str) -> String {
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUT_LEN),
    )
    .expect("fixed argon2 parameters are valid");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; ARGON2_OUT_LEN];
    argon2
        .hash_password_into(
            normalize_phrase(phrase).as_bytes(),
            salt.as_bytes(),
            &mut out,
        )
        .expect("fixed-size salt and output are valid");
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// Column names of `table`, or an empty Vec if it does not exist.
fn table_columns(conn: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    conn.prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect()
}

/// True if the file's schema predates the current one (a `users` table
/// without `salt`, or a `sessions` table without `created`) and cannot be
/// migrated.
fn stale_schema(conn: &Connection) -> rusqlite::Result<bool> {
    let users = table_columns(conn, "users")?;
    if !users.is_empty() && !users.iter().any(|c| c == "salt") {
        return Ok(true);
    }
    let sessions = table_columns(conn, "sessions")?;
    Ok(!sessions.is_empty() && !sessions.iter().any(|c| c == "created"))
}

fn stale_schema_err(path: &Path) -> String {
    format!(
        "{} predates the current schema (per-user salts, session creation stamps); stop serve, move users.db together with \
         users.db-wal and users.db-shm aside, and re-add users with: \
         web-safe-block add-user < users.txt",
        path.display()
    )
}

/// Create an empty db file mode 0600 so SQLite opens it owner-only;
/// SQLite's unix VFS gives -wal/-shm files the db file's permissions.
#[cfg(unix)]
fn create_private_db(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(format!("cannot create {}: {e}", path.display())),
    }
}

#[cfg(not(unix))]
fn create_private_db(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Warn (never chmod) if an existing db is accessible to group/other users.
#[cfg(unix)]
fn warn_if_exposed(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(md) = path.metadata() else { return };
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        eprintln!(
            "web-safe-block: warning: {} is accessible to other users \
             (mode {mode:04o}); run: chmod 600 {}",
            path.display(),
            path.display()
        );
    }
}

#[cfg(not(unix))]
fn warn_if_exposed(_path: &Path) {}

/// Open (creating if needed) the database for `add-user`.
pub fn open_for_add(path: &Path) -> Result<Connection, String> {
    let cannot_open = |e: rusqlite::Error| format!("cannot open {}: {e}", path.display());
    if !path.exists() {
        create_private_db(path)?;
    }
    warn_if_exposed(path);
    let conn = Connection::open(path).map_err(cannot_open)?;
    configure(&conn).map_err(cannot_open)?;
    if stale_schema(&conn).map_err(cannot_open)? {
        return Err(stale_schema_err(path));
    }
    init(&conn).map_err(cannot_open)?;
    Ok(conn)
}

/// Open an existing database read-write for `remove-user`.
pub fn open_for_remove(path: &Path) -> Result<Connection, String> {
    if !path.exists() {
        return Err(format!(
            "no users database at {}; add users with: web-safe-block add-user < users.txt",
            path.display()
        ));
    }
    warn_if_exposed(path);
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    configure(&conn).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    conn.query_row("SELECT COUNT(*) FROM users", [], |_| Ok(()))
        .map_err(|e| {
            if is_no_table(&e) {
                format!("{} does not contain a users table", path.display())
            } else {
                format!("cannot open {}: {e}", path.display())
            }
        })?;
    if stale_schema(&conn).map_err(|e| format!("cannot open {}: {e}", path.display()))? {
        return Err(stale_schema_err(path));
    }
    init(&conn).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    Ok(conn)
}

/// Remove the user `name` and their sessions; returns whether a row was deleted.
pub fn remove_user(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    let name = name.trim();
    let tx = conn.unchecked_transaction()?;
    // Sessions.user_name has BINARY collation; match the stored spelling so
    // a differently-cased argument still deletes the user's sessions.
    tx.execute(
        "DELETE FROM sessions WHERE user_name = \
         (SELECT user_name FROM users WHERE user_name = ?1)",
        [name],
    )?;
    let removed = tx.execute("DELETE FROM users WHERE user_name = ?1", [name])?;
    tx.commit()?;
    Ok(removed > 0)
}

/// Every user, sorted by name.
pub fn list_users(conn: &Connection) -> rusqlite::Result<Vec<User>> {
    conn.prepare("SELECT user_name, is_admin FROM users ORDER BY user_name")?
        .query_map([], |r| {
            Ok(User {
                name: r.get(0)?,
                is_admin: r.get(1)?,
            })
        })?
        .collect()
}

/// Read `user-name pass phrase words...` lines and insert them. Bad lines are
/// reported to `err` and skipped. Returns (added, skipped).
pub fn add_users(
    conn: &Connection,
    input: impl BufRead,
    err: &mut impl Write,
) -> rusqlite::Result<(usize, usize)> {
    let tx = conn.unchecked_transaction()?;
    let (mut added, mut skipped) = (0, 0);
    for (i, line) in input.lines().enumerate() {
        let line_no = i + 1;
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                let _ = writeln!(err, "line {line_no}: unreadable: {e}");
                skipped += 1;
                continue;
            }
        };
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { continue };
        let phrase: String = words.collect();
        let problem = if name.len() > 64 || !name.chars().all(|c| c.is_ascii_graphic()) {
            Some(format!(
                "user name '{name}' must be 1-64 printable ASCII characters"
            ))
        } else if phrase.is_empty() {
            Some(format!("user '{name}' has no pass phrase"))
        } else if let Some(p) = phrase_problem(&phrase) {
            Some(format!("pass phrase for '{name}' {p}"))
        } else if exists(&tx, "user_name", name)? {
            Some(format!("user '{name}' already exists"))
        } else {
            None
        };
        if let Some(p) = problem {
            let _ = writeln!(err, "line {line_no}: skipped: {p}");
            skipped += 1;
            continue;
        }
        let is_admin = name.to_lowercase().contains("admin");
        let salt = new_salt();
        tx.execute(
            "INSERT INTO users (user_name, salt, pass_phrase, is_admin) \
             VALUES (?1, ?2, ?3, ?4)",
            params![name, salt, hash_phrase(&salt, &phrase), is_admin],
        )?;
        added += 1;
    }
    tx.commit()?;
    Ok((added, skipped))
}

fn exists(conn: &Connection, column: &str, value: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        &format!("SELECT 1 FROM users WHERE {column} = ?1"),
        [value],
        |_| Ok(()),
    )
    .optional()
    .map(|r| r.is_some())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub is_admin: bool,
}

/// A session row: the SHA-256 of the cookie token, its user, its expiry, and
/// its creation stamp (unix microseconds, unique and increasing).
pub struct StoredSession {
    pub cookie_string: String,
    pub user_name: String,
    pub expires: SystemTime,
    pub created: i64,
}

/// Access to the users database for `serve`: reads users, writes sessions.
/// These are blocking calls; async callers should use `spawn_blocking` and
/// serialize hashing through `AppState::hash_slot`.
#[derive(Debug)]
pub struct UserStore {
    conn: Mutex<Connection>,
}

impl UserStore {
    /// Open an existing database; errors if it is missing or has no users.
    pub fn open(path: &Path) -> Result<Self, String> {
        let hint = "add users with: web-safe-block add-user < users.txt";
        let missing = || format!("no users database at {}; {hint}", path.display());
        if !path.exists() {
            return Err(missing());
        }
        warn_if_exposed(path);
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        configure(&conn).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .map_err(|e| {
                if is_no_table(&e) {
                    missing()
                } else {
                    format!("cannot open {}: {e}", path.display())
                }
            })?;
        if stale_schema(&conn).map_err(|e| format!("cannot open {}: {e}", path.display()))? {
            return Err(stale_schema_err(path));
        }
        if count == 0 {
            return Err(format!(
                "users database {} has no users; {hint}",
                path.display()
            ));
        }
        init(&conn).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        Ok(UserStore {
            conn: Mutex::new(conn),
        })
    }

    /// Every user, sorted by name.
    pub fn list(&self) -> rusqlite::Result<Vec<User>> {
        list_users(&self.conn.lock().unwrap())
    }

    /// Every session whose expiry is still in the future.
    pub fn load_sessions(&self, now: SystemTime) -> rusqlite::Result<Vec<StoredSession>> {
        self.conn
            .lock()
            .unwrap()
            .prepare(
                "SELECT cookie_string, user_name, timestamp, created FROM sessions \
                 WHERE timestamp > ?1",
            )?
            .query_map([unix_secs(now)], |r| {
                Ok(StoredSession {
                    cookie_string: r.get(0)?,
                    user_name: r.get(1)?,
                    expires: UNIX_EPOCH + Duration::from_secs(r.get::<_, i64>(2)? as u64),
                    created: r.get(3)?,
                })
            })?
            .collect()
    }

    /// Insert `new` and delete each `removed` cookie string, in one transaction.
    pub fn save_session(&self, new: &StoredSession, removed: &[String]) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        for cookie in removed {
            tx.execute("DELETE FROM sessions WHERE cookie_string = ?1", [cookie])?;
        }
        tx.execute(
            "INSERT INTO sessions (user_name, cookie_string, timestamp, created) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                new.user_name,
                new.cookie_string,
                unix_secs(new.expires),
                new.created
            ],
        )?;
        tx.commit()
    }

    /// Delete the sessions with these cookie strings, if they exist.
    pub fn delete_sessions(&self, cookie_strings: &[String]) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("DELETE FROM sessions WHERE cookie_string = ?1")?;
        for cookie in cookie_strings {
            stmt.execute([cookie])?;
        }
        Ok(())
    }

    /// Delete sessions at or past their expiry; returns how many were removed.
    pub fn delete_expired_sessions(&self, now: SystemTime) -> rusqlite::Result<usize> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM sessions WHERE timestamp <= ?1",
            [unix_secs(now)],
        )
    }

    /// The user named `user_name` (case-insensitive) if `phrase` matches their
    /// salted hash; None for an unknown name or wrong phrase. Always runs one
    /// Argon2 hash so response time doesn't reveal whether the name exists.
    pub fn lookup(&self, user_name: &str, phrase: &str) -> rusqlite::Result<Option<User>> {
        let row = self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT user_name, salt, pass_phrase, is_admin FROM users \
                 WHERE user_name = ?1",
                [user_name.trim()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, bool>(3)?,
                    ))
                },
            )
            .optional()?;
        // Callers serialize hashing (AppState::hash_slot) so at most one
        // 12 MiB Argon2 run happens at a time.
        match row {
            Some((name, salt, hash, is_admin)) => {
                Ok(hex_eq(&hash_phrase(&salt, phrase), &hash).then_some(User { name, is_admin }))
            }
            None => {
                let _ = hash_phrase(DUMMY_SALT, phrase);
                Ok(None)
            }
        }
    }
}

/// Constant-time comparison of two same-format hash strings (hex).
fn hex_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        conn
    }

    fn has_table(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
            > 0
    }

    #[test]
    fn normalize_cases() {
        assert_eq!(normalize_phrase("  Open  Sesame\t\n"), "opensesame");
        assert_eq!(normalize_phrase("ÄBC d"), "äbcd");
    }

    #[test]
    fn hash_is_argon2id_of_normalized() {
        // Deterministic, and the phrase is normalized before hashing.
        assert_eq!(
            hash_phrase("aaaaaaaa", "abc"),
            hash_phrase("aaaaaaaa", "abc")
        );
        assert_eq!(
            hash_phrase("aaaaaaaa", " A b C "),
            hash_phrase("aaaaaaaa", "abc")
        );
        assert_eq!(hash_phrase("aaaaaaaa", "abc").len(), 64);
        // Same phrase, different salts -> different hashes.
        assert_ne!(
            hash_phrase("aaaaaaaa", "abc"),
            hash_phrase("bbbbbbbb", "abc")
        );
        // Known answer: computed independently via the argon2 crate.
        let params = Params::new(12 * 1024, 3, 1, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut expected = [0u8; 32];
        argon2
            .hash_password_into(b"abc", b"somesalt", &mut expected)
            .unwrap();
        let expected = expected
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(hash_phrase("somesalt", "abc"), expected);
    }

    #[test]
    fn phrase_problem_cases() {
        // Exactly 20 non-whitespace chars with digit and punctuation is fine.
        assert_eq!(phrase_problem("abcd efgh ijkl mnop qr1!"), None);
        // 19 is rejected.
        let p = phrase_problem("abcdefghijklmnopqrs").unwrap();
        assert!(
            p.contains("at least 20 non-whitespace characters (has 19)"),
            "{p}"
        );
        // Whitespace is not counted.
        let p = phrase_problem("a b c d e f g h i j 1 !").unwrap();
        assert!(p.contains("(has 12)"), "{p}");
        // Missing digit.
        let p = phrase_problem("abcdefghij!klmnopqrst").unwrap();
        assert_eq!(p, "is too weak: needs a number");
        // Missing punctuation.
        let p = phrase_problem("abcdefghij1klmnopqrst").unwrap();
        assert_eq!(p, "is too weak: needs a punctuation character");
        // Several problems are listed together.
        let p = phrase_problem("short").unwrap();
        assert_eq!(
            p,
            "is too weak: needs at least 20 non-whitespace characters (has 5), a number, a punctuation character"
        );
    }

    #[test]
    fn add_users_rules() {
        let conn = mem_db();
        let input = "alice Correct Horse Battery Staple 42!\n\
                     \n\
                     bob correct horse battery staple 42!\n\
                     alice Another Valid Phrase 99!\n\
                     ALICE Yet Another Valid Phrase 88!\n\
                     carol\n\
                     mallory weak\n\
                     SuperAdmin  Very  Long  Admin  Pass  Phrase 9!\n";
        let mut err = Vec::new();
        let (added, skipped) = add_users(&conn, input.as_bytes(), &mut err).unwrap();
        let err = String::from_utf8(err).unwrap();
        assert_eq!((added, skipped), (3, 4), "{err}");
        assert!(err.contains("line 4: skipped: user 'alice' already exists"));
        assert!(err.contains("line 5: skipped: user 'ALICE' already exists"));
        assert!(err.contains("line 6: skipped: user 'carol' has no pass phrase"));
        assert!(err.contains("line 7: skipped: pass phrase for 'mallory' is too weak"));
        assert!(!err.to_lowercase().contains("staple"));

        let rows: Vec<(String, String, String, bool)> = conn
            .prepare("SELECT user_name, salt, pass_phrase, is_admin FROM users ORDER BY rowid")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].0, "alice");
        assert_eq!(rows[0].1.len(), 32, "salt is 16 hex bytes");
        assert_eq!(
            rows[0].2,
            hash_phrase(&rows[0].1, "correcthorsebatterystaple42!")
        );
        assert!(!rows[0].3);
        // bob may share alice's phrase, but his salt and hash differ.
        assert_eq!(rows[1].0, "bob");
        assert_eq!(
            rows[1].2,
            hash_phrase(&rows[1].1, "correct horse battery staple 42!")
        );
        assert_ne!(rows[0].1, rows[1].1);
        assert_ne!(rows[0].2, rows[1].2);
        assert_eq!(rows[2].0, "SuperAdmin");
        assert!(rows[2].3);
    }

    #[test]
    fn add_users_rejects_bad_names() {
        let conn = mem_db();
        let long = "x".repeat(65);
        let input = format!(
            "{long} Correct Horse Battery Staple 42!\n\
             bad\x07name Correct Horse Battery Staple 42!\n\
             naïf Correct Horse Battery Staple 42!\n\
             good-name Correct Horse Battery Staple 42!\n"
        );
        let mut err = Vec::new();
        let (added, skipped) = add_users(&conn, input.as_bytes(), &mut err).unwrap();
        let err = String::from_utf8(err).unwrap();
        assert_eq!((added, skipped), (1, 3), "{err}");
        assert!(err.contains("1-64 printable ASCII"), "{err}");
    }

    #[test]
    fn remove_user_cases() {
        let conn = mem_db();
        add_users(
            &conn,
            "alice Correct Horse Battery 42!\nbob Another Fine Phrase 77!\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        let store_sessions = |user: &str| {
            conn.execute(
                "INSERT INTO sessions (user_name, cookie_string, timestamp, created) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![user, format!("c-{user}"), 999_999_999_999i64, 1i64],
            )
            .unwrap();
        };
        store_sessions("alice");
        store_sessions("bob");
        assert!(remove_user(&conn, "alice").unwrap());
        let left: i64 = conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1, "bob's session survives");
        assert!(!remove_user(&conn, "alice").unwrap());
        assert!(!remove_user(&conn, "carol").unwrap());
        let names: Vec<String> = conn
            .prepare("SELECT user_name FROM users")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(names, ["bob"]);
    }

    fn session(user: &str, cookie: &str, secs_from_now: i64) -> StoredSession {
        StoredSession {
            cookie_string: cookie.to_string(),
            user_name: user.to_string(),
            expires: if secs_from_now >= 0 {
                SystemTime::now() + Duration::from_secs(secs_from_now as u64)
            } else {
                SystemTime::now() - Duration::from_secs((-secs_from_now) as u64)
            },
            created: 1,
        }
    }

    fn mem_store() -> UserStore {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        UserStore {
            conn: Mutex::new(conn),
        }
    }

    #[test]
    fn session_roundtrip() {
        let store = mem_store();
        let conn = store.conn.lock().unwrap();
        add_users(
            &conn,
            "alice Correct Horse Battery 42!\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        drop(conn);

        store
            .save_session(&session("alice", "live", 600), &[])
            .unwrap();
        store
            .save_session(&session("alice", "dead", -10), &[])
            .unwrap();
        let loaded = store.load_sessions(SystemTime::now()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].cookie_string, "live");
        assert_eq!(loaded[0].user_name, "alice");

        // Replacing removes the old rows in the same transaction.
        store
            .save_session(&session("alice", "newer", 600), &["live".into()])
            .unwrap();
        let loaded = store.load_sessions(SystemTime::now()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].cookie_string, "newer");

        store
            .delete_sessions(&["newer".into(), "absent".into()])
            .unwrap();
        assert!(store.load_sessions(SystemTime::now()).unwrap().is_empty());

        store
            .save_session(&session("alice", "gone", -1), &[])
            .unwrap();
        // "dead" (saved above) and "gone" are both expired.
        assert_eq!(store.delete_expired_sessions(SystemTime::now()).unwrap(), 2);
        assert_eq!(store.delete_expired_sessions(SystemTime::now()).unwrap(), 0);
    }

    #[test]
    fn session_for_missing_user_fails() {
        let store = mem_store();
        assert!(
            store.save_session(&session("ghost", "c", 60), &[]).is_err(),
            "foreign key enforced"
        );
    }

    #[test]
    fn old_database_without_salts_rejected() {
        const OLD_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS users (
            user_name   TEXT    NOT NULL UNIQUE,
            pass_phrase TEXT    NOT NULL UNIQUE,
            is_admin    BOOLEAN NOT NULL
        )";
        let dir = std::env::temp_dir().join(format!("wsb-old-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DB_FILE);

        // A database from before per-user salts existed cannot be migrated.
        let conn = Connection::open(&path).unwrap();
        conn.execute(OLD_SCHEMA, []).unwrap();
        conn.execute(
            "INSERT INTO users (user_name, pass_phrase, is_admin) VALUES ('alice', 'h', 0)",
            [],
        )
        .unwrap();
        drop(conn);

        for err in [
            open_for_add(&path).map(|_| ()).unwrap_err(),
            open_for_remove(&path).map(|_| ()).unwrap_err(),
            UserStore::open(&path).map(|_| ()).unwrap_err(),
        ] {
            assert!(err.contains("predates the current schema"), "{err}");
            assert!(err.contains("add-user < users.txt"), "{err}");
        }

        // The database is left untouched.
        let conn = Connection::open(&path).unwrap();
        assert!(!has_table(&conn, "sessions"));
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_sessions_table_without_created_rejected() {
        const OLD_SESSIONS: &str = "CREATE TABLE sessions (
            user_name     TEXT    NOT NULL,
            cookie_string TEXT    NOT NULL UNIQUE,
            timestamp     INTEGER NOT NULL
        )";
        let dir = std::env::temp_dir().join(format!("wsb-oldsess-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DB_FILE);

        // A current users table but a sessions table without `created`.
        let conn = open_for_add(&path).unwrap();
        add_users(
            &conn,
            "alice Correct Horse Battery 42!\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        conn.execute("DROP TABLE sessions", []).unwrap();
        conn.execute(OLD_SESSIONS, []).unwrap();
        drop(conn);

        for err in [
            open_for_add(&path).map(|_| ()).unwrap_err(),
            open_for_remove(&path).map(|_| ()).unwrap_err(),
            UserStore::open(&path).map(|_| ()).unwrap_err(),
        ] {
            assert!(err.contains("predates the current schema"), "{err}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_users_sorted() {
        let conn = mem_db();
        add_users(
            &conn,
            "bob Correct Horse Battery 42!\nadmin-alice Another Fine Phrase 77!\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            list_users(&conn).unwrap(),
            [
                User {
                    name: "admin-alice".into(),
                    is_admin: true
                },
                User {
                    name: "bob".into(),
                    is_admin: false
                },
            ]
        );
    }

    #[test]
    fn store_open_and_lookup() {
        let dir = std::env::temp_dir().join(format!("wsb-users-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DB_FILE);
        let _ = std::fs::remove_file(&path);

        assert!(UserStore::open(&path).unwrap_err().contains("add-user"));
        let conn = open_for_add(&path).unwrap();
        assert!(UserStore::open(&path).unwrap_err().contains("no users"));
        add_users(
            &conn,
            "admin1 Big Secret Phrase Number 99!\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        drop(conn);

        let conn = open_for_add(&path).unwrap();
        add_users(
            &conn,
            "Alice Another Good Phrase 77!\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        drop(conn);
        let store = UserStore::open(&path).unwrap();
        // Right name + right phrase -> the stored name.
        assert_eq!(
            store
                .lookup("admin1", "  BIG secret phrase number 99! ")
                .unwrap(),
            Some(User {
                name: "admin1".into(),
                is_admin: true
            })
        );
        // Name matching ignores case and surrounding whitespace.
        assert_eq!(
            store
                .lookup("  ADMIN1  ", "big secret phrase number 99!")
                .unwrap(),
            Some(User {
                name: "admin1".into(),
                is_admin: true
            })
        );
        // Wrong name with a right phrase -> None.
        assert_eq!(
            store
                .lookup("carol", "big secret phrase number 99!")
                .unwrap(),
            None
        );
        assert_eq!(
            store.lookup("", "big secret phrase number 99!").unwrap(),
            None
        );
        // Right name with another user's phrase -> None.
        assert_eq!(
            store.lookup("admin1", "another good phrase 77!").unwrap(),
            None
        );
        // Alice's own phrase works for her.
        assert_eq!(
            store.lookup("alice", "another good phrase 77!").unwrap(),
            Some(User {
                name: "Alice".into(),
                is_admin: false
            })
        );
        assert_eq!(store.lookup("admin1", "bigsecret!").unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn file_dbs_use_wal_journal_mode() {
        let dir = std::env::temp_dir().join(format!("wsb-wal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DB_FILE);
        let _ = std::fs::remove_file(&path);

        let mode: String = open_for_add(&path)
            .unwrap()
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");

        let conn = open_for_add(&path).unwrap();
        add_users(
            &conn,
            "alice Correct Horse Battery 42!\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        drop(conn);
        let store = UserStore::open(&path).unwrap();
        let mode: String = store
            .conn
            .lock()
            .unwrap()
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lookup_reports_db_errors() {
        let dir = std::env::temp_dir().join(format!("wsb-users-err-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DB_FILE);
        let conn = open_for_add(&path).unwrap();
        add_users(
            &conn,
            "alice Correct Horse Battery 42!\n".as_bytes(),
            &mut Vec::new(),
        )
        .unwrap();
        drop(conn);
        let store = UserStore::open(&path).unwrap();
        open_for_add(&path)
            .unwrap()
            .execute("DROP TABLE users", [])
            .unwrap();
        assert!(store.lookup("alice", "anything at all 1!").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
