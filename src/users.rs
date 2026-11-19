use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use sha2::{Digest, Sha512};

pub const DB_FILE: &str = "users.db";

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS users (
    user_name   TEXT    NOT NULL UNIQUE,
    pass_phrase TEXT    NOT NULL UNIQUE,
    is_admin    BOOLEAN NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    user_name     TEXT    NOT NULL REFERENCES users(user_name) ON DELETE CASCADE,
    cookie_string TEXT    NOT NULL UNIQUE,
    timestamp     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_name)";

/// Foreign keys, a write busy timeout, and every table the file should have.
fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch(&format!("PRAGMA foreign_keys = ON;\n{SCHEMA}"))
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

/// Hex SHA-512 of the normalized phrase; this is what is stored in the database.
pub fn hash_phrase(s: &str) -> String {
    Sha512::digest(normalize_phrase(s).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Open (creating if needed) the database for `add-user`.
pub fn open_for_add(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    init(&conn)?;
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
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    conn.query_row("SELECT COUNT(*) FROM users", [], |_| Ok(()))
        .map_err(|_| format!("{} does not contain a users table", path.display()))?;
    init(&conn).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    Ok(conn)
}

/// Remove the user `name` and their sessions; returns whether a row was deleted.
pub fn remove_user(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM sessions WHERE user_name = ?1", [name])?;
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
        let problem = if phrase.is_empty() {
            Some(format!("user '{name}' has no pass phrase"))
        } else if let Some(p) = phrase_problem(&phrase) {
            Some(format!("pass phrase for '{name}' {p}"))
        } else if exists(conn, "user_name", name)? {
            Some(format!("user '{name}' already exists"))
        } else if exists(conn, "pass_phrase", &hash_phrase(&phrase))? {
            Some(format!("pass phrase for '{name}' is already in use"))
        } else {
            None
        };
        if let Some(p) = problem {
            let _ = writeln!(err, "line {line_no}: skipped: {p}");
            skipped += 1;
            continue;
        }
        let is_admin = name.to_lowercase().contains("admin");
        conn.execute(
            "INSERT INTO users (user_name, pass_phrase, is_admin) VALUES (?1, ?2, ?3)",
            params![name, hash_phrase(&phrase), is_admin],
        )?;
        added += 1;
    }
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

/// A session row: the SHA-256 of the cookie token, its user, and its expiry.
pub struct StoredSession {
    pub cookie_string: String,
    pub user_name: String,
    pub expires: SystemTime,
}

/// Access to the users database for `serve`: reads users, writes sessions.
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
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .map_err(|_| missing())?;
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
                "SELECT cookie_string, user_name, timestamp FROM sessions \
                 WHERE timestamp > ?1",
            )?
            .query_map([unix_secs(now)], |r| {
                Ok(StoredSession {
                    cookie_string: r.get(0)?,
                    user_name: r.get(1)?,
                    expires: UNIX_EPOCH + Duration::from_secs(r.get::<_, i64>(2)? as u64),
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
            "INSERT INTO sessions (user_name, cookie_string, timestamp) VALUES (?1, ?2, ?3)",
            params![new.user_name, new.cookie_string, unix_secs(new.expires)],
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

    pub fn lookup(&self, phrase: &str) -> rusqlite::Result<Option<User>> {
        self.conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT user_name, is_admin FROM users WHERE pass_phrase = ?1",
                [hash_phrase(phrase)],
                |r| {
                    Ok(User {
                        name: r.get(0)?,
                        is_admin: r.get(1)?,
                    })
                },
            )
            .optional()
    }
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
    fn hash_is_sha512_of_normalized() {
        // SHA-512("abc")
        assert!(hash_phrase(" A b C ").starts_with("ddaf35a193617aba"));
        assert_eq!(hash_phrase("abc").len(), 128);
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
                     carol\n\
                     mallory weak\n\
                     SuperAdmin  Very  Long  Admin  Pass  Phrase 9!\n";
        let mut err = Vec::new();
        let (added, skipped) = add_users(&conn, input.as_bytes(), &mut err).unwrap();
        let err = String::from_utf8(err).unwrap();
        assert_eq!((added, skipped), (2, 4), "{err}");
        assert!(err.contains("line 3: skipped: pass phrase for 'bob' is already in use"));
        assert!(err.contains("line 4: skipped: user 'alice' already exists"));
        assert!(err.contains("line 5: skipped: user 'carol' has no pass phrase"));
        assert!(err.contains("line 6: skipped: pass phrase for 'mallory' is too weak"));
        assert!(!err.to_lowercase().contains("staple"));

        let rows: Vec<(String, String, bool)> = conn
            .prepare("SELECT user_name, pass_phrase, is_admin FROM users ORDER BY rowid")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "alice");
        assert_eq!(rows[0].1, hash_phrase("correcthorsebatterystaple42!"));
        assert!(!rows[0].2);
        assert_eq!(rows[1].0, "SuperAdmin");
        assert!(rows[1].2);
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
                "INSERT INTO sessions (user_name, cookie_string, timestamp) \
                 VALUES (?1, ?2, ?3)",
                params![user, format!("c-{user}"), 999_999_999_999i64],
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
    fn old_database_gains_sessions_table() {
        const OLD_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS users (
            user_name   TEXT    NOT NULL UNIQUE,
            pass_phrase TEXT    NOT NULL UNIQUE,
            is_admin    BOOLEAN NOT NULL
        )";
        let dir = std::env::temp_dir().join(format!("wsb-old-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DB_FILE);

        // A database from before the sessions table existed.
        let conn = Connection::open(&path).unwrap();
        conn.execute(OLD_SCHEMA, []).unwrap();
        conn.execute(
            "INSERT INTO users (user_name, pass_phrase, is_admin) VALUES ('alice', 'h', 0)",
            [],
        )
        .unwrap();
        assert!(!has_table(&conn, "sessions"));
        drop(conn);

        let store = UserStore::open(&path).unwrap();
        assert!(store.load_sessions(SystemTime::now()).unwrap().is_empty());
        drop(store);

        let conn = open_for_remove(&path).unwrap();
        assert!(has_table(&conn, "sessions"));
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

        let store = UserStore::open(&path).unwrap();
        assert_eq!(
            store.lookup("  BIG secret phrase number 99! ").unwrap(),
            Some(User {
                name: "admin1".into(),
                is_admin: true
            })
        );
        assert_eq!(store.lookup("bigsecret!").unwrap(), None);
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
        assert!(store.lookup("anything at all 1!").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
