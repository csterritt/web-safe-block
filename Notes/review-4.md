# Code Review 4

Reviewed the repository at `010e986d7e60ccd74ae07231e7efc81e22c50092` (`Cargo.toml`, `src/`, `tests/proxy.rs`, `scripts/`, `README.md`, and `Notes/atlas/`).

Commits `e219cad` and `010e986` resolved the major issues raised in `Notes/review-3.md` — fixing the `Connection`-header spoofing vector, stopping successful logins from wiping prior failure counts, persisting sessions before mutating memory on login, adding a 4 KiB login body limit and `GET /__wsb/login` redirect, handling multiple `wsb_session` cookies and `obs-text` `Set-Cookie` headers, enabling SQLite WAL mode for Litestream, and adding graceful shutdown. Deliberate trade-offs recorded in `Notes/review-3-notes.md` (the monitor's 100 ms `PROBE_WAIT`, mandatory `ConnectInfo`, log timestamps, and `OPTIONS *`) are respected below rather than re-litigated.

*Verification note:* `cargo fmt --all -- --check` passed. `cargo clippy` and `cargo test` could not link in this container because no system C linker / CRT libraries (`cc`, `crtbeginS.o`, `libgcc_s`) are installed; all findings below are verified directly against the source and vendored crate implementations.

Part 1 lists prioritized findings ordered by severity. Part 2 evaluates the codebase across each of the ten requested review dimensions.

---

## Part 1: Prioritized Findings

### 1. [High] Async cancellation in `auth::login` and `auth::logout` drops `hash_slot` and `session_writes` guards while `spawn_blocking` tasks are still running — enabling OOM bypass of Argon2 serialization and DB/memory session desynchronization

**Locations:** `src/auth.rs:76-81, 110-155, 231-262`.

All three `spawn_blocking` call sites in `src/auth.rs` hold a `tokio::sync::MutexGuard` in the **async request future** across the `.await`, rather than moving an `OwnedMutexGuard` into the blocking closure:

```rust
// src/auth.rs:76-81
let looked_up = {
    let _hash = state.hash_slot.lock().await;
    let users = state.config.users.clone();
    let (user_name, phrase) = (form.user.clone(), form.phrase.clone());
    tokio::task::spawn_blocking(move || users.lookup(&user_name, &phrase)).await
};
```

In Tokio, dropping a `JoinHandle` returned by `spawn_blocking` **does not cancel** the OS blocking thread — it continues running to completion. When an HTTP client disconnects or resets the TCP connection right after sending a `POST`, Hyper cancels and drops the handler future immediately:

1. **OOM bypass of the 12 MiB Argon2 serialization (`hash_slot`):** Dropping the `login` future immediately drops `_hash`, releasing `state.hash_slot` while the blocking thread is still computing Argon2id (~12 MiB working memory). The next waiting request immediately acquires `hash_slot` and spawns another concurrent 12 MiB Argon2id run. Even a single IP (within its 10-attempt rate-limit budget) sending 6–10 `POST /__wsb/login` requests and immediately closing each socket can force 6–10 Argon2id hashes to execute **in parallel** on Tokio's blocking pool (default max 512 threads), allocating 72–120+ MiB simultaneously and triggering the OOM killer on the documented 67 MB free-RAM server.
2. **Broken `session_writes` serialization and DB/memory divergence on `login` (`src/auth.rs:110-155`):** If the client disconnects while `users.save_session(&stored, &removed)` is executing (e.g. waiting briefly on SQLite I/O or lock contention), `last_created` (`MutexGuard` for `state.session_writes`) is dropped early while `save_session` continues and commits to SQLite. Lines 141–154 never execute, so `state.sessions` retains the evicted `removed` sessions (accepted for up to 60 seconds) and omits `stored`, while concurrent `login`/`logout`/`reload_sessions` tasks can race with the still-running SQLite write.
3. **Silent revocation lag on `logout` (`src/auth.rs:231-262`):** If the client disconnects while `users.delete_sessions(&present)` is running, `_writes` is dropped early while SQLite deletes the rows, and lines 257–260 never remove the hashes from `state.sessions` (leaving revoked sessions valid in memory until the next 60 s reload).

**Recommendation:** Acquire owned guards with `lock_owned().await` and move them into the `spawn_blocking` closures:
- Move `_hash = state.hash_slot.clone().lock_owned().await` into the `users.lookup` blocking closure so the 12 MiB slot is held until Argon2id actually finishes.
- Move `last_created = state.session_writes.clone().lock_owned().await` (and `_writes`) into the `save_session` / `delete_sessions` blocking closures, and perform the in-memory `state.sessions` mutation inside the blocking closure immediately after the SQLite write succeeds and before the owned guard drops.

---

### 2. [High] `add_users` runs a `BEGIN DEFERRED` read-before-write transaction and holds the SQLite WAL write lock across stdin reads and all Argon2id hashes — causing immediate `SQLITE_BUSY` failures and stalling `serve`

**Locations:** `src/users.rs:274-323`.

`add_users` wraps the entire stdin loop in a single `BEGIN DEFERRED` transaction (`conn.unchecked_transaction()`):

```rust
let tx = conn.unchecked_transaction()?;
let (mut added, mut skipped) = (0, 0);
for (i, line) in input.lines().enumerate() {
    // ...
    } else if exists(&tx, "user_name", name)? {
        Some(format!("user '{name}' already exists"))
    // ...
    let salt = new_salt();
    tx.execute(
        "INSERT INTO users (user_name, salt, pass_phrase, is_admin) \
         VALUES (?1, ?2, ?3, ?4)",
        params![name, salt, hash_phrase(&salt, &phrase), is_admin],
    )?;
```

This creates two severe SQLite WAL concurrency bugs whenever `add-user` runs alongside a live `serve` process:

1. **Deferred read-to-write upgrade bypasses `busy_timeout`:** On the first valid line, `exists(&tx, "user_name", name)?` executes a `SELECT` inside the `BEGIN DEFERRED` transaction, opening a read snapshot. Next, `hash_phrase(&salt, &phrase)` spends ~16+ ms computing Argon2id. Then `tx.execute("INSERT ...")` attempts to upgrade that read transaction to a write transaction. In SQLite WAL mode, if `serve` committed *any* write (a login, logout, or the 60 s `delete_expired_sessions`) between the `SELECT` and the `INSERT`, SQLite **immediately fails with `SQLITE_BUSY` (`SQLITE_BUSY_SNAPSHOT`) without honoring `busy_timeout`** (waiting cannot resolve a stale read snapshot).
2. **Long-held WAL write lock starves `serve`:** Once line 1's `INSERT` succeeds, `add-user` holds the database's single WAL write lock across **all remaining stdin reads and Argon2id hashes** until EOF and `tx.commit()`. If the operator adds a batch of users (e.g. 300+ users, or fewer if `ARGON2_T_COST` is raised per `README.md:80`) or types lines interactively at a terminal and pauses > 5 seconds before Ctrl-D, every `login` and `logout` in `serve` exceeds its 5-second `busy_timeout` and fails with `500 Internal Server Error`.

**Recommendation:** Read, validate, deduplicate (case-insensitively against both existing users and earlier lines in the batch), and compute all Argon2id hashes **outside** any write transaction. Then open a `BEGIN IMMEDIATE` transaction (`conn.unchecked_transaction_with_behavior(TransactionBehavior::Immediate)` or `Transaction::new_unchecked(..., TransactionBehavior::Immediate)`), re-check duplicates or rely on `UNIQUE` constraint errors, insert all rows rapidly (microseconds), and commit.

---

### 3. [High] Non-UTF-8 (`obs-text`) bytes in any sibling cookie cause `parse_cookies` to drop the entire `Cookie` header — locking out valid users and causing `POST /__wsb/logout` to skip DB session revocation

**Locations:** `src/util.rs:14-27`, `src/sessions.rs:42-61`, `src/auth.rs:216-249`.

Commit `e219cad` updated `strip_session_cookie` (`src/util.rs:32-55`) and `sets_session_cookie` (`src/util.rs:136-141`) to operate on raw bytes (`as_bytes()`) so that RFC 6265 / HTTP `obs-text` bytes (`0x80..=0xFF`) in cookies are handled safely. However, `parse_cookies` (`src/util.rs:14-27`) was left using `hv.to_str()`:

```rust
pub(crate) fn parse_cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for hv in headers.get_all(header::COOKIE).iter() {
        if let Ok(s) = hv.to_str() {
            // ...
```

Browsers concatenate all cookies for a domain onto a single `Cookie` header (`Cookie: app=\xff; wsb_session=<valid_64_hex_token>`). Whenever a protected upstream app sets *any* cookie containing a non-UTF-8 byte:

1. **User locked out into a `401` loop:** `valid_session` (`src/sessions.rs:43`) calls `parse_cookies`, which rejects the entire `Cookie` header because `hv.to_str()` returns `Err`. The valid `wsb_session` cookie is ignored, and every request receives `401 Unauthorized` even right after logging in.
2. **Broken server-side logout revocation:** On `POST /__wsb/logout` (`src/auth.rs:216-249`), `parse_cookies` returns an empty `Vec`. `present.is_empty()` evaluates to `true`, so `logout` responds `303 See Other` with `Set-Cookie: wsb_session=; Max-Age=0` **without deleting the session from `users.db` or `state.sessions`**. The user is told they logged out, while the session token remains valid in the database for up to 180 days.

**Recommendation:** Parse `Cookie` headers on raw bytes (`hv.as_bytes().split(|b| *b == b';')`), matching the approach in `strip_session_cookie`. Extract `(name, value)` for each semicolon-separated pair individually, converting valid UTF-8 pairs (or specifically matching `name == SESSION_COOKIE.as_bytes()` and decoding the ASCII hex token) so an `obs-text` byte in a sibling cookie can never hide `wsb_session`.

---

### 4. [Medium] IPv6 `/128` rate-limit keying and unbounded `hash_slot` wait queue allow brute-force rate-limit bypass and login DoS

**Locations:** `src/util.rs:200-208`, `src/auth.rs:59-81`, `src/rate_limit.rs:11-49`.

1. **IPv6 prefix rotation bypasses per-IP rate limiting:** `client_key` (`src/util.rs:200-208`) parses `CF-Connecting-IP` as an `IpAddr` and formats the full address (`ip.to_string()`). For IPv6 clients behind Cloudflare, `CF-Connecting-IP` carries a full `/128` address. Any single IPv6 subscriber typically controls at least a `/64` (2^64 addresses) or `/56` prefix and can rotate the host bits on every `POST /__wsb/login`, getting a fresh 10-attempt budget per request, churning `failures` up to `max_failure_keys` (10,000), and bypassing the 10-failures-per-15-minutes throttle completely.
2. **No per-username throttle and no cap on `hash_slot` waiters:** Because rate limiting is keyed solely by client IP and `login` unconditionally awaits `state.hash_slot.lock().await` (`src/auth.rs:77`), a distributed or IPv6-rotating brute-force attack can target one username (e.g. `site-admin`) at ~60 guesses/second (at 16 ms/hash) while queueing an unbounded number of Tokio tasks + open sockets + 4 KiB form buffers behind `hash_slot`, starving legitimate logins indefinitely.

**Recommendation:** For IPv6 addresses, key the rate limiter (not necessarily the monitor log's `ip` field) on the `/64` prefix (e.g., masking the lower 64 bits). Consider also adding a secondary per-username rate limit or bounding the number of concurrent waiters allowed to queue on `hash_slot` (e.g. via a small `Semaphore` with `try_acquire`, returning `429` or `503` when saturated).

---

### 5. [Medium] `IdleTimeoutBody` does not fire on downstream slow-read backpressure, allowing one authenticated client to permanently exhaust all 256 `upstream_permits`

**Locations:** `src/proxy.rs:110-115, 145-210`.

`forward()` acquires an `OwnedSemaphorePermit` from `state.upstream_permits` (cap 256) and stores it inside `IdleTimeoutBody`. However, `IdleTimeoutBody::poll_frame` (`src/proxy.rs:183-201`) only polls `self.sleep` when Hyper calls `poll_frame`:

```rust
fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match Pin::new(&mut self.inner).poll_frame(cx) {
        Poll::Ready(frame) => {
            let deadline = tokio::time::Instant::now() + self.idle;
            self.sleep.as_mut().reset(deadline);
            Poll::Ready(frame.map(|r| r.map_err(io::Error::other)))
        }
        Poll::Pending => match self.sleep.as_mut().poll(cx) {
            // ...
```

1. **Downstream slow-read permit exhaustion (site-wide 503 DoS):** If an authenticated client (or dropped mobile connection without TCP FIN/RST) requests a response larger than kernel/Hyper buffers and stops reading from the TCP socket, Hyper applies backpressure and **stops calling `poll_frame`**. Because `poll_frame` is not called, `self.sleep` is never polled, the 60 s idle timeout never fires, and `_permit` is held indefinitely. Opening 256 slow-reading connections permanently exhausts `upstream_permits`, causing `503 Service Unavailable` for every other user on the server.
2. **Unnecessary timer reset at end-of-stream and unfused timeout:** When `self.inner.poll_frame(cx)` returns `Poll::Ready(None)`, line 190 still registers a fresh 60-second timer on Tokio's wheel before the body is dropped. Also, `poll_frame` does not set a fused `done` flag after returning `TimedOut`.
3. **No server-side HTTP/1.1 header read timeout:** `axum::serve` (`src/main.rs:182`) uses Hyper's default builder with no `http1_header_read_timeout`; if `listen_addr` is reached without a buffering reverse proxy, slow-header connections can hold FDs open indefinitely.

**Recommendation:** Avoid resetting `self.sleep` when `frame.is_none()`, fuse the body after returning `TimedOut`, and consider enforcing a per-user/per-IP cap on concurrent upstream permits or adding a response-write / connection idle timeout at the server layer so slow-reading clients cannot pin global upstream permits indefinitely.

---

### 6. [Medium] WAL-mode file-opening and permission gaps: `configure` mutates rejected DBs before schema validation, `warn_if_exposed` ignores `-wal`/`-shm`, `list-users` opens DB read-write, and `delete_sessions` is non-atomic

**Locations:** `src/users.rs:29-42, 184-196, 202-242, 360-392, 440-447`, `src/main.rs:127-141`.

Commit `010e986` enabled WAL mode via `configure(&conn)` on every open path, introducing several subtle issues:

1. **Rejected / pre-migration databases are mutated on disk before validation:** `open_for_add` (`line 209`), `open_for_remove` (`line 228`), and `UserStore::open` (`line 369`) all invoke `configure(&conn)` — which executes `PRAGMA journal_mode = WAL`, modifying the database header and creating `-wal`/`-shm` sidecar files — **before** checking `stale_schema(&conn)` or checking whether a `users` table exists. Running any command against a pre-migration database (or an unrelated SQLite file accidentally configured in `config.toml`) converts it to WAL mode before rejecting it with an error (contradicting the test comment at `src/users.rs:792`: `"// The database is left untouched."`).
2. **`warn_if_exposed` ignores `users.db-wal` and `users.db-shm`:** `warn_if_exposed` (`src/users.rs:184-196`) only checks `path` (`users.db`). If an existing `users.db` had mode `0644`, SQLite created `users.db-wal` and `users.db-shm` with `0644`. When the operator follows the warning's instruction (`chmod 600 users.db`), the warning disappears on subsequent runs while `users.db-wal` (which stores recent uncheckpointed writes to `users` and `sessions`) and `users.db-shm` remain `0644` (world-readable).
3. **`list-users` requires write access and runs DDL:** `list-users` (`src/main.rs:128`) calls `UserStore::open`, which opens the DB `SQLITE_OPEN_READ_WRITE`, runs `PRAGMA journal_mode = WAL`, and executes `init(&conn)` (`CREATE TABLE IF NOT EXISTS ...`). A read-only inspection command fails on read-only files/backups and performs unnecessary write-mode initialization.
4. **`delete_sessions` is not transactional (`src/users.rs:440-447`):** Unlike `save_session` and `remove_user`, `delete_sessions` runs each `DELETE` statement in autocommit mode without a transaction. When `auth::logout` revokes multiple `wsb_session` cookies (`src/auth.rs:253`), if the first `DELETE` succeeds and the second fails (e.g. `SQLITE_BUSY`), the first session is deleted in SQLite while `auth::logout` returns `500` and keeps both sessions in `state.sessions`, desynchronizing memory and DB.

**Recommendation:**
- Set `conn.busy_timeout(Duration::from_secs(5))` immediately upon opening, validate the schema (`users` table and `!stale_schema`) **before** switching `journal_mode` to `WAL` or running `init(&conn)`.
- Check permissions on `users.db-wal` and `users.db-shm` (if they exist) in `warn_if_exposed`, and mention sidecar files in the warning message when exposed.
- Wrap `delete_sessions` in a `BEGIN IMMEDIATE` transaction so multi-cookie revocations are atomic.
- Open `users.db` read-only for `list-users` (note: in WAL mode SQLite still needs `-shm` if not immutable, or `SQLITE_OPEN_READ_ONLY` when WAL already exists with `-shm`).

---

### 7. [Medium] Quadratic `O(N * R)` eviction scan under the global `state.sessions` mutex in `sessions::evictions`, plus unbounded `reload_sessions` and unconditional 60 s write lock

**Locations:** `src/sessions.rs:67-114, 138-160`, `src/auth.rs:121-125`.

1. **Quadratic scan while holding `state.sessions` mutex:** In `evictions()` (`src/sessions.rs:73-113`), `removed` is a `Vec<String>`. When either session cap is reached and `R` sessions have expired (e.g. `N = 10,000`, `R = 5,000`), lines 83–86 scan every session and call `removed.contains(*k)` (`O(R)` linear search per element):
   ```rust
   for (k, s) in sessions {
       if s.expires <= now {
           removed.push(k.clone());
       }
   }
   len -= removed.len();
   user_count -= sessions
       .iter()
       .filter(|(k, s)| s.user == user && removed.contains(*k))
       .count();
   ```
   Lines 91 and 104 repeat `!removed.contains(*k)` inside `sessions.iter()`. Because `auth::login` (`src/auth.rs:122`) holds `state.sessions.lock().unwrap()` across `evictions()`, a bulk expiry triggers tens of millions of string comparisons under the lock that gates every authenticated request. Counting `user_count` decrements in the first loop and tracking removed keys in a `HashSet<&str>` reduces this to `O(N)`.
2. **Unconditional write transaction every 60 seconds:** `reload_sessions` (`src/sessions.rs:141`) executes `DELETE FROM sessions WHERE timestamp <= ?1` on every purge tick even when zero rows are expired, taking an unnecessary SQLite write lock (and contending with `add-user`/`remove-user`/logins). Checking `SELECT EXISTS(SELECT 1 FROM sessions WHERE timestamp <= ?1)` (a pure WAL snapshot read) before issuing `DELETE` avoids idle write locks completely.
3. **`reload_sessions` ignores `Limits`:** `reload_sessions` (`src/sessions.rs:144-158`) inserts every unexpired row from SQLite into `state.sessions` without enforcing `limits.max_sessions` or `limits.max_sessions_per_user`.

**Recommendation:** Replace `Vec::contains` in `evictions()` with `HashSet<&str>` and count expired entries for `user` in the initial pass. Skip `delete_expired_sessions` when no rows are expired, and cap/sort rows loaded by `reload_sessions` against `state.config.limits`.

---

### 8. [Medium] Validation and panic edge cases: `cross_site` fails open on non-UTF-8 headers, `sanitize_next` allows non-ASCII/spaces into `Location`, `hash_phrase` panics on short salts, and `load_sessions` panics on negative timestamps

**Locations:** `src/util.rs:58-70, 89-133, 213-241`, `src/auth.rs:162`, `src/users.rs:112-130, 412`.

1. **`cross_site` fails open on non-UTF-8 `Sec-Fetch-Site` or `Origin` (`src/util.rs:213-241`):**
   ```rust
   if let Some(v) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) { ... }
   if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) { ... }
   ```
   If either header is present with non-UTF-8 bytes, `.and_then(|v| v.to_str().ok())` yields `None`, silently falling through and returning `false` (allowed) instead of failing closed (`true`). Also, `headers.get(...)` inspects only the first header if duplicate `Sec-Fetch-Site` or `Origin` headers are sent.
2. **`sanitize_next` permits spaces and non-ASCII UTF-8 into the `Location` header (`src/util.rs:58-70`, `src/auth.rs:162`):**
   `sanitize_next` only filters `!c.is_control()`. Because `Form<LoginForm>` percent-decodes form fields, submitting `next=/%C3%A9` or `next=/foo+bar` produces `"/é"` or `"/foo bar"`, both of which pass `sanitize_next` and are inserted verbatim into `Location` (`HeaderValue::from_str(&next).unwrap()`). Raw non-ASCII bytes and unencoded spaces in a `Location` URI-reference violate RFC 9110 §10.2.2 / RFC 3986 (and `auth.rs:162` relies implicitly on `is_control()` matching `http::HeaderValue`'s byte rules to avoid a panic). Legitimate browser request targets are already percent-encoded ASCII (`is_ascii_graphic()`), so `next.bytes().all(|b| b.is_ascii_graphic())` plus a non-panicking fallback in `auth.rs:162` is both stricter and panic-free.
3. **`pub fn hash_phrase` panics on invalid salt length (`src/users.rs:112-130`):**
   `argon2.hash_password_into(..., salt.as_bytes(), &mut out).expect("fixed-size salt and output are valid")` panics if `salt.len() < 8` (or `> 64` in `argon2`), despite taking an arbitrary `salt: &str`. A corrupted or hand-edited row in `users.db` (or a library caller) causes a panic inside `lookup()`.
4. **`load_sessions` panics on negative DB timestamps (`src/users.rs:412`):**
   `UNIX_EPOCH + Duration::from_secs(r.get::<_, i64>(2)? as u64)` casts any negative `i64` to a `u64 >= 2^63`, overflowing `SystemTime` and panicking (possible if the system clock is at/before epoch or a row has a corrupt value). Use `u64::try_from(ts)` and `UNIX_EPOCH.checked_add(...)`.
5. **`rewrite_cache_control` splits inside quoted parameters (`src/util.rs:100`):**
   Naive `s.split(',')` breaks directives containing quoted commas (e.g. `Cache-Control: private="a, b", max-age=60` becomes `private, b", max-age=60`).

**Recommendation:** Make `cross_site` fail closed on non-UTF-8 or duplicate `Sec-Fetch-Site`/`Origin` headers; require `is_ascii_graphic()` in `sanitize_next` and remove the `.unwrap()` at `src/auth.rs:162`; return a `Result` (or validate salt length) in `hash_phrase`; guard timestamp conversion in `load_sessions` with `u64::try_from` / `checked_add`.

---

### 9. [Low] Monitor thread resilience edge cases: unbounded `read_eof` drain loop, `EINTR` disconnects, untimed `BUSY_MESSAGE` write, non-panic-safe `disconnect()`, and `seq`/`time` ordering race

**Locations:** `src/monitor.rs:124-142, 209-222, 279-292`.

1. **Unbounded drain loop & `EINTR` handling in `read_eof` (`src/monitor.rs:279-292`):**
   ```rust
   let result = loop {
       match (&*stream).read(&mut buf) {
           Ok(0) => break Ok(true),
           Ok(_) => continue,
           Err(e) if e.kind() == ErrorKind::WouldBlock => break Ok(false),
           Err(e) => break Err(e),
       }
   };
   ```
   A local monitor client that continuously writes bytes (e.g. `yes | nc 127.0.0.1 8081`) traps `read_eof` in an infinite loop, permanently stalling event delivery and holding the sole monitor slot. Cap bytes drained per check (or disconnect clients sending excessive input), and retry on `ErrorKind::Interrupted` (`EINTR`) rather than disconnecting.
2. **Untimed `BUSY_MESSAGE` write on the accept thread (`src/monitor.rs:210`):**
   `let _ = stream.write_all(BUSY_MESSAGE);` runs on the `wsb-monitor` accept thread without `set_write_timeout` or `set_nonblocking(true)`.
3. **Non-panic-safe slot release (`src/monitor.rs:217-218`):**
   If `serve_monitor` ever unwinds via panic, `conn_events.disconnect()` is skipped, permanently locking `monitor_connected = true`. Wrap `disconnect()` in an RAII `Drop` guard.
4. **`seq` and `time` can invert under concurrency (`src/monitor.rs:125-128`):**
   `ev.time = rfc3339(SystemTime::now())` executes *before* acquiring `self.inner.lock()`. Thread A can stamp second `T`, pause before locking, and receive a higher `seq` than Thread B stamped at `T + 1`. Sample `SystemTime::now()` inside the lock.

**Recommendation:** Bound the drain loop and handle `ErrorKind::Interrupted` in `read_eof`, set a short write timeout (or nonblocking) before writing `BUSY_MESSAGE`, guard `disconnect()` with `Drop`, and capture `SystemTime::now()` while holding `self.inner`.

---

### 10. [Low] Swallowed upstream errors, unused/over-broad dependencies, redundant code, script bugs, and documentation drift

**Locations:** `src/proxy.rs:123`, `src/users.rs:325-333, 494-500`, `src/util.rs:49, 72-83, 95, 116, 151, 274`, `src/rate_limit.rs:44-46`, `src/main.rs:158-179`, `src/app.rs:25-31, 95-118`, `src/settings.rs:42, 89-104`, `Cargo.toml`, `scripts/tar-new.sh`, `scripts/pull-up-new.sh`, `README.md:111`, `Notes/atlas/*`.

1. **Swallowed upstream `502` errors (`src/proxy.rs:123`):** `Ok(Err(_))` discards the Hyper client error without logging anything to stderr, leaving operators blind when diagnosing upstream connection refusals, DNS failures, or malformed upstream HTTP responses.
2. **Hand-rolled `hex_eq` (`src/users.rs:494-500`):** LLVM can optimize `.fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0` into a short-circuiting comparison in release builds. `subtle` is already in `Cargo.lock` (transitive dependency); using `subtle::ConstantTimeEq` (or `std::hint::black_box`) avoids compiler optimization defeating constant-time comparison.
3. **Unused and over-broad dependencies in `Cargo.toml`:**
   - `http-body-util = "0.1.5"` and `hyper = { version = "1.12.0", features = ["http1"] }` are never referenced directly anywhere in `src/` or `tests/`.
   - `sha2 = "0.11.1"` is duplicated in both `[dependencies]` and `[dev-dependencies]`.
   - `tokio` enables `features = ["full"]` despite only needing `rt-multi-thread`, `net`, `time`, `sync`, and `signal` (and `macros` in dev-dependencies for `#[tokio::test]`).
4. **Redundant code & micro-inefficiencies:**
   - `html_escape` (`src/util.rs:72-83`) allocates a separate `Vec<char>` on the heap for every character of `s`.
   - `while headers.remove(...).is_some() {}` (`src/util.rs:49, 95, 116, 274`, `src/proxy.rs:91, 141`) loops needlessly: `http::HeaderMap::remove` already removes all entries for the key on the first call.
   - `src/rate_limit.rs:44-46` (`if v.len() >= RATE_LIMIT_MAX_FAILURES { v.drain(...); }`) is dead code because lines 23–28 already returned `false` when `v.len() >= RATE_LIMIT_MAX_FAILURES`.
   - `exists(conn, column, value)` (`src/users.rs:325-333`) interpolates `column` into SQL via `format!` even though its sole caller passes `"user_name"`.
   - `src/main.rs:158-179` spawns the monitor thread and prints `"monitor on ..."` before binding `listen_addr` or calling `build_router`.
   - `src/app.rs:25-31, 95-118`: `pub fn build_router` implicitly panics if called outside a Tokio runtime, and `spawn_purger` holds a strong `AppState` forever (leaking `UserStore` / DB handle if a `Router` is dropped before runtime shutdown).
   - `login_page` (`src/util.rs:151`) and `logout_form_html` (`src/auth.rs:194`) still omit `<meta name="viewport" content="width=device-width, initial-scale=1">` for mobile usability.
   - `settings::load` (`src/settings.rs:42, 89-104`) accepts `users_db = ""` and `upstream` URIs containing userinfo (`http://user:pass@127.0.0.1:3000`).
5. **Shell script bugs (`scripts/tar-new.sh`, `scripts/pull-up-new.sh`):**
   - `scripts/tar-new.sh:45, 50` still depends on `/home/chris/chz 1` (external binary outside the repo) and breaks on git renames (`R  old -> new`) and filenames containing spaces.
   - When a change contains **only deleted files**, `tar-new.sh:58-61` exits `0` without creating `/tmp/new-files.tar`; `pull-up-new.sh:24` then fails on `scp` (or unpacks a stale `/tmp/new-files.tar` from a prior run!). Fixed `/tmp` paths also create collision/symlink hazards.
6. **Documentation drift:**
   - `Notes/atlas/SYSTEM.md:113` and `Notes/atlas/adr/0006-sessions-persisted.md:7` still state that session eviction drops the *earliest-expiring* entry (and `0006` omits the `created` column), whereas the code evicts by persisted `created` stamp (`src/sessions.rs:18`).
   - `Notes/atlas/SYSTEM.md:93` omits `GET /__wsb/login` and the 4 KiB `DefaultBodyLimit`; `line 35` (Cost model) omits the 60 s body-idle timeout, 256 concurrent upstream request cap, 4 KiB login form cap, and 4 MiB monitor byte budget; `line 182` omits `rewrite_cache_control`; `lines 15, 250` and `Notes/atlas/CONTEXT.md:15` omit the `truncated` event field.
   - `README.md:111` describes `login_error` as only `(user lookup failed)`, omitting `save_session` failures (`src/auth.rs:139`).

---

## Part 2: Review by Dimension

### 1. Code Quality Problems
- **Async lock lifetime vs `spawn_blocking` lifetime mismatch (`src/auth.rs:76-81, 110-155, 231-262`):** Holding `MutexGuard` in the cancellable async future instead of moving `OwnedMutexGuard` into `spawn_blocking` breaks both the 12 MiB Argon2 serialization and `session_writes` DB/memory consistency (Finding 1).
- **Transaction scoping in `add_users` (`src/users.rs:274-323`):** Keeping a deferred transaction open across stdin I/O, `SELECT`, and Argon2 hashing causes `SQLITE_BUSY` snapshot failures and long write-lock stalls (Finding 2).
- **Asymmetric byte-vs-UTF-8 cookie parsing (`src/util.rs:14-55`):** `strip_session_cookie` and `sets_session_cookie` handle raw bytes while `parse_cookies` still rejects non-UTF-8 headers (Finding 3).
- **Non-atomic `delete_sessions` (`src/users.rs:440-447`):** Multi-cookie logout runs without a transaction, unlike `save_session` and `remove_user` (Finding 6).
- **Dead code & unnecessary loops:** Unreachable `v.drain(...)` in `src/rate_limit.rs:44-46`; redundant `while headers.remove(...).is_some() {}` loops in `src/util.rs` and `src/proxy.rs`; unnecessary dynamic SQL in `src/users.rs:325-333` (`exists`).

### 2. Best Practice Violations
- **Mutating files before validation (`src/users.rs:209, 228, 369`):** Enabling `PRAGMA journal_mode = WAL` before verifying schema/tables modifies invalid or old-schema databases on disk (Finding 6).
- **Read-only CLI opening DB read-write (`src/main.rs:128`):** `list-users` opens `users.db` read-write via `UserStore::open` and runs WAL/DDL initialization (Finding 6).
- **Hand-rolled constant-time comparison (`src/users.rs:494-500`):** `hex_eq` can be optimized to a short-circuiting comparison by LLVM instead of using `subtle::ConstantTimeEq` (Finding 10).
- **Panicking in `pub` library functions on bad inputs/DB data:** `hash_phrase` panics on short salts (`src/users.rs:128`), `load_sessions` panics on negative timestamps (`src/users.rs:412`), `build_router` panics if called outside a Tokio runtime (`src/app.rs:31`), and `auth.rs:162` calls `.unwrap()` on `HeaderValue::from_str(&next)`.
- **Unused / overly broad Cargo dependencies:** Unused `http-body-util` and `hyper`, duplicate `sha2`, and `tokio` `features = ["full"]` (`Cargo.toml`).

### 3. General Mistakes
- **`parse_cookies` left on `hv.to_str()`** when `strip_session_cookie` and `sets_session_cookie` were migrated to raw bytes (Finding 3).
- **`evictions()` re-scans `sessions` with `Vec::contains`** instead of counting expired user sessions during the loop it just ran (`src/sessions.rs:77-86`) (Finding 7).
- **`scripts/pull-up-new.sh:24` fails when only files were deleted** because `scripts/tar-new.sh:60` exits without creating `/tmp/new-files.tar` (Finding 10).
- **`serve` spawns and logs the monitor before binding `listen_addr` or loading sessions** (`src/main.rs:158-179`).
- **Missing `<meta name="viewport">`** in `login_page` and `logout_form_html` despite mobile styling changes.

### 4. Logic Correctness and Edge Case Handling
- **Cancellation during `login`/`logout` `spawn_blocking`** leaves `state.sessions` out of sync with SQLite and allows concurrent DB writes (Finding 1).
- **`BEGIN DEFERRED` read-before-write in `add_users`** triggers immediate `SQLITE_BUSY` under WAL concurrency (Finding 2).
- **`obs-text` sibling cookie** causes `valid_session` to reject valid tokens and `logout` to skip DB deletion (Finding 3).
- **`IdleTimeoutBody::poll_frame`** resets `self.sleep` on `Poll::Ready(None)` and is not fused after timeout (Finding 5).
- **`rewrite_cache_control`** splits inside quoted-string parameters containing commas (`src/util.rs:100`) (Finding 8).
- **`remove-user -h`** prints usage instead of looking up user `-h` (`src/main.rs:24`); `settings::load` allows empty `users_db = ""` and upstream userinfo (`src/settings.rs:42, 89-104`).
- **Axum-generated error responses on `/__wsb/login` (`400`, `405`, `413`, `415`, `422`)** bypass `plain_response`/`html_response` and omit `Cache-Control: no-store`.
- **`Monitor` `seq`/`time` inversion** under concurrent `EventQueue::push` (`src/monitor.rs:125-128`) (Finding 9).

### 5. Security Vulnerabilities and Data Validation
- **OOM amplification via client-cancelled login requests bypassing `hash_slot`** (Finding 1).
- **Silent logout revocation bypass** when a sibling cookie contains `obs-text` bytes (Finding 3).
- **IPv6 `/128` rotation bypass of login rate limiting** and unbounded `hash_slot` queueing (Finding 4).
- **Site-wide 503 DoS via slow-reading authenticated clients holding `upstream_permits`** (Finding 5).
- **Exposed `users.db-wal` and `users.db-shm` permissions go unchecked** by `warn_if_exposed`, even after `chmod 600 users.db` (Finding 6).
- **`cross_site` fails open on non-UTF-8 `Sec-Fetch-Site`/`Origin` headers** (`src/util.rs:214, 218`) (Finding 8).
- **`sanitize_next` permits non-ASCII UTF-8 and spaces in `Location` redirects** (`src/util.rs:58-70`) (Finding 8).

### 6. Performance Implications and Resource Usage
- **Parallel 12 MiB Argon2id runs on client disconnect** directly threaten the 67 MB free-memory target (Finding 1).
- **Quadratic `O(N * R)` scan under `state.sessions.lock()`** during `evictions()` on bulk expiry (Finding 7).
- **Long-held SQLite write lock in `add_users`** during Argon2 hashing and stdin reads stalls `serve` (Finding 2).
- **Unconditional 60-second `DELETE` write transaction in `reload_sessions`** even when nothing is expired (Finding 7).
- **`html_escape` allocates a `Vec<char>` per input character** (`src/util.rs:72-83`) (Finding 10).
- **Unbounded `read_eof` drain loop** can pin the monitor thread on noisy local input (`src/monitor.rs:282-289`) (Finding 9).
- **`spawn_purger` leaks `AppState`** if a `Router` is dropped before runtime shutdown (`src/app.rs:95-118`).

### 7. Code Style and Maintainability Standards
- Overall module layout and readability remain strong; `cargo fmt --all -- --check` is clean.
- `src/users.rs` duplicates open/validate boilerplate across `open_for_add`, `open_for_remove`, and `UserStore::open` — which directly led to `configure(&conn)` being placed before schema validation in all three functions. Consolidating a shared internal open-and-validate helper would eliminate this drift.
- `scripts/tar-new.sh` still relies on an external personal tool (`/home/chris/chz 1`) and fragile `git status -sb` parsing instead of `git status -z`.

### 8. Error Handling and Logging
- **`forward()` silently drops upstream connection/protocol errors** (`src/proxy.rs:123`: `Ok(Err(_))` returns `502` with zero stderr logging).
- **`read_eof` treats `ErrorKind::Interrupted` (`EINTR`) as a fatal disconnect** (`src/monitor.rs:287`).
- **`spawn_monitor` does not guard `disconnect()` against panics** (`src/monitor.rs:217-218`).
- **`README.md:111` under-documents `login_error`** (triggered by both user lookup and session save errors).
- **Error hints with unquoted paths:** `settings::hint` (`src/settings.rs:67`) and `warn_if_exposed` (`src/users.rs:191`) interpolate paths into shell commands without quoting.

### 9. Test Coverage and Quality
- Unit and integration test suites are thorough for the happy paths and previously fixed bugs.
- **Test hygiene issues:**
  - Async integration tests in `tests/proxy.rs` (`temp_dir`, `user_db`, `spawn_proxy_full`) never delete their `/tmp/wsb-it-*` directories.
  - `restart_keeps_eviction_order` (`tests/proxy.rs:1388-1447`) leaks the spawned `web-safe-block serve` child process if any assertion fails before `child.kill()`.
  - `logout_waits_for_durable_revoke` sleeps 6 real seconds (`tests/proxy.rs:1266`); `upstream_permit_caps_concurrency` relies on a fixed 300 ms sleep (`line 1578`).
- **High-value test gaps to add:**
  1. `Cookie: app=\xff; wsb_session=<valid>` tested against both `valid_session` (`200`) and `POST /__wsb/logout` (DB row actually deleted).
  2. Client disconnect / future cancellation mid-`login` and mid-`logout` (verifying `hash_slot` remains serialized and `state.sessions` stays consistent with `users.db`).
  3. `add-user` running concurrently while `serve` writes sessions (verifying no `SQLITE_BUSY_SNAPSHOT` failure and no >5 s lock stall).
  4. `login` when `users.db` is locked past `busy_timeout` while the user already has `max_sessions_per_user` sessions (verifying existing sessions stay valid and the rate-limit attempt is refunded).
  5. `remove_user(&conn, "ALICE")` deleting sessions for stored user `alice`.
  6. `cross_site` with non-UTF-8 `Sec-Fetch-Site` and `Origin` headers.
  7. `login` with `next=/%C3%A9` and `next=/foo+bar`.
  8. `warn_if_exposed` warning when `users.db` is `0600` but `users.db-wal` is `0644`.
  9. End-to-end test with `cookie_secure = true` (`Secure` flag, `X-Forwarded-Proto: https`, `Origin: http://...` rejected).

### 10. Documentation and Comments
- `Notes/atlas/SYSTEM.md` (`lines 35, 93, 113, 182, 250`), `Notes/atlas/CONTEXT.md` (`line 15`), and `Notes/atlas/adr/0006-sessions-persisted.md` (`line 7`) lag behind recent commits (`f5285b2`, `e219cad`): they still cite earliest-expiring eviction instead of `created`-stamp eviction, omit the `created` column in ADR 0006, and omit `GET /__wsb/login`, `4 KiB` body cap, `rewrite_cache_control`, `truncated`, and upstream body-idle / concurrency caps in the cost model.
- `src/users.rs:792` comments `"// The database is left untouched."` in `old_database_without_salts_rejected`, which is now false because `configure(&conn)` converts the rejected DB to WAL mode before `stale_schema` runs.
- `README.md:111` omits `save_session` failures from `login_error`.
- `src/app.rs:22-25` (`build_router`) does not document that it must be called inside a Tokio runtime (or that it spawns a detached background task).
