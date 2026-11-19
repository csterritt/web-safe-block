# Code Review 3

Reviewed the repository at `aead90726c599c36f32c56899f095b054ca0ae87` (`src/`, `tests/proxy.rs`, `scripts/`, `README.md`, and `Notes/atlas/`).

Commits `c3f8099`, `f5285b2`, `69c268b`, and `aead907` addressed the issues from `Notes/review-2.md` by migrating to username + per-user salted Argon2id hashes, adding `Cache-Control` rewriting, bounding monitor event sizes/bytes, adding upstream concurrency and body-idle limits, persisting session creation timestamps, and checking `users.db` permissions. However, several of those fixes introduced new edge cases, and a number of security, concurrency, logic, and maintainability defects remain.

Part 1 lists prioritized findings ordered by severity. Part 2 evaluates the codebase across each of the ten requested review dimensions.

---

## Part 1: Prioritized Findings

### 1. [High] Client-controlled `Connection` header strips `CF-Connecting-IP` and `Host` before `forward()` reads them, spoofing `X-Forwarded-For: 127.0.0.1` to the upstream

**Locations:** `src/proxy.rs:75-103`, `src/util.rs:211-239`.

In `forward()`, hop-by-hop header removal runs **before** `client_key` and `Host` are extracted from the request headers:

```rust
let headers = req.headers_mut();
strip_session_cookie(headers);
strip_hop_by_hop(headers);
// ...
let key = client_key(headers, Some(peer));
if let Ok(v) = HeaderValue::from_str(&key) {
    headers.insert("x-forwarded-for", v);
}
// ...
if let Some(host) = headers.get(header::HOST).cloned() {
    headers.insert("x-forwarded-host", host);
}
```

`strip_hop_by_hop` (`src/util.rs:213-222`) reads every header name listed in the incoming `Connection` header and deletes those headers from `headers`. Because the client controls `Connection`:

1. Sending `Connection: cf-connecting-ip` causes `strip_hop_by_hop` to delete `CF-Connecting-IP` at line 77.
2. When `client_key(headers, Some(peer))` runs at line 89, `CF-Connecting-IP` is gone, so it falls back to `peer.ip()`.
3. In the documented Cloudflare Tunnel deployment, the TCP peer is the local tunnel daemon (`127.0.0.1`). `forward()` therefore stamps `X-Forwarded-For: 127.0.0.1` on the request sent to the protected server.
4. Meanwhile, `record_event` (`src/app.rs:46`) extracted `client_key` *before* `forward()` mutated the request, so the monitor log still records the client's external IP while the upstream application sees `X-Forwarded-For: 127.0.0.1`.
5. Similarly, sending `Connection: host` strips the `Host` header before line 101, omitting `X-Forwarded-Host`.

**Recommendation:** Extract `client_key` and `Host` *before* calling `strip_hop_by_hop`, and restrict `strip_hop_by_hop` so untrusted `Connection` tokens cannot strip security-critical or framing headers (`cf-connecting-ip`, `host`, `content-length`, `cookie`, etc.). Add an integration test sending `Connection: cf-connecting-ip, host` with `CF-Connecting-IP: 203.0.113.5` and asserting that the upstream still receives `X-Forwarded-For: 203.0.113.5` and `X-Forwarded-Host`.

---

### 2. [High] Successful login wipes all prior failure history for the client IP (`clear_failures`), allowing any holder of a valid account to brute-force other accounts without rate limiting

**Locations:** `src/auth.rs:51-56, 144`, `src/rate_limit.rs:12-64`.

Login rate limiting is keyed solely by client IP (`RATE_LIMIT_MAX_FAILURES = 10` per 15-minute window). When `login` succeeds (`src/auth.rs:144`), it calls:

```rust
clear_failures(&state.failures, &key);
```

which deletes the entire failure vector for that IP (`failures.lock().unwrap().remove(key)`).

With the transition to multi-user accounts and an `is_admin` flag (`commit c3f8099`), this creates an authentication throttle bypass:
1. An attacker with one valid low-privilege account (e.g. `chris`) sends 9 failed guesses for `user=site-admin` from IP `X`. `failures[X]` now has 9 timestamps.
2. On the 10th request, the attacker logs in as `user=chris` with `chris`'s valid pass phrase. Because `9 < 10`, `reserve_attempt` allows the attempt and pushes a 10th timestamp.
3. `chris`'s login succeeds and calls `clear_failures(&state.failures, &key)`, erasing all 9 failed guesses against `site-admin`.
4. The attacker can repeat `9 guesses against site-admin + 1 valid login as chris` indefinitely from a single IP without ever triggering a `429`.
5. Even without malice, any legitimate user logging in from a shared NAT/CGNAT IP resets the failure counter accumulated by an attacker sharing that IP.

Additionally, in `reserve_attempt` (`src/rate_limit.rs:35-43`), when `failures.len() >= max_keys` (10,000), eviction removes the key with the oldest `v.last()`. Because a rate-limited key (already at 10 failures) returns `false` at line 28 without updating `v.last()`, its `v.last()` ages while new keys arrive, making already-blocked IPs the first to be evicted and granted a fresh 10-attempt budget when the table fills.

**Recommendation:** On login success, call `refund_attempt(&mut state.failures.lock().unwrap(), &key)` instead of `clear_failures`, so a successful login only removes its own optimistic reservation while preserving actual failed attempts within the 15-minute window. Consider also rate-limiting per target username (or `(IP, user)`) in addition to per-IP.

---

### 3. [High] `auth::login` mutates in-memory sessions before persisting to SQLite, and its failure recovery (`reload_sessions`) aborts on locked/unwritable databases, leaving phantom sessions and evicting valid ones

**Locations:** `src/auth.rs:111-141`, `src/sessions.rs:111-130`.

In `auth::logout` (`src/auth.rs:220-237`), the database deletion is performed *before* removing the session from `state.sessions`. In `auth::login` (`src/auth.rs:111-141`), the order is reversed:

```rust
let removed = {
    let mut sessions = state.sessions.lock().unwrap();
    insert_session(
        &mut sessions,
        &state.config.limits,
        stored.cookie_string.clone(),
        Session {
            expires,
            user: user.name.clone(),
            created,
        },
    )
};
let users = state.config.users.clone();
let saved =
    tokio::task::spawn_blocking(move || users.save_session(&stored, &removed)).await;
if !matches!(saved, Ok(Ok(()))) {
    // ...
    let st = state.clone();
    match tokio::task::spawn_blocking(move || reload_sessions(&st)).await {
```

This creates three failure modes when `users.db` is contended or unwritable:

1. **Premature eviction before commit:** `insert_session` inserts the new session and evicts the user's oldest session (`removed`) from `state.sessions`, then releases the map mutex *before* `save_session` runs. While `save_session` waits up to 5 seconds on SQLite's `busy_timeout`, concurrent requests carrying the evicted session cookie immediately fail with `401 Unauthorized` — even if `save_session` ultimately fails and rolls back.
2. **Double 5-second timeout and broken rollback in `reload_sessions`:** When `save_session` fails (typically because another connection holds a write lock past the 5s busy timeout, or the database/disk is read-only or full), line 134 calls `reload_sessions(&st)` to restore `state.sessions`. However, the first line of `reload_sessions` (`src/sessions.rs:113`) executes `state.config.users.delete_expired_sessions(now)?` — another **write** statement (`DELETE FROM sessions WHERE timestamp <= ?1`). On a locked or read-only database, that `DELETE` waits *another* 5 seconds (stalling `session_writes` for 10+ seconds total) and then returns `Err` **before** reaching `sessions.clear()` at line 117.
3. **Permanent cache/DB desynchronization and session DoS:** Because `reload_sessions` fails before touching `state.sessions`, `state.sessions` retains the uncommitted phantom session (whose raw token was discarded when `login` returned `500`) and never restores the evicted session (`removed`, which is still in `users.db`). If a user with 3 active sessions attempts to log in 3 times while the database is locked or read-only, all 3 of their valid sessions are evicted from `state.sessions` and replaced by 3 unusable phantom sessions.

**Recommendation:** Since `state.session_writes` is already held across the login write path, either compute the eviction list without mutating `state.sessions` until `save_session` succeeds, or record the evicted `(String, Session)` pairs in memory and restore them directly if `save_session` fails instead of calling `reload_sessions`. In `reload_sessions`, do not let a failure in `delete_expired_sessions` prevent `load_sessions` from refreshing the in-memory map.

---

### 4. [Medium] Unbounded login form bodies and pass-phrase lengths allow memory and Argon2 CPU amplification, including from rate-limited or cross-site requests

**Locations:** `src/auth.rs:32-46, 68-73`, `src/users.rs:37-42, 88-106`.

1. **Body extraction precedes `cross_site` and `reserve_attempt`:** In `login` (`src/auth.rs:41-46`), `Form(form): Form<LoginForm>` is extracted by Axum *before* the handler body runs `cross_site(&headers)` (line 48) or `reserve_attempt(...)` (line 52). Axum's default `Form` body limit is **2 MiB**. A client IP that is already rate-limited (`429`) or sending cross-site POSTs (`403`) can still force the server to read, allocate, and URL-decode 2 MiB payloads on every request.
2. **Unbounded `user` and `phrase` lengths:** Neither `LoginForm` nor `users.lookup` caps the length of `user` or `phrase`. Before acquiring `state.hash_slot.lock().await` (`src/auth.rs:69`), each task holds `form` in memory; once inside, it clones `form.user` and `form.phrase` (`line 71`), queries SQLite with `user_name.trim()`, allocates a normalized copy in `normalize_phrase(phrase)` (`src/users.rs:37`), and hashes the entire buffer with Argon2id. Concurrent requests waiting on `hash_slot` can each retain multi-megabyte form buffers, threatening the 67 MB free-memory budget cited in the README.

**Recommendation:** Attach `axum::extract::DefaultBodyLimit::max(4096)` to the `/__wsb/login` and `/__wsb/logout` routes, check `cross_site` and `reserve_attempt` before parsing the form body (e.g. by extracting `Bytes` or checking headers first), and reject `user` (e.g. `> 128` bytes) or `phrase` (e.g. `> 1024` bytes) inputs immediately.

---

### 5. [Medium] Upstream `Set-Cookie` filtering fails open on non-UTF-8 bytes, and multi-cookie handling in `valid_session`/`logout` only inspects the first `wsb_session` cookie

**Locations:** `src/proxy.rs:146-156`, `src/sessions.rs:39-54`, `src/auth.rs:199-225`, `src/util.rs:14-43, 123-128`.

1. **Fail-open upstream `Set-Cookie` filter:** `src/proxy.rs:150` filters upstream `Set-Cookie` headers with:
   ```rust
   .filter(|v| v.to_str().map(|s| !sets_session_cookie(s)).unwrap_or(true))
   ```
   `http::HeaderValue` permits `obs-text` bytes (`0x80..=0xFF`), for which `v.to_str()` returns `Err`. Because of `.unwrap_or(true)`, if an upstream sends `Set-Cookie: wsb_session=evil; Path=/; a=\xff`, `v.to_str()` fails and the filter evaluates to `true`, forwarding the forbidden `wsb_session` cookie to the browser.
2. **Silent loss of non-UTF-8 `Cookie` headers:** In `parse_cookies` (`src/util.rs:17`), any `Cookie` header failing `hv.to_str()` is skipped, and `strip_session_cookie` (`src/util.rs:37`) then deletes all `Cookie` headers, dropping all cookies from that header instead of preserving non-`wsb_session` cookies.
3. **Only the first `wsb_session` cookie is checked or revoked:** As noted in `README.md:133`, other services on the same hostname share cookies. Under RFC 6265 §5.4, if a sibling service or path sets a more specific `wsb_session` cookie (e.g. `Path=/app`), the browser sends `Cookie: wsb_session=stale; wsb_session=<valid_token>`. Both `valid_session` (`src/sessions.rs:42`) and `logout` (`src/auth.rs:201`) use `.find(|(n, _)| n == SESSION_COOKIE)`. `valid_session` rejects the request on the first cookie without checking the second (putting the user in an unrecoverable login loop on `/app`, since login sets `Path=/`), and `logout` revokes only the first cookie while leaving the second active in `users.db`.

**Recommendation:** Check `Set-Cookie` names on raw bytes (`v.as_bytes()`) or use `.unwrap_or(false)` so non-UTF-8 `Set-Cookie` headers never bypass the filter. In `valid_session`, accept the request if *any* `wsb_session` cookie resolves to a valid session. In `logout`, collect all `wsb_session` cookie values from the request and pass all of their hashes to `users.delete_sessions(&hashes)`.

---

### 6. [Medium] Late `busy_timeout` initialization, swallowed SQLite errors in `UserStore::open`, a single `Mutex<Connection>` without WAL mode, and unauthenticated `POST /__wsb/logout` DB writes cause avoidable contention and false error messages

**Locations:** `src/users.rs:27-30, 177-209, 308-339`, `src/auth.rs:195-226`, `src/sessions.rs:111-114`.

1. **`busy_timeout` is set after initial queries, and errors are misreported as missing DB/table:** In `open_for_add` (`src/users.rs:183-187`), `open_for_remove` (`lines 200-207`), and `UserStore::open` (`lines 321-335`), `conn.busy_timeout(Duration::from_secs(5))` is only called inside `init(&conn)` at the **end** of each function — *after* `SELECT COUNT(*) FROM users` and `stale_schema(&conn)` have already executed with a `0 ms` busy timeout. Furthermore, `UserStore::open` maps any error from `SELECT COUNT(*) FROM users` via `.map_err(|_| missing())?` to `"no users database at ...; add users with: ..."` (and `open_for_remove` maps it to `"... does not contain a users table"`). If `serve` is writing a session when the operator runs `list-users` or `remove-user` (or if the file is corrupt or locked), the query fails immediately with `SQLITE_BUSY` (0ms wait) and falsely tells the operator that `users.db` does not exist.
2. **Single `Mutex<Connection>` without WAL mode blocks login lookups during session writes:** `UserStore` wraps a single `Connection` in a `std::sync::Mutex` and operates in default rollback-journal mode (`PRAGMA journal_mode = WAL` is never enabled). When a session write (`save_session`, `delete_sessions`, or `reload_sessions`) waits up to 5 seconds on an external lock, it holds `UserStore::conn`, blocking `users.lookup()` for concurrent logins even before Argon2 hashing begins.
3. **Unauthenticated `POST /__wsb/logout` forces SQLite writes:** `logout` (`src/auth.rs:213-225`) acquires `state.session_writes.lock().await` and executes `DELETE FROM sessions WHERE cookie_string = ?1` on `UserStore::conn` for *any* `Cookie: wsb_session=<arbitrary>` value without checking whether the hash exists in `state.sessions` and without rate limiting. An unauthenticated client can flood `POST /__wsb/logout` with random cookie values to contend on `session_writes` and `UserStore::conn`.
4. **Unconditional write lock every 60 seconds:** `reload_sessions` (`src/sessions.rs:113`) runs `DELETE FROM sessions WHERE timestamp <= ?1` on every 60s purge tick even when no sessions are expired.

**Recommendation:** Set `conn.busy_timeout(Duration::from_secs(5))` immediately after opening the connection, enable `PRAGMA journal_mode = WAL;`, and inspect the actual `rusqlite::Error` instead of unconditionally mapping errors to `missing()`. In `logout`, acquire `session_writes` and only call `users.delete_sessions` if `state.sessions` actually contains the hash (since all session writes and reloads are serialized under `session_writes`, any live persisted session is present in `state.sessions`).

---

### 7. [Medium] Monitor thread sleeps 100ms (`PROBE_WAIT`) after every write batch, retains already-written events against queue capacity during the sleep, and busy-spins at 100% CPU on `accept()` errors

**Locations:** `src/monitor.rs:147-168, 199-262`, `src/settings.rs:36`.

1. **Unconditional 100ms sleep per batch:** In `serve_monitor` (`src/monitor.rs:253-260`), after every `stream.write_all(out.as_bytes())?`, the monitor thread sleeps `PROBE_WAIT` (100ms) before calling `events.mark_consumed(last.seq)` — even when the client has not half-closed (`half_closed == false`). Under steady traffic where 1–2 events arrive per wake-up, this caps the monitor to 10 writes/second; under burst load (`MAX_BATCH = 100`), throughput is capped at 1,000 events/second.
2. **Events are evicted and neither redelivered nor counted as dropped during `PROBE_WAIT`:** Commit `69c268b` lowered the default `monitor_queue_len` from `1000` to `100` (`== MAX_BATCH`). When 100 events (`seq 1..=100`) are queued:
   - `pending()` clones all 100 events, sets `inner.sent_up_to = 100`, and zeroes `inner.dropped` (`std::mem::take(&mut inner.dropped)`).
   - Those 100 events **remain in `inner.events`** for the next 100ms (`PROBE_WAIT`) until `mark_consumed(100)` runs.
   - Because `inner.events.len() == 100 == self.capacity`, **any** request arriving during that 100ms sleep overflows the queue and evicts `seq 1, 2, ...` from `inner.events`.
   - If the monitor client had closed just before `write_all` (the exact case `PROBE_WAIT` is intended to detect, per lines 254–255), `read_eof` returns `Err` and skips `mark_consumed`, but the events evicted during the 100ms sleep are already gone from `inner.events` *and* were not counted in `inner.dropped` because `old.seq <= inner.sent_up_to`. Similarly, if `write_all` fails when `dropped > 0`, the `dropped` count taken by `pending()` is permanently lost.
3. **100% CPU busy loop on `accept()` failure:** In `spawn_monitor` (`src/monitor.rs:203-204`):
   ```rust
   for stream in listener.incoming() {
       let Ok(mut stream) = stream else { continue };
   ```
   If `accept()` fails due to file-descriptor exhaustion (`EMFILE`/`ENFILE`), `listener.incoming()` yields `Err` immediately on every iteration without sleeping, pinning an OS thread at 100% CPU.

**Recommendation:** Advance `sent_up_to` and clear `dropped` only inside `mark_consumed` (after the write and liveness check succeed), or remove the unconditional 100ms post-write sleep on healthy connections. Add a short backoff sleep on `Err` in `listener.incoming()`.

---

### 8. [Medium] `GET /__wsb/login` returns an empty `405 Method Not Allowed`, `cross_site` ignores the `Origin` scheme, `session_ttl_secs` can overflow `SystemTime`, and `sanitize_next` has no length cap

**Locations:** `src/app.rs:33`, `src/auth.rs:98`, `src/settings.rs:114-116`, `src/util.rs:46-57, 130-140, 188-208`.

1. **`GET /__wsb/login` returns a blank `405`:** When a user submits an invalid pass phrase or hits the rate limit on `POST /__wsb/login`, the server returns a `401` or `429` HTML page directly in response to the POST, leaving the browser's URL bar at `/__wsb/login`. If the user bookmarks the page, taps the address bar and presses Enter, or if a mobile browser reloads the tab via `GET /__wsb/login`, Axum returns an empty `405 Method Not Allowed` instead of rendering the login page (contradicting `README.md:13`: "presents for any URL, from memory, a tiny (632 bytes) log-in page").
2. **`cross_site` ignores `Origin` scheme:** In `src/util.rs:198-205`, when `Sec-Fetch-Site` is absent and `Origin` is present, `cross_site` parses `Origin` as a `Uri` and compares only `u.authority()` against `Host`, ignoring `u.scheme()`. A POST from `Origin: http://example.com` to `https://example.com` is treated as same-origin despite being cross-origin under the Same-Origin Policy.
3. **Unbounded `session_ttl_secs` panics on login:** `src/settings.rs:114-116` only validates `raw.session_ttl_secs != 0`. Setting a very large `session_ttl_secs` in `config.toml` causes `SystemTime::now() + state.config.session_ttl` (`src/auth.rs:98`) to panic with an overflow on the first successful login (or wrap `as_secs() as i64` negative in `unix_secs` at `src/users.rs:33`).
4. **Unbounded `next` parameter reflection & missing mobile viewport meta tag:** `sanitize_next` (`src/util.rs:46-57`) has no length cap, allowing a large `next` query string to be reflected into the HTML form on `401`/`429`/`500` responses. Also, despite commit `69c268b` ("improved HTML for mobile"), neither `login_page` nor `logout_form_html` includes `<meta name="viewport" content="width=device-width, initial-scale=1">`, causing mobile browsers to render in a ~980px virtual desktop viewport.

**Recommendation:** Register `.route(LOGIN_PATH, get(login_get).post(login))` so `GET /__wsb/login` renders the login form (or redirects to `/`). In `cross_site`, verify that `Origin`'s scheme matches the expected scheme (`https` when `cookie_secure` is true, or `http`/`https`). Cap `session_ttl_secs` in `settings::load` (e.g. to 10 years = `315_360_000`) and cap `next` in `sanitize_next` to `1024` bytes.

---

### 9. [Low] Collation, Unicode case-folding, and cap-enforcement inconsistencies in `users.rs` and `sessions.rs`

**Locations:** `src/users.rs:12-25, 212-218, 250-275, 407-425`, `src/sessions.rs:111-130`.

1. **`sessions.user_name` lacks `COLLATE NOCASE`:** `users.user_name` is declared `TEXT NOT NULL UNIQUE COLLATE NOCASE`, whereas `sessions.user_name` is `TEXT NOT NULL REFERENCES users(user_name) ON DELETE CASCADE` (default `BINARY` collation). In `remove_user` (`src/users.rs:214`), `DELETE FROM sessions WHERE user_name = ?1` uses `BINARY` comparison and therefore matches 0 rows when `remove-user` is given a differently-cased name (e.g. `remove-user alice` for stored user `Alice`), relying solely on `ON DELETE CASCADE` from the subsequent `DELETE FROM users` statement. Furthermore, `lookup` trims `user_name.trim()` (`src/users.rs:415`), whereas `remove_user` does not trim `name`.
2. **ASCII-only `COLLATE NOCASE` vs Unicode `.to_lowercase()`:** SQLite's built-in `COLLATE NOCASE` only folds ASCII `A-Z` to `a-z`, whereas `is_admin` (`src/users.rs:267`) and `normalize_phrase` (`src/users.rs:40`) use Rust's Unicode `.to_lowercase()`. Non-ASCII characters in usernames are therefore case-sensitive in SQLite despite `README.md:77, 129` stating that usernames are case-insensitive.
3. **No username character/length validation in `add_users`:** `add_users` (`src/users.rs:250`) accepts any non-whitespace token as `name`, including control characters (e.g. ANSI escape sequences) or arbitrarily long strings, which are later printed unescaped to stdout on login (`src/auth.rs:143`) and in `list-users`.
4. **`reload_sessions` does not enforce `Limits`:** `reload_sessions` (`src/sessions.rs:111-130`) loads all unexpired rows from `sessions` without enforcing `limits.max_sessions` or `limits.max_sessions_per_user`.

**Recommendation:** Add `COLLATE NOCASE` to `sessions.user_name` (or normalize/lowercase usernames at creation and lookup time, and restrict usernames to printable ASCII graphic characters of reasonable length, e.g. 1–64 chars). Trim `name` in `remove_user`, and enforce session caps (or `ORDER BY created`) during `reload_sessions`.

---

### 10. [Low] `cargo fmt --check` failure, brittle shell scripts in `scripts/`, and documentation drift in `README.md` and `Notes/atlas/`

**Locations:** `src/util.rs:130`, `README.md:38, 54, 58-64, 109`, `Notes/atlas/*`, `scripts/tar-new.sh`, `scripts/pull-up-new.sh`.

1. **Formatting check fails:** `cargo fmt --all -- --check` fails on `src/util.rs:130` (introduced in commit `aead907`).
2. **`README.md` errors and drift:**
   - Line 38 has a stray `EOF` after `./target/release/web-safe-block list-users`, breaking copy-pasted shell commands.
   - Line 64 states the default for `monitor_queue_len` is `1000`, whereas commit `69c268b` changed `DEFAULT_CONFIG` (`src/settings.rs:36`) to `100`.
   - Line 54 states "`add-user` and `serve` exit with an error if the config file is missing...", omitting `remove-user` and `list-users`, which also load and validate the config file.
   - Lines 58–59 have stray periods after `` `users_db`. `` and `` `listen_addr`. ``.
   - Line 109 states `proxied` event status is "the upstream's, or 502/504", omitting `503` (emitted when `upstream_permits` is exhausted in `src/proxy.rs:111`).
3. **`Notes/atlas/` is out of date with the codebase:** `Notes/atlas/data.mjs`, `Notes/atlas/SYSTEM.md`, `Notes/atlas/CONTEXT.md`, and `Notes/atlas/adr/0001-phrase-is-the-credential.md` still describe the pre-`c3f8099` / pre-`f5285b2` design: phrase-only login with no username field, unsalted SHA-512 in `users.db`, `monitor_queue_len` default 1,000, and open question `Q-F2` claiming there is no mid-body upstream timeout.
4. **Defects in `scripts/tar-new.sh` and `scripts/pull-up-new.sh`:**
   - `scripts/tar-new.sh:45, 50` hardcodes `/home/chris/chz 1` (a local binary outside the repository), uses obsolescent `egrep`, breaks on git renames (`R  old -> new`), and writes a blank line to `/tmp/deleted-files.txt` when `deleted_files` is empty (`printf '%s\n' "${deleted_files[@]}"`).
   - Both scripts read/write fixed paths in world-writable `/tmp` (`/tmp/new-files.tar`, `/tmp/deleted-files.txt`) instead of `mktemp`, and `scripts/pull-up-new.sh:22` interpolates `${last_dir}` unquoted into the remote `ssh` command.

**Recommendation:** Run `cargo fmt`, fix the typos and `monitor_queue_len` default in `README.md`, update `Notes/atlas/data.mjs` and rebuild `SYSTEM.md`/`atlas.html`, and replace the `/home/chris/chz` pipeline in `scripts/tar-new.sh` with standard `git status -z` / `git diff --name-only` and `mktemp`.

---

## Part 2: Review by Dimension

### 1. Code Quality Problems
- **Inconsistent state-mutation ordering between `login` and `logout`:** `logout` (`src/auth.rs:220-237`) updates SQLite before mutating `state.sessions`, whereas `login` (`src/auth.rs:111-141`) mutates `state.sessions` first and tries to repair it on error by calling `reload_sessions` (Finding 3).
- **Inconsistent `ConnectInfo<SocketAddr>` extraction:** `record_event` (`src/app.rs:42-45`) and `client_key` (`src/util.rs:177`) gracefully handle a missing `ConnectInfo<SocketAddr>` extension, whereas `login` (`src/auth.rs:43`) and `proxy_or_login` (`src/proxy.rs:27`) use the mandatory `ConnectInfo(peer)` extractor. Calling the public `build_router` API without `.into_make_service_with_connect_info::<SocketAddr>()` results in `500 Internal Server Error` at runtime.
- **Misleading startup log order:** `serve` (`src/main.rs:160-174`) prints `"web-safe-block: listening on ..."` *before* binding the public `TcpListener` and *before* calling `build_router` (which loads sessions from `users.db`). If either step fails, stdout reports that the server is listening right before stderr reports a fatal startup error.

### 2. Best Practice Violations
- **SQLite concurrency configuration:** `UserStore` uses default rollback-journal mode instead of `PRAGMA journal_mode = WAL;` and serializes all readers and writers through a single `std::sync::Mutex<Connection>` (`src/users.rs:309`).
- **Non-constant-time hash comparison:** `src/users.rs:430` compares Argon2id hex outputs with `==` (`String::eq`), which short-circuits on the first differing byte instead of using a constant-time comparison (`subtle::ConstantTimeEq`).
- **No graceful shutdown handling:** `serve` (`src/main.rs:177`) runs `axum::serve(listener, service)` without `with_graceful_shutdown`, and `spawn_purger` (`src/app.rs:90`) / `spawn_monitor` (`src/monitor.rs:199`) have no shutdown signaling, abruptly terminating in-flight upstream requests and database transactions on `SIGINT`/`SIGTERM`.

### 3. General Mistakes
- **`cargo fmt` check failure:** `src/util.rs:130` exceeds the configured line width after commit `aead907`.
- **Stray `EOF` in `README.md:38`** and stale `monitor_queue_len` default (`1000` in `README.md:64` vs `100` in `src/settings.rs:36`).
- **Hardcoded `/home/chris/chz` binary in `scripts/tar-new.sh:45, 50`.**

### 4. Logic Correctness and Edge Case Handling
- **Header stripping order in `forward()`** deletes `CF-Connecting-IP` and `Host` when named in a client's `Connection` header (Finding 1).
- **Rate-limit reset on any successful login (`clear_failures`)** and premature eviction of rate-limited keys in `reserve_attempt` (Finding 2).
- **Multi-cookie edge case:** Only the first `wsb_session` cookie is checked in `valid_session` and revoked in `logout` (Finding 5).
- **`IdleTimeoutBody::poll_frame` (`src/proxy.rs:195-213`):** Resets the sleep timer even when `self.inner.poll_frame(cx)` returns `Poll::Ready(None)` (end-of-stream), and does not fuse the stream after returning a timeout error.
- **Asterisk-form `OPTIONS * HTTP/1.1` requests:** In `forward()` (`src/proxy.rs:66-72`), combining `upstream`'s scheme/authority with `path_and_query = "*"` fails `Uri::from_parts` and returns `502 Bad Gateway`.

### 5. Security Vulnerabilities and Data Validation
- **IP spoofing to upstream via `Connection: cf-connecting-ip`** (Finding 1).
- **Cross-account brute-force rate-limit bypass via `clear_failures`** (Finding 2).
- **Upstream `Set-Cookie: wsb_session=...` filter bypass via non-UTF-8 bytes** (Finding 5).
- **Missing request body size limits and input length bounds on `/__wsb/login`** (Finding 4).
- **Missing scheme validation in `cross_site` `Origin` check** (`src/util.rs:198-205`) and **missing upper bound on `session_ttl_secs`** (`src/settings.rs:114-116`) (Finding 8).
- **Gate-generated error responses (`403`, `404`, `501`, `502`, `503`, `504`) omit `Cache-Control: no-store` / `private`:** Only `html_response` sets `Cache-Control: no-store` and only proxied upstream responses run through `rewrite_cache_control`, leaving plain-text error responses without explicit cache-control headers.

### 6. Performance Implications and Resource Usage
- **Unconditional 100ms sleep (`PROBE_WAIT`) per monitor write batch** and queue saturation when `monitor_queue_len == 100 == MAX_BATCH` (Finding 7).
- **100% CPU busy-spin in `spawn_monitor`** if `listener.incoming()` yields `accept()` errors such as `EMFILE` (Finding 7).
- **Unauthenticated `POST /__wsb/logout` DB writes** and **every-60s unconditional `DELETE` write transaction in `reload_sessions`** (Finding 6).
- **Repeated `O(N)` scans in `insert_session` (`src/sessions.rs:66-101`) and `reserve_attempt` (`src/rate_limit.rs:30-43`):** `insert_session` scans all `sessions.values()` multiple times per login; `reserve_attempt` performs two full `O(N)` passes over `failures` under the mutex whenever a new IP arrives at capacity.
- **Autocommit per user in `add_users` (`src/users.rs:240-275`):** Each inserted user runs in its own transaction (one fsync per line) rather than wrapping the batch in a transaction or using prepared statements.

### 7. Code Style and Maintainability Standards
- The module split across `app`, `auth`, `proxy`, `sessions`, `rate_limit`, `state`, `users`, `monitor`, `settings`, and `util` is clean and idiomatic.
- Session state coordination remains split across `auth.rs`, `sessions.rs`, `app.rs`, and `users.rs` with three separate synchronization primitives (`state.session_writes`, `state.sessions`, and `UserStore::conn`), which contributed to the inconsistent mutation ordering between `login` and `logout` (Finding 3).
- `CLI` argument parsing (`src/main.rs:41-62`) does not recognize `-h`/`--help` or `-V`/`--version` (exiting with status 2 on `--help`) and treats `-c -c serve` as `-c` with path `"-c"`.

### 8. Error Handling and Logging
- **Swallowed SQLite errors in `UserStore::open` (`src/users.rs:325`) and `open_for_remove` (`src/users.rs:203`)** combined with setting `busy_timeout` only at the end of `init()` cause lock contention or corruption to be misreported as a missing database or missing table (Finding 6).
- **Inconsistent stdout vs stderr logging without timestamps:** Operational messages (`listening on`, `monitor on`, `user '...' logged in`) go to `stdout` without timestamps (`src/main.rs:154, 160`, `src/auth.rs:143`), while CLI status messages (`wrote default config`, `added N user(s)`, `removed user`) and runtime errors go to `stderr` without timestamps.

### 9. Test Coverage and Quality
- Existing unit and integration tests are well-structured and cover the happy paths and previously reported issues well.
- **Key test gaps to add:**
  1. Authenticated request with `Connection: cf-connecting-ip, host` and `CF-Connecting-IP: 203.0.113.5` verifying that `X-Forwarded-For` and `X-Forwarded-Host` are preserved upstream.
  2. Multi-account rate-limit test verifying that 9 failed attempts against `admin` followed by 1 successful login as `alice` does not reset the failure budget against `admin`.
  3. Login failure test when `users.db` is locked past the 5s busy timeout while the user already has `max_sessions_per_user` active sessions, verifying that existing in-memory sessions remain valid (`200`) and no phantom session is left in memory.
  4. Upstream `Set-Cookie: wsb_session=evil` header containing non-UTF-8 bytes (`0x80..=0xFF`), verifying that it is still stripped.
  5. Request carrying multiple `wsb_session` cookies (`Cookie: wsb_session=stale; wsb_session=<valid>`), verifying both `valid_session` and `logout`.

### 10. Documentation and Comments
- `README.md` has a stray `EOF` in the usage block (`line 38`), outdated default `monitor_queue_len` (`1000` vs `100` on `line 64`), incomplete command list for config validation (`line 54`), and omits `503` from `proxied` event statuses (`line 109`).
- `Notes/atlas/` (`data.mjs`, `SYSTEM.md`, `CONTEXT.md`, `adr/0001-phrase-is-the-credential.md`, `research/code-survey.md`) still documents the old phrase-only / unsalted SHA-512 architecture and needs to be regenerated from updated source data.
- Comment in `src/monitor.rs:254-255` (`"wait for a possible reset so those events stay queued for the next monitor"`) does not hold when `monitor_queue_len == MAX_BATCH (100)` and new events arrive during `PROBE_WAIT` (Finding 7).
