# Code Review 5

Reviewed the repository at `d23617a6c4136890b9fb5276ec50b826e57b439f` (`Cargo.toml`, `src/`, `tests/proxy.rs`, `scripts/`, `README.md`, and `Notes/atlas/`).

Commits `ed9f266` through `d23617a` resolved every prioritized issue from `Notes/review-4.md` (except the items explicitly recorded as accepted in `Notes/review-4-notes.md`, which are respected below rather than re-litigated) and added several new features: custom Hyper accept loop with timeouts (`src/server.rs`), loopback-only `CF-Connecting-IP` trust, fail-closed `cross_site` POST validation, Unix-socket upstreams (`src/upstream.rs`) and Unix-socket monitors (`src/monitor.rs`), 7-day in-memory `daily_counts`, `front_page_message` with pre-built root page, and `/robots.txt`.

*Verification note:* `cargo fmt --all -- --check`, `RUSTFLAGS="-C linker=gcc-16" CC=gcc-16 cargo clippy --all-targets -- -D warnings`, and `RUSTFLAGS="-C linker=gcc-16" CC=gcc-16 cargo test` all passed (75 lib unit tests, 1 bin unit test, 40 integration tests; 0 warnings, 0 failures).

Part 1 lists prioritized findings ordered by severity. Part 2 evaluates the codebase across each of the ten requested review dimensions.

---

## Part 1: Prioritized Findings

### 1. [High] `DailyCounts::roll` and `serve_monitor` have unbounded day-catchup loops on forward clock jumps, silently drop all counters on backward clock steps, and can miss a day's `final: true` report at connect time

**Locations:** `src/monitor.rs:322-367, 459-464, 603-627`.

The new 7-day UTC counter logic assumes `SystemTime` only ever advances smoothly by small amounts:

```rust
// src/monitor.rs:322-335
fn roll(&mut self, now: u64) {
    let today = now / 86_400;
    let mut next = match self.days.back() {
        Some((d, _)) => d + 1,
        None => self.started / 86_400,
    };
    while next <= today {
        self.days.push_back((next, Counts::default()));
        next += 1;
    }
    while self.days.len() > RETAINED_DAYS {
        self.days.pop_front();
    }
}
```

Four distinct bugs stem from this design:

1. **Unbounded loop while holding `EventQueue.inner` mutex on forward clock jumps:** On headless servers/SBCs that boot without a battery-backed RTC (starting near 1970-01-01, `started = 0`) and later NTP-sync to 2026 (`today ≈ 20,780`), the first event after sync pushes ~20,781 `Counts` entries into `VecDeque` and immediately pops 20,774 of them while holding the global `EventQueue` mutex that every HTTP request acquires. A bogus future clock step (corrupt RTC or NTP leap) spins for millions/billions of iterations under the mutex, deadlocking every HTTP request on the server. The same pattern repeats in `serve_monitor` (`src/monitor.rs:621-627`), where `while day < today` calls `events.finished_day(day)` — acquiring the mutex once per day across the entire jump — even though only 7 days are ever retained.
2. **Silent counter loss on backward clock steps:** If NTP steps the clock backward across UTC midnight before the first event or first monitor connect (`now / 86_400 < self.started / 86_400`), `self.days` is empty and `next <= today` is `false`. `self.days` remains empty, so `record()` hits `let Some((_, c)) = self.days.back_mut() else { return; }` (`line 339-341`), silently dropping every security counter, `drop_unseen()` silently drops eviction counts, and `report()` returns an empty `Vec` (violating the contract that a connecting monitor always receives at least today's `daily_counts` line).
3. **Connect-time UTC midnight race drops a day's `final: true` report (`src/monitor.rs:603-609`):** `serve_monitor` calls `events.daily_report()` (capturing day `D` with `final: false`), writes it to the socket, and *after* the write initializes `let mut day = events.utc_day();`. If UTC midnight ticks during `daily_report`..`write_all`, `day` starts at `D + 1` and day `D` never receives its `final: true` line.
4. **Split clock sample in `EventQueue::push` (`src/monitor.rs:459-464`):** `now` is sampled from `(self.clock)()` before acquiring `self.inner.lock()`, while `ev.time = rfc3339(SystemTime::now())` is sampled directly from `SystemTime::now()` after locking. Across UTC midnight, an event's JSON `time` can fall on day `D + 1` while its counter is tallied in day `D` (and tests injecting `with_clock` still stamp wall-clock time on events).

**Recommendation:**
- Clamp `roll()` to at most `RETAINED_DAYS` new entries: start `next` at `(self.started / 86_400).max(today.saturating_sub(RETAINED_DAYS as u64 - 1))` (and when `self.days` is empty and `today < self.started / 86_400`, seed `today` rather than leaving `days` empty).
- In `serve_monitor`, initialize `day` from the last day returned by `daily_report()` (atomically alongside the report) and clamp `day = day.max(today.saturating_sub(RETAINED_DAYS as u64))` before iterating.
- In `EventQueue::push`, sample `(self.clock)()` once *inside* the lock and derive `ev.time` from that same `now` value (`rfc3339(UNIX_EPOCH + Duration::from_secs(now))`).

---

### 2. [High] No request-body read timeout, no connection cap, and unbounded graceful-shutdown drain allow unauthenticated slow-body requests to pin resources forever and hang `SIGTERM`

**Locations:** `src/server.rs:37-40, 41-74, 80-132`, `src/app.rs:34-40`.

Commit `ed9f266` introduced `src/server.rs` with `header_read_timeout` (30 s) and `StallTimeoutIo` (60 s write-stall timeout). However, **request-body reads are completely untimed**, and **shutdown has no deadline**:

1. **Unauthenticated slow-body connection pinning:** `StallTimeoutIo::poll_read` (`src/server.rs:124-132`) passes reads straight through untouched. On `POST /__wsb/login`, an unauthenticated attacker can send valid headers (`Content-Length: 4000`, `Content-Type: application/x-www-form-urlencoded`, `Sec-Fetch-Site: same-origin`) immediately — disarming Hyper's 30 s `header_read_timeout` — and then send zero body bytes. Axum's `Form<LoginForm>` extractor awaits the full body forever before `login()`, rate limiting, `login_waiters`, or `record_event` ever execute. Because `server.rs` accepts connections with no concurrency cap, an attacker can accumulate idle slow-body connections, FDs, Tokio tasks, and Hyper buffers until FD exhaustion or OOM on the 67 MB free-RAM target server.
2. **Unbounded `graceful.shutdown().await` (`src/server.rs:73`):** On `SIGTERM` or `Ctrl-C`, `serve` drops the listener and awaits `graceful.shutdown().await` with no upper timeout. A single stalled slow-body `POST /__wsb/login` — or a single authenticated slow-drip client reading 1 byte every 59 seconds (which resets `StallTimeoutIo.sleep = None` on each 1-byte write and also pins an upstream permit indefinitely) — causes `serve` to hang forever on shutdown until `SIGKILL`.

**Recommendation:**
- Wrap `Form<LoginForm>` (or the login route / read side of `StallTimeoutIo` when a request is active, or add a route-level `tower::timeout` / `tokio::time::timeout` around body collection) so slow request bodies time out cleanly (e.g., 15–30 s for the 4 KiB login form).
- Bound `graceful.shutdown().await` with a drain timeout (e.g., 15–30 s) via `tokio::time::timeout`, logging a warning if active connections had to be aborted.
- Consider adding a configurable global connection limit (e.g., semaphore around accepted connections) to protect FDs and RAM under flood conditions.

---

### 3. [Medium] `bind_unix_monitor` has a `rename` TOCTOU clobber race, probes live monitors intrusively, and leaves stale sockets on startup failure or clean shutdown

**Locations:** `src/monitor.rs:180-229`, `src/main.rs:162-190`.

```rust
// src/monitor.rs:191-226
match UnixStream::connect(path) {
    Ok(_) => return Err(io::Error::new(ErrorKind::AddrInUse, ...)),
    Err(e) if e.kind() == ErrorKind::ConnectionRefused => std::fs::remove_file(path)?,
    Err(e) => return Err(e),
}
...
std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
std::fs::rename(&sock, path)?;
```

1. **TOCTOU overwrite via `rename`:** Between the `symlink_metadata` / `connect` / `remove_file` sequence (`lines 184-207`) and `std::fs::rename(&sock, path)` (`line 224`), `rename(2)` unconditionally overwrites whatever is at `path`. If two `serve` instances start concurrently (or another file is placed at `path` in that window), the second silently clobbers the first's live socket instead of failing with `AddrInUse`. Using `std::fs::hard_link(&sock, path)` followed by removing the temp dir is atomic and fails with `AlreadyExists` if `path` appeared concurrently.
2. **Intrusive liveness probe on a live monitor:** Calling `UnixStream::connect(path)` against a running `serve` with no watcher connected actually completes a connection into the live server's monitor slot. If the running server accepts and writes `daily_counts` plus queued events into the kernel socket buffer before the prober's `UnixStream` is dropped, `serve_monitor`'s `read_eof` sees `Ok(true)` (EOF, not `ECONNRESET` — `AF_UNIX` `SOCK_STREAM` sockets do not synthesize `ECONNRESET` on close with unread data) and calls `events.mark_consumed(last.seq)`, silently consuming queued events.
3. **Startup ordering and shutdown cleanup (`src/main.rs:162-190`):** `bind_monitor` runs *before* `TcpListener::bind(listen)` and `build_router`. If binding `listen_addr` fails (e.g., port already in use) or loading sessions fails, `serve` exits leaving a stale unix socket file at `monitor_addr`. Clean shutdown (`SIGTERM` / `Ctrl-C`) also leaves the unix socket file behind on disk.
4. **Tight `sun_path` margin (`src/monitor.rs:212, 220`):** The temporary bind path `parent/.w<pid>-<attempt>/s` appends 13–15 bytes to `parent`. A valid `path` whose filename is short (e.g., 95 bytes total on macOS where `sun_path` is 104 bytes) can fail `UnixListener::bind(&sock)` even though `path` itself fits.

**Recommendation:**
- Bind `listen_addr` and call `build_router` *before* `bind_monitor`, and remove the unix socket path on clean shutdown (only when owned by this process).
- Prefer `hard_link(&sock, path)` over `rename(&sock, path)` so concurrent creation fails atomically with `AlreadyExists` instead of clobbering a live socket.
- Shorten the temp name further (e.g., `.w{attempt}/s` inside `parent` or a fixed short name with retry) if long parent directories matter on macOS.

---

### 4. [Medium] `valid_session` acquires the global `state.sessions` mutex on every unauthenticated request and runs SHA-256 hashing while holding it

**Locations:** `src/sessions.rs:42-57`.

```rust
pub(crate) fn valid_session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let tokens = session_tokens(headers);
    let mut sessions = state.sessions.lock().unwrap();
    let now = SystemTime::now();
    for token in tokens {
        let key = hash_token(&token);
        match sessions.get(&key) {
            // ...
```

1. **Unnecessary lock on every unauthenticated request:** When `tokens.is_empty()` (virtually all scraper/bot traffic hitting the gate), `valid_session` still acquires and releases the global `state.sessions` `std::sync::Mutex` on the Tokio worker thread.
2. **CPU work and allocations under the global session mutex:** For requests carrying `wsb_session` cookies, `hash_token(&token)` computes SHA-256 and allocates a 64-byte hex `String` *while holding `state.sessions.lock()`*. An unauthenticated attacker sending a `Cookie` header packed with dozens of oversized `wsb_session=<large value>` pairs (up to Hyper's header limit) forces SHA-256 hashing and heap allocations inside the global lock on async worker threads, stalling legitimate authenticated traffic.

**Recommendation:**
- Return `None` immediately when `tokens.is_empty()`.
- Filter candidates to the exact format of minted tokens (64 ASCII lowercase hex bytes — anything else can never match a valid session) and compute `hash_token` *before* acquiring `state.sessions.lock()`.

---

### 5. [Medium] `server.rs` omits `TCP_NODELAY` on accepted connections (latency regression vs `axum::serve`)

**Locations:** `src/server.rs:46-65`.

When `src/server.rs` replaced `axum::serve` with a manual `TcpListener::accept()` loop in commit `ed9f266`, `stream.set_nodelay(true)` was omitted (`axum::serve` enables `TCP_NODELAY` by default). Without `TCP_NODELAY`, Nagle's algorithm interacts with TCP delayed ACK (40 ms on Linux, up to 200 ms on other stacks) whenever Hyper sends HTTP headers and body frames in separate `write` syscalls, adding avoidable latency to every proxied and gate response.

**Recommendation:** Call `let _ = stream.set_nodelay(true);` right after `listener.accept()` succeeds.

---

### 6. [Medium] `list-users` no longer fails on an empty database (contradicting `README.md`), and `create_private_db` bypasses `0600` on dangling symlinks

**Locations:** `src/users.rs:164-176, 253-304`, `src/main.rs:125-139`, `README.md:89`, `Notes/atlas/SYSTEM.md:161`.

1. **`list-users` empty-DB regression:** `README.md:89` documents: *"`web-safe-block list-users` ... exits with an error if the users database is missing or empty."* When commit `ed9f266` switched `list_users` from `UserStore::open` (`OpenKind::Serve`) to `users::open_read_only` (`OpenKind::ReadOnly`), line 292 (`if matches!(kind, OpenKind::Serve) && users == Some(0)`) excluded `OpenKind::ReadOnly`. On a database with 0 users, `list-users` now prints nothing and exits `0` instead of erroring. (Additionally, `Notes/atlas/SYSTEM.md:161` still claims `UserStore` opens `users.db` read-write for `list-users`.)
2. **Dangling symlink bypass in `open_for_add` (`src/users.rs:164-176, 257-262`):** `if !path.exists()` follows symlinks and returns `false` for a dangling symlink. `create_private_db(path)` then opens with `create_new(true)` (`O_CREAT | O_EXCL`), which fails with `AlreadyExists` on a dangling symlink — and line 173 swallows `ErrorKind::AlreadyExists` as `Ok(())`. Immediately afterward, `Connection::open(path)` follows the symlink and creates the target file using the process `umask` instead of mode `0600`.
3. **Minor redundancies in `src/users.rs`:**
   - `busy_timeout` is set three times on every read-write open (`open` line 271, `configure` line 33, `init` line 50).
   - `add_users` (`src/users.rs:425`) opens and commits a `BEGIN IMMEDIATE` write transaction even when `pending.is_empty()` (e.g., empty stdin or all lines skipped).
   - `warn_if_exposed` (`src/users.rs:212-234`) calls `p.metadata()` a second time after `exposed_files` already stat'd the same paths (and prints `mode 0000` if a transient `-wal` file disappears between the two calls).

**Recommendation:**
- Decide whether `list-users` should error on an empty DB (include `OpenKind::ReadOnly` in line 292) or exit 0, and align `README.md:89` plus add a test.
- Reject symlinks in `create_private_db` (or check `symlink_metadata` when `AlreadyExists` occurs), skip the empty transaction in `add_users`, remove duplicate `busy_timeout` calls, and return `(PathBuf, u32)` from `exposed_files`.

---

### 7. [Medium] Untrusted `CF-Connecting-IP` is forwarded upstream on non-loopback connections, plus minor `client_ip` / `cross_site` edge cases

**Locations:** `src/proxy.rs:89-118`, `src/util.rs:238-255, 279-320`.

1. **Spoofed `CF-Connecting-IP` leaked to upstream (`src/proxy.rs:95-104`):** `forward()` strips `forwarded`, `x-forwarded-*`, and `x-real-ip` because the client is untrusted, and `client_ip()` refuses to trust `CF-Connecting-IP` when the TCP peer is non-loopback. However, `forward()` leaves `cf-connecting-ip` intact in the forwarded headers. If `listen_addr` is non-loopback (which `serve` allows with a warning), a direct client can spoof `CF-Connecting-IP` to the protected upstream application even though the gate rejected it.
2. **Inconsistent IPv4-mapped IPv6 canonicalization (`src/util.rs:238-255`):** `client_ip()` canonicalizes `peer` (`a.ip().to_canonical()`), but returns the parsed `CF-Connecting-IP` without canonicalizing it. Consequently, `rate_limit_key` maps `::ffff:203.0.113.5` to `203.0.113.5`, while `client_key` logs and forwards `::ffff:203.0.113.5` in the monitor and `X-Forwarded-For`. Calling `.to_canonical()` inside `client_ip()` makes both consistent.
3. **Duplicate `CF-Connecting-IP` header (`src/util.rs:241`):** `headers.get("CF-Connecting-IP")` takes the first value. If a local reverse proxy appends rather than replaces the header, an attacker-supplied first value wins. Failing back to `peer_ip` when multiple `CF-Connecting-IP` headers exist (matching `cross_site`'s duplicate-header rule) is safer.
4. **`cross_site` `Origin` path/query looseness and default-port comparison (`src/util.rs:302-317`):**
   - `origin.parse::<Uri>()` does not check `u.path_and_query().is_none()`, so malformed headers like `Origin: https://example.com/evil?x=1` are accepted as same-origin.
   - Comparing `a.as_str().eq_ignore_ascii_case(host.trim())` rejects explicit default ports (e.g., `Origin: https://example.com` with `Host: example.com:443`). Rare behind Cloudflare, but worth knowing.

**Recommendation:** Strip `cf-connecting-ip` in `forward()` when `!peer.ip().to_canonical().is_loopback()`, canonicalize the IP inside `client_ip()`, reject duplicate `CF-Connecting-IP` headers, and require `u.path_and_query().is_none()` in `cross_site`.

---

### 8. [Low] Error message typo (`not unix:////...`), non-Unix compiler warnings, library enum invariants, monitor `dropped` loss, and documentation/script nits

**Locations:** `src/upstream.rs:30-51, 58-63, 98-102`, `src/monitor.rs:4-5, 72-87, 493, 646`, `src/auth.rs:149, 190-205, 253-262`, `src/util.rs:191-214`, `README.md:13, 89, 103`, `Notes/atlas/SYSTEM.md:9, 161, 276`, `Notes/atlas/CONTEXT.md:10, 16`, `scripts/tar-new.sh:27`, `scripts/pull-up-new.sh:22-37`.

1. **Four-slash error typo (`src/upstream.rs:98-102`):** When `rest` starts with `"//"`, `format!("{setting} unix socket uses unix:/absolute/path, not unix://{rest}")` prints **`not unix:////run/app.sock`** (four slashes). It should be `not unix:{rest}`.
2. **Non-Unix `unused_variables` warnings (`src/monitor.rs:82`, `src/upstream.rs:58`):** Under `#[cfg(not(unix))]`, `rest` in `if let Some(rest) = s.strip_prefix("unix:")` is unused and will fail `cargo clippy -- -D warnings` on Windows.
3. **Public enum invariants bypassable by library callers (`src/upstream.rs:30-51`, `src/monitor.rs:72-76`):** `Upstream::Http(Uri)` is publicly constructible, so passing a relative `Uri` panics at `.expect("http upstream always has an authority")` inside `forward()`. Likewise `MonitorAddr::Tcp(SocketAddr)` allows bypassing the loopback check when constructed directly.
4. **Monitor `dropped` counter lost if write fails (`src/monitor.rs:493, 646`):** `EventQueue::pending()` clears `inner.dropped` via `std::mem::take` *before* `stream.write_all` succeeds. If the write fails or the client is already dead, those dropped counts are lost from both `dropped` and `dropped_unseen`.
5. **Unchecked `i64` increment in `auth::login` (`src/auth.rs:149`):** `*last_created + 1` panics (debug) or wraps (release) if a tampered DB contains `created = i64::MAX`; `last_created.saturating_add(1)` avoids overflow.
6. **Implicit `Cache-Control: no-store` on 303 login/logout (`src/auth.rs:190-205, 253-262`):** `login` and `logout` 303 responses rely on `record_event` middleware (`src/app.rs:73-76`) to attach `Cache-Control: no-store`, whereas `login_redirect` (`src/auth.rs:36`) sets it explicitly. Setting it directly in `login` and `logout` keeps all `/__wsb/` handlers self-contained.
7. **Defense-in-depth response header (`src/util.rs:191-214`):** `html_response` and `plain_response` omit `X-Content-Type-Options: nosniff`.
8. **Stale documentation:**
   - `README.md:13` claims the login page is `632 bytes`; the actual rendered size of `login_page("Site Description Here", None, "/")` is **730 bytes** (701 bytes when `front_page_message` is empty).
   - `README.md:89` claims `list-users` errors on an empty database (see Finding 6).
   - `src/monitor.rs:4-5`, `Notes/atlas/SYSTEM.md:9, 276`, and `Notes/atlas/CONTEXT.md:10, 16` still describe `monitor_addr` as loopback TCP only and `upstream` as always `http://` on loopback; `Notes/atlas/SYSTEM.md:161` still claims `UserStore` opens `users.db` read-write for `list-users`.
9. **Helper scripts:**
   - `scripts/tar-new.sh:27`: a file renamed in the index and then deleted in the working tree (`RD`) enters the `R*|C*` branch and adds the non-existent `$path` to `files`, causing `tar` to fail.
   - `scripts/pull-up-new.sh:22-37`: the `EXIT` trap cleans up `$local_dir` but leaves `$remote_dir` behind on `chris@utmbox` if `ssh`/`scp`/`tar` fails mid-run.

---

## Part 2: Review by Dimension

### 1. Code Quality Problems
- **Unbounded day-stepping loops (`src/monitor.rs:322-335, 621-627`):** Stepping one day at a time from `started` or `day` to `today` mixes wall-clock deltas with loop iteration counts inside/around a hot mutex (Finding 1).
- **Locking and hashing coupled in `valid_session` (`src/sessions.rs:42-57`):** Acquires `state.sessions` even when no `wsb_session` cookie is present and runs SHA-256 inside the critical section (Finding 4).
- **Minor redundancies in `src/users.rs`:** `busy_timeout` set three times per RW open, empty `BEGIN IMMEDIATE` transaction in `add_users` when `pending.is_empty()`, and duplicate `metadata()` stat calls in `warn_if_exposed` (Finding 6).
- **Implicit middleware dependency for `Cache-Control: no-store`** in `auth::login` / `auth::logout` vs explicit header in `auth::login_redirect` (Finding 8).

### 2. Best Practice Violations
- **Missing `TCP_NODELAY` on manual `TcpListener::accept` (`src/server.rs:46-65`):** Replacing `axum::serve` dropped `set_nodelay(true)` (Finding 5).
- **Unbounded `graceful.shutdown().await` (`src/server.rs:73`):** Production servers should always cap graceful drain so stalled clients cannot block `SIGTERM` indefinitely (Finding 2).
- **Non-atomic `rename` over socket path (`src/monitor.rs:224`):** Overwrites a concurrently created socket/file instead of failing atomically via `hard_link` (Finding 3).
- **Public enum variants exposing unchecked invariants (`src/upstream.rs:30-34`, `src/monitor.rs:72-76`):** `Upstream::Http(Uri)` can trigger an internal `.expect()` panic if constructed directly by a library caller (Finding 8).
- **Missing `X-Content-Type-Options: nosniff`** on gate responses (`src/util.rs:191-214`).
- **Non-Unix `unused_variables` warnings** in `src/monitor.rs:82` and `src/upstream.rs:58` (Finding 8).

### 3. General Mistakes
- **`not unix://{rest}` prints four slashes (`not unix:////...`)** because `rest` already begins with `//` (`src/upstream.rs:100`) (Finding 8).
- **`list-users` empty-DB check accidentally dropped** when migrating from `OpenKind::Serve` to `OpenKind::ReadOnly` (`src/users.rs:292`) (Finding 6).
- **`bind_monitor` called before `TcpListener::bind` and `build_router`** (`src/main.rs:162-176`), leaving a stale unix socket behind when startup fails on `listen_addr` or session loading (Finding 3).
- **`serve_monitor` initializes `day = events.utc_day()` after sending `daily_report()`** (`src/monitor.rs:604-609`), creating a midnight race (Finding 1).
- **`EventQueue::push` mixes `(self.clock)()` with `SystemTime::now()`** (`src/monitor.rs:459-461`) (Finding 1).
- **`scripts/tar-new.sh:27` mishandles `RD` status** (Finding 8).

### 4. Logic Correctness and Edge Case Handling
- **`DailyCounts` under backward clock steps** leaves `self.days` empty and silently drops all counts (`src/monitor.rs:322-367`) (Finding 1).
- **Monitor `dropped` counter zeroed before write succeeds** (`src/monitor.rs:493`) (Finding 8).
- **Unix monitor `connect()` liveness probe** can connect to a live monitor and, under a tight race, consume queued events because `AF_UNIX` `read_eof` returns `Ok(true)` rather than `ECONNRESET` (`src/monitor.rs:191, 646-653`) (Finding 3).
- **`cross_site` `Origin` check** does not reject paths/queries on `Origin` and does not normalize explicit default ports (`src/util.rs:302-317`) (Finding 7).
- **`client_ip` canonicalizes `peer` but not `CF-Connecting-IP`** (`src/util.rs:238-249`) (Finding 7).
- **`*last_created + 1` unchecked overflow** on tampered `i64::MAX` DB rows (`src/auth.rs:149`) (Finding 8).
- **`POST /__wsb/login` body parsing runs before `cross_site`:** Malformed or >4 KiB cross-site POSTs return `413`/`415`/`422` (`EventKind::Other`) instead of `403` (`EventKind::Forbidden`) because `Form<LoginForm>` extracts before the handler runs (`src/auth.rs:49-58`). Harmless for security (4 KiB cap, no side effects), but slightly noisy in `daily_counts`.

### 5. Security Vulnerabilities and Data Validation
- **Unauthenticated slow-body DoS and shutdown hang (`src/server.rs:73, 124-132`):** Slow `POST /__wsb/login` bodies bypass `header_read_timeout`, `StallTimeoutIo`, rate limiting, and `login_waiters`, and hold connections + graceful shutdown indefinitely (Finding 2).
- **Lock-contention DoS via multi-cookie SHA-256 hashing inside `state.sessions` mutex (`src/sessions.rs:42-57`):** Unauthenticated requests with many `wsb_session` cookies burn CPU while holding the global session mutex (Finding 4).
- **Spoofed `CF-Connecting-IP` forwarded to upstream on non-loopback `listen_addr` (`src/proxy.rs:95-104`)** and duplicate `CF-Connecting-IP` first-header precedence (`src/util.rs:241`) (Finding 7).
- **Dangling symlink permission bypass in `create_private_db` (`src/users.rs:164-176, 257-262`):** Can create `users.db` with default `umask` instead of `0600` (Finding 6).
- **TOCTOU clobber via `rename` in `bind_unix_monitor` (`src/monitor.rs:224`):** Can overwrite a concurrently created socket/file (Finding 3).
- **Strengths verified:** Zero `unsafe` code; salted Argon2id with `subtle::ConstantTimeEq` and dummy-salt lookup for unknown users; `OwnedMutexGuard` properly moved into `spawn_blocking` closures for both `hash_slot` and `session_writes`; raw-byte cookie extraction and `Set-Cookie` filtering handle `obs-text` cleanly; `Cache-Control` rewriting handles quoted parameters and drops CDN override headers; `sanitize_next` restricts redirects to printable ASCII same-origin paths.

### 6. Performance Implications and Resource Usage
- **Global `state.sessions` mutex hit on every unauthenticated request** (`src/sessions.rs:44`) undermines the gate's primary job of absorbing scraper/bot traffic cheaply (Finding 4).
- **Missing `TCP_NODELAY`** adds 40–200 ms Nagle/delayed-ACK latency on multi-write HTTP responses (`src/server.rs:46-65`) (Finding 5).
- **Forward clock jump allocation/CPU spike** under `EventQueue.inner` mutex (`src/monitor.rs:328-334`) (Finding 1).
- **No concurrent connection cap in `server.rs`** leaves FDs and Hyper connection buffers unbounded under slow-body floods on a 67 MB free-RAM host (Finding 2).
- **Slow-drip authenticated reader** (1 byte every 59 s) defeats `StallTimeoutIo` and can hold `upstream_permits` indefinitely (Finding 2).
- **Strengths verified:** Pre-built `Bytes` root login page (`AppState.root_page`) serves `/` with zero per-request HTML rendering; `evictions()` uses `HashSet<&str>` in `O(N)`; `delete_expired_sessions` checks `SELECT EXISTS` before taking a write lock; `EventQueue` caps both count and ~4 MiB total bytes; `add_users` hashes all entries before taking a brief `BEGIN IMMEDIATE` transaction.

### 7. Code Style and Maintainability Standards
- Overall structure, module separation, naming, and readability are very strong; `cargo fmt --all -- --check` and `cargo clippy --all-targets -- -D warnings` pass cleanly.
- Consolidating `users::open` (`src/users.rs:253-304`) into one parameterized helper dramatically improved clarity over review 4; cleaning up the triplicate `busy_timeout` and `exposed_files` double-stat will make it even tighter.
- Extracting `Upstream` and `MonitorAddr` into focused types with `FromStr`/`Display` keeps `settings.rs` clean and readable; tightening visibility or constructors would protect their invariants for library users.

### 8. Error Handling and Logging
- Startup errors, SQLite errors, and upstream `502` errors are consistently surfaced to stderr with clear `web-safe-block:` prefixes; `users.rs` error messages include actionable hints.
- **`src/upstream.rs:100`** has the `not unix:////...` formatting typo (Finding 8).
- **`src/server.rs:48-52` and `src/monitor.rs:566-570`** silently swallow `accept()` errors (with a 100 ms backoff to avoid spinning). Logging transient `accept()` errors (rate-limited) would help diagnose FD exhaustion (`EMFILE`/`ENFILE`) in production.
- **`src/monitor.rs:592-594`**: if spawning `wsb-monitor-conn` fails (`OS` thread limit / OOM), the slot is cleanly released via `events.disconnect()`, though the error is silently dropped without logging to stderr.

### 9. Test Coverage and Quality
The suite is fast (~7.4 s total) and exercises 116 unit and integration tests with zero failures. However, several newly added security and reliability mechanisms have **zero test coverage**:

1. **`max_login_waiters` / `503` `EventKind::LoginBusy`:** No unit or integration test verifies that exceeding `max_login_waiters` returns `503`, logs `login_busy`, and refunds the rate-limit attempt (`src/auth.rs:79-96`).
2. **`header_read_timeout` (slowloris) and graceful shutdown (`src/server.rs`):** Neither the 30 s header timeout nor `serve` resolving its `shutdown` future is tested anywhere.
3. **`DailyCounts` clock anomalies:** No tests cover backward clock steps (`now < started`) or large forward clock jumps (`src/monitor.rs:322-367`). Also `daily_counts_ignores_uncounted_kinds` (`src/monitor.rs:933-946`) omits `EventKind::Robots` (only indirectly checked in `tests/proxy.rs::robots_txt`).
4. **`cli_list_users` on an empty database:** Missing — adding it would have caught the `README.md:89` regression.
5. **`remove_user` with mismatched casing (`"Alice"` removed as `"alice"`):** `src/users.rs:776-809` only tests lowercase `"alice"`, leaving the `BINARY`-vs-`NOCASE` subquery in `remove_user` (`src/users.rs:327-331`) untested against mixed case.
6. **`strip_hop_by_hop` unit tests:** `src/util.rs` has no unit tests for `strip_hop_by_hop` (multiple `Connection` headers, `Host`/`Content-Length` protection, case-insensitivity, standard hop-by-hop headers).
7. **Unix monitor disconnect / redelivery:** `monitor_half_closed_client` only tests TCP, not `UnixListener`/`UnixStream`.
8. **Minor test hygiene:** `monitor_receives_daily_then_final` (`src/monitor.rs:1087`) and `unix_monitor_streams_events` (`src/monitor.rs:1217`) manually call `q.disconnect()` while `serve_monitor` is still running and leave detached accept threads alive for the remainder of the test binary.

### 10. Documentation and Comments
- **`README.md:13`:** States the login page is `632 bytes`; it is currently `730 bytes` (default `front_page_message`) or `701 bytes` (empty).
- **`README.md:89`:** States `list-users` exits with an error on an empty database, which no longer matches `src/users.rs:292` (Finding 6).
- **`src/monitor.rs:4-5`, `Notes/atlas/SYSTEM.md:9, 276`, `Notes/atlas/CONTEXT.md:10, 16`:** Still describe the monitor as loopback TCP only and upstream as always `http://` on loopback (outdated after Unix socket support in `c407e3b` and `9c58118`).
- **`Notes/atlas/SYSTEM.md:161`:** Still states `UserStore` opens `users.db` read-write for `list-users` (now uses `open_read_only`).
- **`Notes/atlas/data.mjs` vs `SYSTEM.md`:** Remember per `AGENTS.md` to update `Notes/atlas/data.mjs` and regenerate `SYSTEM.md`/`atlas.html` with `bun Notes/atlas/build.mjs`, plus update `Notes/atlas/CONTEXT.md` by hand.
