# Code survey — evidence for the atlas

Facts the atlas is drawn from, gathered 2026-11-17. File-by-file.

## src/main.rs (162 lines)
- Commands: `write-config`, `add-user`, `serve`; `-c path` accepted anywhere. Usage exit code 2, failures exit 1.
- `serve` binds the monitor listener first (std TcpListener), spawns the monitor thread, then starts a tokio runtime and `axum::serve` on `listen_addr` with `ConnectInfo<SocketAddr>`.

## src/lib.rs (926 lines)
- Router: `POST /__wsb/login` → `login`; `GET|POST /__wsb/logout` → page/handler; fallback `proxy_or_login`; `record_event` middleware wraps everything.
- Reserved: any other `/__wsb/*` path → 404, kind `reserved`.
- Sessions: `HashMap<String, Session>` in a Mutex; token = 32 random bytes hex; caps 10/user, 10k total, earliest-expiry eviction; purger task every 60s.
- Rate limit: `failures` map ip → Vec<Instant>; `reserve_attempt` counts under one lock before lookup; `refund_attempt` on db error; `clear_failures` on success; 10 in 15min → 429; failures also wait `fail_delay` = 1s → 401. Max 10k keys, oldest-key eviction.
- Client IP: `CF-Connecting-IP` header if it parses, else peer addr, else "unknown".
- CSRF: `cross_site()` checks `Sec-Fetch-Site` (only same-origin/none allowed), else `Origin` authority vs `Host`. Applied to login + logout POSTs → 403 `forbidden`.
- `forward()`: swaps scheme+authority to `upstream`; strips `wsb_session` from Cookie; removes hop-by-hop + `forwarded`, `x-forwarded-for/proto/host/port`, `x-real-ip`; writes its own X-Forwarded-For (client key), -Proto (`https` iff cookie_secure), -Host (from Host header). Connect timeout 10s (connector), 60s `tokio::time::timeout` for response headers → 502/504. Response: hop-by-hop stripped; upstream `Set-Cookie: wsb_session=…` filtered out.
- Login page: static HTML form, `html_escape`d `next` + message; `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- `sanitize_next`: must start with `/`, not `//`, `/\`, `/__wsb/`, no control chars; else `/`.

## src/users.rs (311 lines)
- `normalize_phrase`: strip whitespace + `char::to_lowercase`.
- `hash_phrase`: SHA-512 hex of normalized phrase — that's what's stored.
- Policy: ≥20 non-whitespace chars, ≥1 digit, ≥1 ASCII punctuation.
- `add_users`: stdin lines, first word = name, rest = phrase; per-line skip reporting; name & phrase-hash UNIQUE (also checked against db); `is_admin` = name contains "admin" case-insensitive.
- `UserStore::open`: READ_ONLY sqlite; errors if file missing or table empty. `lookup` → `rusqlite::Result<Option<User>>` — errors propagate (login returns 500 `login_error` + refunds the attempt).

## src/monitor.rs (378 lines)
- `EventQueue`: `VecDeque` + `Condvar`; `push` stamps seq + rfc3339 time; full → pop oldest, count `dropped` only if monitor connected AND seq > sent_up_to.
- `pending(1s)` hands out copies; `mark_consumed` removes only after socket write + 100ms reset-wait.
- One monitor slot (`try_connect`); busy → `{"error":"another monitor is already connected"}`.
- Half-close handling: EOF on read → heartbeat every 10s to detect gone clients; write timeout 30s.
- Event kinds: login_page, login_failed, login_succeeded, login_error, rate_limited, logout_page, logout, forbidden, proxied, reserved, other.

## src/settings.rs (280 lines)
- 7 settings, all required, `deny_unknown_fields`. Validation: upstream http + no path/query; monitor_addr loopback; queue_len ≥1; ttl ≥1. users_db relative → config dir. `write_default` uses `create_new` (no overwrite).

## review-1.md → code state
All eight findings appear addressed in current code: X-Forwarded-* rebuilt (F1), hash caveat documented + strength policy (F2, partially — hashing still unsalted by design), session/failure caps (F3), upstream timeouts (F4), logout GET shows form only (F5), lookup errors → 500 + refund (F6), atomic reserve (F7), upstream path rejected (F8). These are the `resolved` questions in data.mjs.

## Known gaps the atlas tracks as questions
- No `remove-user`/rotation CLI (Q-U1); `is_admin` stored but unused (Q-U2).
- Sessions volatile on restart (Q-S1 → ghost P).
- WebSocket upgrades stripped → apps can't do WS (Q-W1 → ghost W).
- CF-Connecting-IP trusted unconditionally (Q-T1); IP-keyed limiter shares budget across NATs (Q-R1).
- No mid-body upstream timeout (Q-F2); monitor has no auth beyond loopback (Q-M1); unconnected drops uncounted (Q-Q1); config-only settings (Q-C1); csrf check posture (Q-G2); https/unix upstream (Q-A1).

## Update 2026-11-17 — CLI growth, lib.rs split, upgrade 501

Changes landed after the first survey; resolves Q-U1 (mostly) and Q-W1.

### src/lib.rs refactor (~926 → 15 lines)
The gate code split into per-concern modules; `lib.rs` is now only module declarations plus re-exports (`build_router`, `Config`, `Limits`, `SESSION_COOKIE`, `LOGIN_PATH`, `LOGOUT_PATH`):
- `app.rs` — `build_router`, `record_event` middleware, `with_outcome`, 60s purger.
- `auth.rs` — `login`, `logout_page`, `logout`, `forbidden`, `LoginForm`.
- `proxy.rs` — `proxy_or_login`, `forward`.
- `sessions.rs` — `Session`, `valid_session`, `insert_session`, `new_token`.
- `rate_limit.rs` — `reserve_attempt`, `refund_attempt`, `clear_failures`, window consts.
- `state.rs` — `Config`, `Limits`, `AppState`.
- `util.rs` — cookie/header/HTML helpers (`parse_cookies`, `strip_hop_by_hop`, `cross_site`, `login_page`, …).
Public API unchanged; tests moved next to the code they cover.

### New commands
- `remove-user NAME` — opens users.db read-write (`open_for_remove`: errors if missing or lacking the users table), `DELETE WHERE user_name`; exit 2 missing arg, exit 1 unknown name. Live sessions are unaffected (in-memory; expire on TTL or restart).
- `list-users` — `UserStore::list()` = `SELECT user_name, is_admin … ORDER BY user_name`; prints `name<TAB>true|false` on stdout. Errors on missing/empty db (same open as `serve`).
- `parse_args` now accepts one optional positional arg.

### Upgrade attempts → 501
`proxy_or_login` answers `501 Not Implemented` for any authenticated request with an `Upgrade` header — checked after the `/__wsb/` reserved check and after the session check, so the event carries the user name. New `EventKind::Upgrade` serializes as `upgrade`. Unauthenticated requests still get the 401 login page. Integration test `upgrade_requests_get_501` asserts nothing reaches upstream.
