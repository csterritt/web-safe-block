# Cruft hunt results — 2026-11-24

Candidates, not verdicts. Prove with `/is-it-dead` before deleting.

### Twins
- `UserStore::list` (src/users.rs:488) — wraps the free `list_users` (src/users.rs:338); `rg "\.list\("` finds zero call sites anywhere, including tests. `main.rs` calls the free function for `list-users`. Payoff medium · risk low
- Hex-encode idiom `bytes.iter().map(|b| format!("{b:02x}")).collect()` — four copies: src/sessions.rs:33, src/sessions.rs:164, src/users.rs:100, src/users.rs:130. One `to_hex` helper would merge them. Payoff low · risk low
- `login_page` (src/util.rs:176) vs `logout_form_html` (src/auth.rs:222) — same document shell (doctype/meta/`PAGE_STYLE`/escaped `<p>`/form), different form bodies. Payoff low · risk low

### Scaffolding
- `IdleTimeoutBody<B>` (src/proxy.rs:170-238) — generic body wrapper instantiated exactly once (`forward`, src/proxy.rs:160, always hyper's `Incoming`). ~70 lines of generic machinery for one call site. Payoff medium · risk low
- `From<TcpListener> for MonitorListener` (src/monitor.rs:118-122) — production only builds the enum via `bind_monitor`; the `Into` impl exists solely so tests can pass a raw `TcpListener` to `spawn_monitor` (src/monitor.rs:1155, 1206). Payoff low · risk low

### Just-in-case
- `is_admin` — computed in `add_users` (src/users.rs:401), stored in the schema (src/users.rs:19), returned by `lookup`, printed by `list-users` — and grants nothing; README.md:78 says so itself. A flag nothing acts on. Payoff low · risk medium (documented in `list-users` output)
- `peer: Option<SocketAddr>` on `client_ip`/`client_key`/`rate_limit_key` (src/util.rs:238,251,261) — every production call passes `Some` (auth.rs:59, proxy.rs:90, and app.rs:86 where `ConnectInfo` is always set by `into_make_service_with_connect_info`). The `None` → `"unknown"` branch is only exercised by tests. Payoff low · risk low
- `pub use` re-exports `Upstream`, `LOGIN_PATH`, `LOGOUT_PATH`, `SESSION_COOKIE` (src/lib.rs:18-19) — nothing names them: the binary reaches them through `crate::util`, and tests/proxy.rs parses into the `Config` field type and hardcodes `"wsb_session"`. Payoff low · risk low

### Litter
- Identical `Err(e)` and `Ok(Err(e))` match arms in `login` (src/auth.rs:110-120) — same four-line body twice, mergeable with `|`. Payoff low · risk low
- `let _ = i;` (src/rate_limit.rs:68) — statement existing only to silence an unused loop variable in a test. Payoff low · risk low

Not run: cargo machete (not installed; dependency usage checked by grep instead — all 15 crates in Cargo.toml are imported).

**Start with:** `UserStore::list`, the `IdleTimeoutBody` generic, the hex-encode idiom.

10 candidates, 0 to check first.
