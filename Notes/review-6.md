# Code Review 6

Reviewed the repository at `2f9d3961b09e8ac052a308e7dbbca435ba38472c` (`Cargo.toml`, `src/`, `tests/proxy.rs`, `scripts/`, `README.md`, and `Notes/atlas/`).

This review confirms several still-open findings from `Notes/review-5.md` and adds new ones, most notably downstream header-memory amplification, incomplete forwarding-header scrubbing, query-string credential exposure in the monitor, and missing Host validation. Fixes already made for the review-5 daily-counter, slow-body, connection-cap, shutdown, and `TCP_NODELAY` findings are not re-litigated.

*Verification note:* this environment has no `cargo`, `rustc`, `gcc-16`, or `jj` on `PATH`, so I could not compile, run clippy, or execute the test suite. The compiled artifacts under `target/` are for a different architecture and cannot be executed here either. Findings are therefore based on static review of the current source, dependency documentation/source, and the existing tests.

Part 1 lists prioritized findings ordered by severity. Part 2 evaluates the codebase across each of the ten requested review dimensions.

---

## Part 1: Prioritized Findings

### 1. [High] Unauthenticated clients can pin hundreds of MiB of downstream memory with large headers because Hyper's ~400 KiB per-connection buffer is left at its default

**Locations:** `src/server.rs:46-53`, `src/state.rs:66-69`, `Cargo.lock` (`hyper 1.12.0`).

`serve` configures only `header_read_timeout` on the HTTP/1 builder:

```rust
let mut conn_builder = hyper::server::conn::http1::Builder::new();
conn_builder
    .timer(TokioTimer::new())
    .header_read_timeout(limits.header_read_timeout);
```

It never configures `max_header_size`, `max_headers`, or `max_buf_size`. In Hyper 1.x the default maximum read buffer is approximately **417,792 bytes** (`8192 + 4096 * 100`). A client can send a syntactically valid request whose headers fit just below that limit. Even after the request has been parsed and answered, Hyper can retain the enlarged empty read buffer while the keep-alive connection waits for another request; this retention is the subject of the still-open upstream Hyper issue/PR about releasing oversized server read buffers between requests. The project's timeout does not solve the memory placement: the attacker can send the large header quickly, then send a small request often enough to keep the connection open.

Arithmetic matters on the documented small-memory host:

- `max_connections` defaults to 1,024 (`src/state.rs:69`).
- 1,024 connections × ~408 KiB of retained read buffer is about **408 MiB**, before Tokio tasks, sockets, parsed header copies, write buffers, upstream connections, and application state.
- Even in the intended Cloudflare deployment this is not eliminated. Cloudflare's current documented total request-header limit is 128 KiB, so 1,024 saturated connections can still represent roughly **128 MiB** at the gate — already above the README's approximately 67 MiB free-memory target.

This is an unauthenticated remote memory-exhaustion vector. The connection semaphore bounds file descriptors but currently also sizes the attacker's memory budget very generously.

**Recommendation:**

- Set an explicit `max_header_size` commensurate with this application (for example 16–32 KiB, after checking legitimate cookie/user-agent sizes) and consider setting `max_buf_size` explicitly as well.
- Consider lowering `max_connections` or making it configurable; 1,024 concurrent downstream HTTP connections is a large default for a host documented as having ~67 MiB free.
- Add a raw-socket integration test that sends a large-but-accepted header, receives the 401/response, keeps the connection open, and asserts the configured bound is enforced. A second test should assert over-bound headers receive 431/close rather than being buffered indefinitely.
- Track the upstream Hyper read-buffer-retention fix, but do not rely on it as the only control; explicit application-level size limits are still needed.

---

### 2. [High] Forwarding metadata is not actually rebuilt from scratch: `CF-Connecting-IP`, nonstandard `X-Forwarded-*` names, and other client-IP aliases are forwarded upstream

**Locations:** `src/proxy.rs:92-123`, `src/util.rs:262-299`, `README.md:135`.

`forward()` says the client is untrusted and forwarding headers are rebuilt, but it removes only this fixed list:

```rust
for name in [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-real-ip",
] {
    headers.remove(name);
}
```

That is much narrower than the README's claim that incoming `X-Forwarded-*` headers are discarded. In particular, all of these survive to the upstream:

- `CF-Connecting-IP` — even when the peer is not loopback and `client_ip()` explicitly refused to trust it.
- Duplicate or attacker-ordered `CF-Connecting-IP` values — `headers.get()` uses only the first for gate decisions, while all values remain upstream.
- Less common `X-Forwarded-*` names such as `X-Forwarded-Scheme`, `X-Forwarded-Ssl`, `X-Forwarded-Server`, `X-Forwarded-Protocol`, or `X-Original-Forwarded-For`.
- Other commonly trusted client-address headers such as `True-Client-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, `Fastly-Client-IP`, and vendor-specific variants.

The intended Cloudflare path may overwrite some of these, but the gate cannot rely on every edge/proxy overwrite semantics — especially since `serve` explicitly permits non-loopback `listen_addr` with only a warning. The result is a trust-splitting bug: the gate may rate-limit and log one client identity while the protected application trusts a different, attacker-supplied identity header. Applications commonly have framework or platform middleware that prefers `CF-Connecting-IP`, `True-Client-IP`, or an `X-Forwarded-*` variant over the gate's canonical `X-Forwarded-For`.

Related consistency issues remain in `src/util.rs`:

- A parsed IPv4-mapped IPv6 `CF-Connecting-IP` is not canonicalized in `client_key`, while `rate_limit_key` canonicalizes it, so logs/XFF and rate-limit identity can differ textually.
- Multiple `CF-Connecting-IP` headers should fail closed to the peer address rather than selecting the first.

**Recommendation:**

- Strip every header whose lowercase name starts with `x-forwarded-`, not just five examples, then stamp the gate's canonical values.
- Strip or rewrite `cf-connecting-ip` before forwarding. At minimum remove it whenever the TCP peer is not loopback; preferably remove it unconditionally and require upstreams to use the gate's canonical `X-Forwarded-For`.
- Maintain a denylist for other platform-specific client-IP headers (`true-client-ip`, `x-client-ip`, `x-cluster-client-ip`, etc.) or switch to an allowlist of headers the upstream is known to need.
- Reject duplicate `CF-Connecting-IP` values for identity purposes and canonicalize the parsed IP once inside `client_ip()`.
- Add tests that direct clients cannot smuggle any of these alternate identity headers upstream.

---

### 3. [Medium] The monitor logs full query strings, exposing bearer tokens, OAuth codes, reset links, and application session identifiers to local watchers

**Locations:** `src/app.rs:92-96`, `src/monitor.rs:236-250`, `README.md:103-124`.

`record_event` stores `path_and_query` in every monitor event:

```rust
let (path, m2) = truncate_at(
    req.uri().path_and_query().map_or("/", |pq| pq.as_str()),
    1024,
);
```

Query strings frequently carry high-value secrets even in otherwise well-designed applications: OAuth/OIDC `code` and `state`, password-reset tokens, magic-login links, CSRF tokens, signed URLs, search terms, invitation tokens, and sometimes application session IDs. Reverse proxies are a classic place where such data accidentally leaves the application trust boundary. Here it is copied into a 4 MiB in-memory queue and streamed to any monitor client. With the default TCP monitor, any local process can read it; even with the recommended unix socket, the data is retained longer and in more places than necessary.

The internal atlas does say `path+query`, but the README's user-facing monitor documentation only says `path` and gives no explicit warning that query strings are included. “The monitor is local” is not a sufficient reason to collect credentials by default; local access logging is precisely where least-privilege data minimization matters.

**Recommendation:**

- Log only `req.uri().path()` by default. If query strings are operationally indispensable, make them opt-in and document the credential risk prominently.
- Alternatively record a redacted form such as `/callback?…` or a fixed-size keyed hash for correlation without exposing values.
- Add a regression test that a request to `/callback?code=secret` does not place `secret` on the monitor stream.
- Update the README either way so operators cannot misunderstand what is exposed.

---

### 4. [Medium] Missing, duplicate, and invalid `Host` headers are accepted and forwarded instead of rejected with 400

**Locations:** `src/proxy.rs:92-123`, `src/util.rs:325-342`, `src/server.rs:50-53`.

HTTP/1.1 requires a server to reject a request with no `Host` header, more than one `Host` header, or an invalid `Host` value. Hyper historically does not enforce this for the application. This gate does not enforce it either:

- `headers.get(header::HOST)` silently selects the first `Host` value for `X-Forwarded-Host` and for the `Origin` comparison, while all duplicate values remain in the forwarded request.
- If `Host` is absent, Hyper's client may synthesize one from the upstream URI, so the upstream can see a different authority than the client supplied.
- Invalid authority strings are forwarded without validation.

This creates parsing ambiguity between the gate and the protected application. Even when it is not directly exploitable in the gate, reverse proxies should not forward ambiguous request identity and authority metadata; upstream frameworks commonly use `Host` for routing, CSRF origin checks, absolute URL generation, cache keys, and virtual-host selection. Duplicate-host disagreement is a well-known proxy inconsistency class.

**Recommendation:**

- Add an early gate-level validation layer before authentication/routing: for HTTP/1.1 require exactly one `Host` value and parse it as a valid authority; reject missing, duplicate, or invalid values with 400.
- Strip all existing Host values and insert the single validated value before forwarding, or explicitly set the upstream Host according to a documented policy.
- Add raw-socket integration tests for missing Host, duplicate identical Host, duplicate different Hosts, whitespace/userinfo/port abuse, and IPv6 literal forms.
- Make the `Origin` comparison consume that validated canonical host rather than whichever value `HeaderMap::get` happens to return.

---

### 5. [Medium] `valid_session` still hashes attacker-controlled cookie values while holding the global session mutex

**Locations:** `src/sessions.rs:43-57`, `src/util.rs:1-99` (`session_tokens`).

This review-5 finding remains present. Every request — including unauthenticated scanner traffic — enters `valid_session`; when any `wsb_session` cookie is present, SHA-256 and a 64-byte hex allocation are performed while holding `state.sessions`:

```rust
let tokens = session_tokens(headers);
let mut sessions = state.sessions.lock().unwrap();
for token in tokens {
    let key = hash_token(&token);
    ...
}
```

Because minted tokens have a fixed format (32 random bytes encoded as 64 lowercase hex characters), almost every attacker-controlled value is knowably invalid before hashing. Nevertheless large or numerous cookie values are hashed under the one lock that also serializes session lookup, insertion, eviction, logout, and reload. Combined with the large-header issue in Finding 1, this is unnecessary contention on Tokio worker threads.

**Recommendation:**

- Return immediately if there are no session cookies.
- Filter candidates before hashing: exactly 64 ASCII lowercase hex bytes; all other values can never match a minted session.
- Compute candidate hashes before acquiring the mutex, then take the lock only for map lookup/expiry mutation.
- Add a unit test for malformed/oversized cookie values and a contention-oriented integration test if practical.

---

### 6. [Medium] Unix monitor binding remains race-prone and operationally fragile

**Locations:** `src/monitor.rs:177-227`, `src/main.rs:161-190`.

This review-5 finding remains substantially unresolved:

1. **TOCTOU clobber:** `bind_unix_monitor` checks/removes the existing path, then uses `rename(&sock, path)`. `rename` replaces whatever appears in the interim. Concurrent `serve` startup can therefore clobber a live socket rather than fail atomically.
2. **Intrusive liveness probe:** `UnixStream::connect(path)` is used to distinguish a live socket. Against this monitor implementation, that probe consumes the single monitor slot briefly and may cause queued events to be written to a probe that immediately disappears.
3. **Stale files:** the monitor socket is bound before the public listener and router initialization; startup failure after that point leaves the socket behind. Clean shutdown also leaves it behind. The next start handles only a stale socket that returns `ConnectionRefused`.
4. **Temp-name margin:** the temporary path `.w<pid>-<attempt>/s` is longer than the final filename, so a valid final path near the platform `sun_path` limit can fail before rename.
5. **Crash litter:** a crash between temp-dir creation and cleanup leaves `.w<pid>-<attempt>` directories. Predictable names plus a 16-attempt cap make repeated crashes or local interference capable of preventing startup.

**Recommendation:**

- Use an atomic no-replace publication mechanism (for example `hard_link` followed by cleanup where supported, or another platform-appropriate no-clobber operation) rather than unconditional `rename`.
- Reorder startup so all fallible initialization happens before publishing the monitor socket, and unlink the owned socket during orderly shutdown.
- Keep temporary names shorter than final names and clean stale temp dirs opportunistically.
- Avoid consuming the real monitor slot during liveness probes if possible; at minimum document and test that behavior.

---

### 7. [Medium] `list-users` still contradicts the README for an empty database, and database creation can still lose mode `0600` through a dangling symlink

**Locations:** `src/users.rs:167-187, 259-310`, `src/main.rs:129-143`, `README.md:89`.

Two review-5 issues remain:

1. **Empty database behavior:** `open(path, OpenKind::ReadOnly)` returns success after querying `SELECT COUNT(*) FROM users`, even when the count is zero. Only `OpenKind::Serve` rejects `users == Some(0)` (`src/users.rs:298-303`). Therefore `list-users` prints nothing and exits 0 on an empty database, while `README.md:89` says it exits with an error if the database is missing **or empty**.
2. **Dangling symlink permission bypass:** `path.exists()` follows symlinks and is false for a dangling symlink. `create_private_db` then receives `AlreadyExists` from `create_new(true)` and treats it as success. SQLite subsequently follows the symlink and creates the target using the process umask rather than the promised mode `0600`. This breaks the documented confidentiality invariant even absent a malicious local user — for example after an operator rotation mistake leaves a dangling link.

Minor database hygiene issues also remain: the busy timeout is set redundantly, `add_users` opens an immediate transaction even when there are no valid pending rows, and `warn_if_exposed` stats the same files twice with a small race.

**Recommendation:**

- Decide the intended empty-database contract and implement it consistently in both code and README, with a CLI regression test.
- Refuse symlinked database paths or use `symlink_metadata` when `AlreadyExists` is encountered; never let SQLite create the target implicitly.
- Skip the no-op transaction and consolidate connection pragma setup.

---

### 8. [Low] The upstream client pool has no timer or idle-connection bound, so upstream sockets can linger needlessly

**Locations:** `src/state.rs:145-158`.

Both clients are built with only:

```rust
Client::builder(TokioExecutor::new()).build(connector)
```

In `hyper-util`'s legacy client, the default idle timeout is 90 seconds but a pool timer must be installed for background expiry, and `pool_max_idle_per_host` defaults to `usize::MAX`. Since a burst can create up to 256 concurrent upstream connections, a burst can also leave a large collection of idle upstream connections/sockets/tasks around until the upstream closes them or a later request happens to reap expired entries. These idle connections are in addition to newly active requests, so total upstream sockets can exceed the 256-request concurrency budget.

This is bounded in theory by the upstream permit count, but it is still unnecessary FD and memory pressure on the target host and the protected application.

**Recommendation:**

- Configure `pool_timer(TokioTimer::new())`.
- Set a deliberate `pool_max_idle_per_host` appropriate to the workload (possibly a small number, or zero if upstream reuse is unimportant).
- Document the interaction between active-request permits and idle pooled connections.

---

### 9. [Low] The reserved `/__wsb/` namespace is matched only as one literal, case-sensitive, trailing-slash prefix

**Locations:** `src/proxy.rs:35-42`, `src/app.rs:106`, `src/util.rs:74`, `README.md:140`.

The gate treats only paths beginning exactly with `/__wsb/` as reserved. It does not reserve:

- `/__wsb` itself (no trailing slash).
- Case variants such as `/__WSB/login`.
- Percent-encoded byte variants that an upstream framework may decode before routing.
- Dot-segment or duplicate-slash forms that an upstream framework may normalize to `/__wsb/...`.

Unauthenticated users cannot reach upstream either way, so this is not a direct authentication bypass. The invariant is still weaker than “paths under `/__wsb/` are reserved and never forwarded,” especially because the protected application is explicitly not trusted and may normalize paths differently from the proxy.

**Recommendation:**

- Reserve `/__wsb` as well as `/__wsb/`.
- Document that matching is raw, literal, and case-sensitive, or implement a carefully specified normalization policy shared with expected upstreams.
- Add tests for exact-prefix, encoded, and normalization-adjacent paths so the intended contract is explicit.

---

### 10. [Low] Assorted correctness, portability, and maintainability defects remain

**Locations:** `src/auth.rs:153-155`, `src/upstream.rs:40-51, 96-104`, `src/monitor.rs:82-101, 500-512, 651-666`, `src/util.rs:218-241`, `scripts/pull-up-new.sh`, `scripts/tar-new.sh`, `tests/proxy.rs`.

1. **`created` overflow:** `unix_micros().max(*last_created + 1)` can overflow if a tampered database loads `created = i64::MAX`; use `saturating_add` or validated arithmetic.
2. **Public enum invariant escapes:** library callers can construct `Upstream::Http` without an authority and hit `expect` later, or construct a non-loopback `MonitorAddr::Tcp`, bypassing validation. Either make construction fallible/private or document that the enums are internal implementation details.
3. **Monitor drop count can be lost:** `pending()` takes `inner.dropped` before the socket write succeeds. A failed write loses the notification entirely.
4. **Missing `X-Content-Type-Options: nosniff`:** gate HTML/plain-text responses omit this inexpensive hardening header.
5. **Error typo:** the unix-socket diagnostic can print `unix:////...` because it prefixes `unix://` to a `rest` string that already starts with `//`.
6. **Windows clippy risk:** the `unix:` branches in `MonitorAddr::from_str` / `Upstream::from_str` leave `rest` unused under `#[cfg(not(unix))]`, which is a warning under `-D warnings` on non-Unix builds.
7. **Script mismatch and fragility:** the project is jj-first, but `scripts/tar-new.sh` uses `git status`; this only works reliably for the colocated case and should be explicit. `pull-up-new.sh` cleans the remote temporary directory only on the success path, and `tar-new.sh` mishandles index-rename/worktree-delete combinations by archiving a path that no longer exists.
8. **Test-port race:** integration helpers obtain a free port by binding port 0 and closing the listener before the child/server rebinds it. Another process can claim the port in between, causing intermittent failures.
9. **No MSRV/package metadata:** `edition = "2024"` implies a modern compiler, but `Cargo.toml` does not document `rust-version`; contributors only discover toolchain requirements indirectly.

---

## Part 2: Review by Requested Dimension

### 1. Code quality problems

The code is generally well organized into small, single-purpose modules (`auth`, `sessions`, `users`, `proxy`, `monitor`, `server`), with unusually explicit comments explaining security-relevant invariants. The write-through session design and bounded queues show evidence of careful iteration.

The main quality concerns are concentrated at trust boundaries:

- Finite denylist header scrubbing while claiming wildcard behavior (Finding 2).
- Validation invariants encoded only in parser constructors but bypassable through public enum variants (Finding 10).
- Work performed inside locks that does not need to be there (Finding 5).
- `src/monitor.rs` and `tests/proxy.rs` are large and dense; both are still readable, but monitor behavior now has enough clock, socket, queueing, and retention logic that further decomposition would reduce risk.

### 2. Best practice violations

The most important violations are reverse-proxy and operational best practices:

- Forwarding ambiguous duplicate Host metadata rather than rejecting it (Finding 4).
- Logging complete query strings by default (Finding 3).
- Relying on dependency defaults for header/buffer sizes on a memory-constrained internet-facing service (Finding 1).
- Allowing SQLite to create a database through a dangling symlink with default umask permissions (Finding 7).
- Running with a default local TCP monitor even though any local process can connect; the unix-socket mitigation is documented, which softens but does not remove the concern.

Positive practices include strict TOML unknown-field rejection, constant-time hash comparison, HttpOnly/SameSite cookies, hop-by-hop header stripping, cache rewriting, WAL use for backup compatibility, and explicit loopback checks.

### 3. General mistakes

The clearest general mistakes are small but concrete:

- Empty-DB `list-users` behavior contradicts the README (Finding 7).
- The unix error message can contain four slashes (Finding 10).
- The monitor drop notification is consumed before durable delivery (Finding 10).
- The creation-stamp increment is not overflow-safe (Finding 10).
- Test free-port probing has a classic close-then-rebind race (Finding 10).

None of these individually undermines the design, but they are exactly the kind of small inconsistencies that should be cleaned up before they become operational folklore.

### 4. Logic correctness and edge case handling

Strengths:

- Session insertion/removal is serialized and write-through ordering is deliberate.
- Eviction uses persisted creation stamps rather than expiry order.
- Multiple cookies and non-UTF-8 cookie bytes are handled better than in most small proxies.
- Daily-count rolling now handles large clock jumps and backward steps much better than the version criticized in review 5.
- Login body buffering, connection caps, and shutdown deadlines have been added since review 5.

Remaining edge-case concerns:

- Host cardinality/validity is not enforced (Finding 4).
- Literal-only reserved-path matching creates normalization edge cases (Finding 9).
- Refunds in the rate limiter pop the newest timestamp for a key rather than the exact concurrent attempt being refunded; counts remain mostly correct, but timestamp attribution can be wrong when concurrent attempts complete out of order.
- `reload_sessions` trusts rows produced by the normal writer path; it does not itself enforce count caps or validate creation-stamp invariants if the database was externally manipulated.

### 5. Security vulnerabilities and data validation

The highest-impact security concerns are:

- Header-memory amplification (Finding 1).
- Incomplete forwarding-identity scrubbing and trust splitting (Finding 2).
- Query-string secret exposure in monitor events (Finding 3).
- Host ambiguity forwarded to upstream (Finding 4).
- Database symlink permission bypass (Finding 7).

Positive security properties are substantial: per-user Argon2id salts, dummy-hash work for unknown users, session-token hashing at rest, fail-closed cross-site POST checks, explicit cookie stripping, cache hardening, upgrade refusal, loopback-only monitor parsing, and warnings for exposed database files.

Design risks that appear intentional but should remain visible to operators:

- Cookies are not port-scoped, so another service on the same hostname can receive or attempt to shadow `wsb_session`; the README notes this but does not fully discuss cookie-tossing/session-fixation consequences.
- Any local process can spoof `CF-Connecting-IP` to the gate; the README does disclose this.
- The 180-day default session lifetime is very long. It is configurable and documented, but a stolen cookie remains valuable for months.

### 6. Performance implications and resource usage

The dominant performance issue is downstream memory amplification from large headers (Finding 1). Secondary resource concerns are:

- SHA-256 work under the global session mutex (Finding 5).
- Unbounded idle pooled upstream connections due missing pool timer/idle bound, capped indirectly but not explicitly (Finding 8).
- Monitor queue memory is bounded by count and approximate bytes, which is good; however each `pending()` call clones up to 100 events before writing. Given the individual field caps this is modest, not alarming.
- Session eviction can scan the whole map and repeat scans when many entries need removal. With the fixed 10,000 cap this is acceptable in normal operation and was previously accepted.
- `TCP_NODELAY` is now set, correcting the latency regression noted in review 5.

### 7. Code style and maintainability standards

Style is consistent, compact, and idiomatic Rust. Comments often explain *why*, not merely what. The cfg split for Unix sockets is understandable, though non-Unix warning cleanliness needs attention.

Maintainability concerns:

- `src/monitor.rs` is over 1,300 lines including tests and mixes queue semantics, time formatting, daily counters, socket binding, and connection serving.
- `tests/proxy.rs` is over 2,300 lines and mixes raw-socket tests, CLI tests, upstream fixtures, and proxy behavior; splitting fixtures by concern would make failures easier to diagnose.
- Several fixed resource limits live in `Limits::default()` rather than configuration. That is a defensible simplicity choice, but it should be explicit in operator documentation if intentional.
- Helper scripts do not clearly reflect the jj-first workflow documented in `AGENTS.md`.

### 8. Error handling and logging

Error handling is generally careful around SQLite transactions and session write ordering. The decision not to expose detailed internal errors to users is appropriate.

Concerns:

- `eprintln!` is used for operational warnings/errors while login success uses `println!`; there is no consistent logging convention or severity structure.
- Accept-loop errors are silent except for a sleep. Silently retrying is better than crashing, but a rate-limited warning would make fd exhaustion or persistent accept failure visible.
- Monitor socket probe/accept behavior can perturb the very event stream it is trying to protect (Finding 6).
- Monitor events are the primary observability mechanism, yet query strings create a secrecy problem and drop notifications can be lost (Findings 3 and 10).

### 9. Test coverage and quality

Coverage is unusually broad for a project of this size: integration tests exercise login, logout, restart persistence, eviction order, cache rewriting, cookie edge cases, upstream errors, upgrade refusal, unix upstreams, unix monitor sockets, slow login bodies, connection caps, write stalls, shutdown deadlines, monitor batching, clock behavior, and CLI permission modes.

Important missing or weak coverage:

- Large-header memory/size behavior (Finding 1).
- Alternate forwarding headers, `CF-Connecting-IP` pass-through, duplicate `CF-Connecting-IP`, and duplicate Host (Findings 2 and 4).
- Query-string redaction policy (Finding 3).
- Empty-database `list-users` contract and dangling-symlink database creation (Finding 7).
- Concurrent unix monitor bind/startup behavior (Finding 6).
- Encoded/trailing-slash/case variants of the reserved namespace (Finding 9).
- `max_login_waiters` saturation and out-of-order rate-limit refund behavior.
- Non-Unix compilation/clippy is not covered here at all.

Test reliability concerns: the free-port race, timing-sensitive monitor disconnect tests, and use of real wall-clock sleeps can produce flaky results on loaded machines or platforms with different socket behavior.

### 10. Documentation and comments

The README is extensive and generally candid about trade-offs. In particular, the Cloudflare/client-IP and separate-user sections are better than typical small-project documentation.

Documentation mismatches or omissions remain:

- The claim that incoming `X-Forwarded-*` headers are discarded is broader than the implementation (Finding 2).
- The monitor documentation does not clearly warn that query strings are logged (Finding 3).
- `list-users` empty-database behavior is documented incorrectly (Finding 7).
- Reserved-path documentation does not state raw/literal matching semantics (Finding 9).
- Header-size/resource expectations are not documented even though they drive the memory model (Finding 1).
- The atlas is unusually detailed, but because it is generated from `data.mjs`, any fix should update the source and regenerate rather than editing generated files.

---

## Overall assessment

The project is substantially more mature than earlier reviews suggest: the highest-impact session consistency, slow-body, shutdown, clock-roll, and latency issues have been addressed, and the test suite reflects real attention to edge cases. The remaining serious risks are concentrated where a reverse proxy most often fails in production: byte and header budgets, canonicalization of client/authority identity, metadata scrubbing, and accidental credential capture in logs.

I would prioritize Finding 1 immediately because it is remotely triggerable before authentication and directly contradicts the low-memory design goal. Finding 2 should follow because it undermines the trust boundary between the gate and the protected application. Findings 3–5 are then worthwhile hardening/correctness work with relatively small implementation surface area.
