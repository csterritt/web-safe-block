# Code Review 2

Reviewed the repository at `aa29e2380876f2c94885611e2f3d9aa7a815227d`, primarily `src/`, `tests/proxy.rs`, configuration, and the operational/security documentation. Findings are ordered by severity. This is a review, not an implementation change.

## Findings

### 1. [High] Protected responses can be served from a shared cache without authentication

**Locations:** `src/proxy.rs:123-136`; compare `src/util.rs:90-103`.

The proxy returns upstream caching headers unchanged. Only the gate's own HTML pages receive `Cache-Control: no-store`. An application can therefore return a protected resource with `Cache-Control: public, max-age=300`, without `Vary: Cookie`, and explicitly authorize an intervening shared cache to reuse it for another client. A request's `Cookie` header does not, by itself, prohibit shared caching. On a cache hit, the request never reaches the session check.

**Verification:** A local upstream served a protected stylesheet with that cache policy and no `Set-Cookie`. Through a local shared-cache test fixture honoring the explicit public policy, an authenticated request populated the cache, and a subsequent request without any cookie received `200`, a cache hit, and the protected body. The same unauthenticated request sent directly to web-safe-block received `401`. This verifies the failure mode, not the configuration of a particular production CDN.

**Recommendation:** Enforce a non-shared/non-storable cache policy on gated responses, accounting for CDN-specific cache-control overrides as appropriate. Document required edge cache bypasses rather than assuming that TLS termination or a session cookie implies them. Add a two-client integration test through a cache: one client authenticates and fetches a resource; the other must still be denied.

### 2. [High] The event queue is bounded by count, not by memory, and is attacker-fillable before login

**Locations:** `src/app.rs:43-54,63-73`; `src/monitor.rs:99-114,120-131,206-215`.

Every request copies its complete path/query and user-agent into an event. The default queue retains 1,000 events, but neither individual fields nor total retained bytes have an application-level bound. An unauthenticated caller can fill it with large headers using ordinary GETs, without encountering the login rate limiter. Connecting a monitor additionally clones the queued events and constructs a serialized batch, increasing peak memory and holding the queue mutex during cloning.

**Verification:** An unauthenticated GET with a 100,000-byte user-agent was accepted with `401`; the monitor emitted a 100,156-byte JSON line containing the entire user-agent. At the default capacity, 1,000 such events retain approximately 95 MiB of user-agent data alone, before allocation overhead, other fields, or monitor copies. That exceeds the README's stated 67 MB free-memory motivation. The full memory-exhaustion workload was deliberately not run.

**Recommendation:** Cap/truncate request metadata with an explicit truncation indicator, enforce a total queue byte budget, and bound monitor batch sizes. Apply suitable request-header limits as defense in depth. Test oversized unauthenticated metadata and assert retained-byte bounds, not just event counts.

### 3. [High] Logout reports success even when durable revocation fails, allowing the session to return

**Locations:** `src/auth.rs:160-181`; `src/sessions.rs:98-113`.

Logout removes the in-memory entry before attempting the database deletion. If deletion fails, it only logs the error, still returns `303`, and clears the browser cookie. The persisted session remains valid and is restored by the next successful reload or process restart. Someone retaining a copy of the old cookie can then use it again. A retry before reload also skips deletion because the map entry is already absent.

**Verification:** After logging in against a disposable database, another SQLite connection held `BEGIN IMMEDIATE`. Logout returned `303` after approximately 5.2 seconds and logged `session delete failed: database is locked`. The old token initially received `401`, but received `200` after releasing the database lock and actually stopping and restarting the server.

There is also a success-path race: the session-map lock is released before database deletion. A concurrent reload can read the still-existing row and reinstall it before the deletion completes, leaving the supposedly revoked session in memory until another reload.

**Recommendation:** Coordinate deletion with cache refresh and acknowledge successful logout only after durable revocation succeeds. Return an actionable server error on failure rather than success, and attempt deletion by token hash independently of map membership. Add database-failure/recovery and concurrent logout/reload tests that replay the old token.

### 4. [High] Fast phrase hashes remain vulnerable to offline guessing; the new policy and cracking estimates do not address it

**Locations:** `src/users.rs:43-72,275-281`; `README.md:19-29`.

This remains open from the first review. A database reader can test a candidate with one unkeyed SHA-512 operation and compare it against every user's deterministic hash. The length/digit/punctuation policy does not establish entropy: predictable sentences and repeated characters still pass. The README's estimates assume effectively uniform selection from a large candidate space, but the recommended human-chosen sentences are not sampled that way. Attackers try likely phrases and predictable suffixes first; they need not enumerate the advertised space. This does not mean every long phrase will be cracked quickly, but the stated estimates are not a defensible guarantee.

**Verification:** The CLI accepted a 20-character phrase consisting of 18 `a` characters followed by `1!`. One Python `hashlib.sha512` calculation reproduced its stored credential hash.

**Recommendation:** Use a credential-storage design resistant to database-only compromise. A separately held secret-keyed lookup index can preserve phrase-only login; a username-based flow can instead use conventional per-user salted, slow password verification. Choose and document an explicit threat model and recovery/rotation procedure. If retaining the present design, require genuinely generated high-entropy phrases and remove unsupported cracking-time assurances; a composition rule alone is not equivalent.

### 5. [Medium] Newly created credential databases are world-readable under a normal umask

**Location:** `src/users.rs:74-78`.

`Connection::open` creates the database without restricting its permissions. With umask `0022`, the resulting mode is `0644`. If the containing directories are traversable, another local account can read all credential hashes despite the README's instruction to keep the database private. This materially increases exposure to finding 4. The stored session hashes are not directly reusable bearer tokens, but that does not protect the phrase hashes.

**Verification:** A database created through the documented `write-config` / `add-user` flow had mode `0644` with umask `0022`.

**Recommendation:** Create new credential databases with owner-only permissions, account for SQLite sidecar files, and either reject or clearly warn about insecure existing-file permissions. Do not silently change the permissions of unrelated existing files. Add a Unix permissions test under an explicit permissive umask.

### 6. [Medium] Blocking SQLite operations and a global session lock stall unrelated requests

**Locations:** `src/auth.rs:64,90-111`; `src/users.rs:23-26,244-254,275-289`; `src/sessions.rs:98-112`.

The async handlers call synchronous SQLite APIs and wait on `std::sync::Mutex` directly on Tokio workers. SQLite can wait up to five seconds for a database lock. Login additionally holds the global session-map mutex throughout the write, and reload holds it throughout database cleanup and loading. Consequently, a slow write blocks session checks for unrelated authenticated traffic; waiting tasks can also block other runtime workers on the same mutex.

**Verification:** Another connection held a write transaction for 1.5 seconds while a successful login attempted to persist its session. An unrelated authenticated GET, whose upstream answered immediately, took approximately 1.36 seconds because it waited behind that login.

**Recommendation:** Move synchronous database work to a bounded blocking executor or dedicated database worker, and avoid holding the session-map lock across disk I/O or busy waits. Preserve the required ordering between committed database changes and cache updates rather than simply removing locks. Add a contention test asserting that database delays do not block unrelated proxy traffic.

### 7. [Medium] The default advertised as six months actually lasts 1,260 days

**Locations:** `src/settings.rs:25-26,193`; `README.md:73`; `Notes/atlas/SYSTEM.md:32`.

`108864000 / 86400` is **1,260 days**, approximately **3.45 years**, not six months. The value controls both server-side session expiry and the cookie's `Max-Age`. The unit test asserts the same incorrect literal, so it preserves the mistake instead of checking the intended duration. The atlas cost-model table separately still says the default is seven days.

**Recommendation:** Decide what "six months" means for this configuration, derive the seconds from that definition, and make the generated configuration and documentation agree. For example, a deliberately chosen 180-day lifetime is `15_552_000` seconds. Assert the intended day count in tests. Correcting the default does not shorten already-persisted sessions, so also decide how to handle the overlong sessions already issued.

### 8. [Medium] An upstream that stalls after sending headers retains proxy resources indefinitely

**Locations:** `src/proxy.rs:99-121,123-136`.

The timeout wraps `state.client.request(req)`, which completes when response headers arrive. The response body is then forwarded without an idle deadline. An upstream that sends `200` and an incomplete body can retain the downstream request and upstream connection indefinitely, even though the response-header timeout works correctly. There is also no application-level concurrency bound to limit the number of these retained streams.

**Verification:** A local upstream immediately returned `200`, declared a 100-byte body, sent one byte, and then stopped sending. The proxy returned headers immediately but did not terminate the body during the following 62 seconds; only the test client's own timeout ended the wait. This is a gap after headers, not a claim that the README promises a total-transfer deadline.

**Recommendation:** Apply a configurable body idle timeout, or define an explicit streaming policy together with a concurrency limit. Prefer an idle deadline over a short absolute deadline so legitimate long downloads or active streams can continue. Extend the stalled-upstream test to cover a response that stalls after headers and partial body data.

### 9. [Medium] Persistence loses the ordering needed to evict the oldest session

**Locations:** `src/users.rs:29-30,224-239,250-252`; `src/sessions.rs:68-89`; `tests/proxy.rs:623-639,642-677`.

Eviction chooses the smallest expiry from a `HashMap`. Before persistence, expiries retain subsecond precision, but the database stores only whole Unix seconds. After restart, sessions created within one second have equal expiries, so whichever tied entry the hash-map iterator encounters first is removed, not necessarily the oldest. More generally, expiry order is not creation order if the configured TTL changes.

**Verification:** Three sessions created within one second were persisted, the process was stopped and restarted, and a fourth login was performed. Requests using tokens in creation order returned `[200, 401, 200, 200]`: the second session was evicted while the oldest remained valid. All three original stored timestamps were identical.

The current "restart" integration test starts a second router while the first is still running; it does not stop and restart the process. The oldest-session test checks eviction before a reload, where the precision loss is absent.

**Recommendation:** Persist an unambiguous creation/insertion order separately from expiry and use it consistently for eviction. Add a genuine restart test with multiple sessions created in the same second, and a test covering a TTL change. Verify both the accepted tokens and the persisted rows.

## Validation And Coverage

- `cargo test --locked --all-targets`: passed all 60 tests (39 library, 1 binary, 20 integration).
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- Focused probes used temporary databases and local listeners. No existing users database, configuration, or implementation file was changed.
- Existing tests meaningfully cover basic gating, session-cookie isolation, concurrent login throttling, ordinary logout/CSRF behavior, persistence loading, user removal, and response-header timeouts. They do not cover the failure/recovery and resource-budget scenarios above.
- No standalone formatting/style findings: the module split is understandable. The most consequential maintainability problem is coordinating two authorities for sessions, with locking and failure behavior spread across authentication, persistence, and reload code.

## Assumptions And Limits

- Assumed the documented trusted-edge deployment and one serving process per database. Trusting `CF-Connecting-IP` is explicitly documented; arbitrary direct access to that listener would invalidate the assumption.
- The cache reproduction uses a local fixture honoring an explicit public cache policy. No claim is made that a particular Cloudflare account or other production edge was inspected.
- Large-event retention was verified with individual requests, not an intentional out-of-memory test. No production-scale load benchmark, fuzzing run, or external dependency-vulnerability database audit was performed.
- This review does not re-report the first review's fixed issues as if they were still present. The phrase-hashing issue is explicitly identified as an unresolved design risk.
