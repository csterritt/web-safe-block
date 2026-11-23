// Single source of truth for the web-safe-block atlas.
// Build: bun Notes/atlas/build.mjs  → writes SYSTEM.md and atlas.html beside this file.

export const META = {
  title: 'web-safe-block',
  artifactUrl: '',                        // fill after first publish; keep it stable across rebuilds
  sourcePath: 'Notes/atlas/data.mjs',
  buildCmd: 'bun Notes/atlas/build.mjs',
  outDir: '.',                            // generated files land in Notes/atlas/, next to this source
  stats: [
    { k: 'System', v: 'rust · axum 0.8 + hyper 1' },
    { k: 'Source', v: '~2,900 LOC · ~3,300 tests' },
    { k: 'Seats', v: '1 public port · 1 monitor' },
  ],
  intro: `_**This file is the living source of truth for the design.** The interactive atlas (\`atlas.html\`) is built from the same data; edit this file and rebuild, never the outputs._`,
  onePara: `web-safe-block is a small Rust program that parks itself in front of a web server you don't fully trust. The internet reaches only its public port (through a TLS terminator such as Cloudflare Tunnel); it answers every request with a small login form until someone submits a user name and pass phrase that verifies against \`users.db\` — then it mints a session cookie (persisted as a hash in \`users.db\`) and becomes a plain reverse proxy to the protected app on loopback. A second, loopback-only port streams one JSON line per request to a single watcher. v1 answers protocol upgrades with a 501 instead of relaying them, and sessions survive a restart.`,
  costModel: [
    'Bounds, not dollars — this is one process on one box. Every in-memory structure is capped:',
    '',
    '| Resource | Bound | Where |',
    '|---|---|---|',
    '| Sessions | 3 per user, 10,000 total, TTL from `session_ttl_secs` (default 180d); earliest-created evicted; persisted as hashes in users.db | `src/state.rs` `Limits` + `src/sessions.rs` |',
    '| Failed-login keys | 10,000 IPs, ≤10 stamps each, 15-minute window; fullest ledger evicts the fewest-stamp key | `src/rate_limit.rs` `reserve_attempt` |',
    '| Argon2 memory | one ~12 MiB hash at a time, on the blocking pool; at most 32 logins queued, extras get 503 | `src/state.rs` `hash_slot` + `login_waiters` + `src/auth.rs` |',
    '| Client connections | 30s to send request headers; writes may stall 60s | `src/server.rs` `serve` + `StallTimeoutIo` |',
    '| Login POST body | 4,096 B | `src/app.rs` `DefaultBodyLimit` |',
    '| Event queue | `monitor_queue_len` (default 100) events *and* ~4 MiB retained, oldest overwritten | `src/monitor.rs` `EventQueue` |',
    '| Upstream waits | 10s to connect, 60s for response headers, 60s body-idle; 256 requests upstream at once | `src/proxy.rs` `forward` |',
    '| users.db | one row per user; phrase kept only as a per-user salted Argon2id hash; 5s busy timeout | `src/users.rs` |',
  ],
  deepDive: '',
  platformGives: 'axum 0.8 (router, form extractor, middleware), hyper + hyper-util (HTTP/1 server and client with timeouts), rusqlite with bundled sqlite, tokio, rand, argon2, sha2, subtle, serde + serde_json, toml.',
  weOwn: 'the gate: user-name + pass-phrase login, persisted sessions (write-through to users.db behind an in-memory map), the per-IP throttle, header scrub + forwarding-header rebuild, the bounded event queue and monitor thread, strict config loading, and the users.db schema plus pass-phrase strength policy.',
  filesystem: `web-safe-block/
  src/
    main.rs       commands: write-config · add-user · remove-user · list-users · serve
    lib.rs        crate root: module wiring + re-exports
    app.rs        router, record_event middleware, 60s purger
    auth.rs       login/logout handlers
    server.rs     accept loop: header-read + write-stall timeouts
    proxy.rs      session check, 501 on upgrade, forwarder
    sessions.rs   session table ops + token minting
    rate_limit.rs per-IP failure ledger ops
    state.rs      Config · Limits · AppState
    util.rs       cookie/header/HTML helpers
    users.rs      users.db schema, phrase normalize/hash, UserStore
    monitor.rs    EventQueue + monitor thread (JSON lines)
    settings.rs   config.toml: strict load + write_default
  tests/proxy.rs  end-to-end tests against a real upstream
  Notes/atlas/    this atlas`,
};

// Decisions render as the SYSTEM.md table and the last chapter's "Decisions locked" list.
export const DECISIONS = [
  { axis: 'Runtime', decision: 'Rust + axum/hyper on one tokio runtime; a plain OS thread runs the monitor', adr: '—' },
  { axis: 'Credential', decision: 'User name + pass phrase; names are 1–64 printable ASCII, matched case-insensitively', adr: '[0001](./adr/0001-phrase-is-the-credential.md)' },
  { axis: 'Phrase storage', decision: 'Per-user salted Argon2id (12 MiB, t=3, p=1, 32-byte out) of the normalized phrase, looked up by user name — unknown names still cost one hash against a dummy salt; ≥20 chars + digit + punctuation enforced at add time', adr: '[0001](./adr/0001-phrase-is-the-credential.md)' },
  { axis: 'Sessions', decision: 'Write-through to a sessions table in users.db (SHA-256 of the token only), in-memory map as cache, 3/user and 10k total with earliest-created evicted; the db write lands before the map mutates; reload at startup and on the 60s purge tick picks up remove-user', adr: '[0006](./adr/0006-sessions-persisted.md)' },
  { axis: 'Hash work', decision: 'Argon2 runs are serialized through hash_slot on the blocking pool — at most one ~12 MiB hash at a time', adr: '—' },
  { axis: 'Client IP', decision: 'CF-Connecting-IP is trusted only from a loopback peer (cloudflared on the same box) and when it parses as an IP; any other peer is keyed on its own address. serve warns if listen_addr is not loopback', adr: '[0003](./adr/0003-trusted-edge-header.md)' },
  { axis: 'Config', decision: 'Every setting required; unknown keys rejected; relative users_db resolves against the config file; session_ttl_secs bounded to 1s–10y', adr: '[0004](./adr/0004-strict-config.md)' },
  { axis: 'Monitor', decision: 'One loopback JSON-lines client at a time; queue bounded by count and ~4 MiB, oldest overwritten', adr: '[0005](./adr/0005-one-monitor.md)' },
  { axis: 'Upstream', decision: 'http:// (no path) or unix:/absolute/path socket — the protected app stays on the same machine', adr: '—' },
  { axis: 'Reserved paths', decision: '/__wsb/* is never forwarded; cross-site POSTs to it are rejected', adr: '—' },
  { axis: 'Shared caches', decision: 'Upstream Cache-Control is rewritten to private (public/s-maxage/proxy-revalidate and CDN override headers dropped) — a shared cache must never serve a gated page', adr: '—' },
  { axis: 'Protocol upgrades', decision: 'An Upgrade header gets 501 after the session check — never proxied (a real WS relay is still a ghost)', adr: '—' },
];

export const GROUPS = [
  { id: 'edge', title: 'The edge' },
  { id: 'gate', title: 'The gate' },
  { id: 'relay', title: 'Through to the app' },
  { id: 'ops', title: 'Operating it' },
  { id: 'off', title: 'Not switched on' },
];

// Structure = one isometric box. kind: box|tall|store|cards|slab|screen|gate|job
export const NODES = [
  // ---- The edge ----
  { id: 'BR', code: 'B', name: 'Visitor\'s browser', short: 'BROWSER', group: 'edge', gx: 0, gy: 6, w: 2, d: 2, h: 26, kind: 'screen',
    one: 'A person with a browser, outside, who wants in.',
    what: 'Anyone on the internet. They see exactly two things from web-safe-block itself: the phrase form, and — once they are in — whatever the protected app serves.',
    how: 'All it ever needs to send is a <code>POST /__wsb/login</code> with <code>user</code> and <code>phrase</code> fields, then carry the <code>wsb_session</code> cookie. No JavaScript on our pages; plain forms only.',
    steps: [
      ['Ask', 'GET any path — gets the login form back until logged in.'],
      ['Submit', 'POST the user name and phrase to /__wsb/login.'],
      ['Carry', 'Browser sends wsb_session automatically on later requests.'],
    ],
    cond: [] },
  { id: 'CF', code: 'T', name: 'TLS terminator', short: 'TUNNEL', group: 'edge', gx: 3.5, gy: 4.5, w: 2, d: 2, h: 40, kind: 'box',
    one: 'Cloudflare Tunnel (or any TLS front) — the only road in.',
    what: 'TLS is not web-safe-block\'s job. A tunnel or reverse proxy holds the certificate and forwards plain http to the public port, stamping the real client IP in a header.',
    how: 'Forwards to <code>listen_addr</code> (default <code>127.0.0.1:8080</code>) and sets <code>CF-Connecting-IP</code>, which the gate trusts <mark>only when the TCP peer is loopback</mark> — i.e. cloudflared on the same machine — and the value parses as an IP; from any other peer the header is ignored and the peer address is used for client IP, rate limiting, and event logs.',
    steps: [
      ['Terminate', 'TLS ends here; onward hop is plain http.'],
      ['Stamp', 'Adds CF-Connecting-IP with the real client address.'],
      ['Forward', 'Sends the request to listen_addr.'],
    ],
    cond: [
      { q: 'If listen_addr is ever exposed directly, CF-Connecting-IP becomes attacker-controlled — should the gate only honor it from the tunnel\'s peer address?', r: 'Yes, option A: the header is honored only from a loopback peer (127.0.0.0/8, ::1, IPv4-mapped loopback), with no new config setting; other peers are keyed on their own address, and serve warns at startup when listen_addr is not loopback. cloudflared must run on the same machine (2026-11-21).' },
    ] },
  // ---- The gate ----
  { id: 'G', code: 'G', name: 'The gate', short: 'GATE', group: 'gate', gx: 7, gy: 3, w: 3, d: 2.5, h: 56, kind: 'gate',
    one: 'The public listener: login page, session check, reserved endpoints, upgrade refusal, then forward-or-refuse.',
    what: 'One port answers every request the internet sends. Without a valid session you get the phrase form and nothing else; with one, your request is handed to the forwarder — unless it asks for a protocol upgrade, which earns a 501. A tiny /__wsb/ namespace carries login, logout, and nothing else.',
    how: '<code>axum</code> router in <code>src/app.rs</code>: <code>GET|POST /__wsb/login</code> (GET just 303s to /; POST bodies capped at 4 KiB) and <code>GET|POST /__wsb/logout</code> live in <code>src/auth.rs</code>, fallback <code>proxy_or_login</code> in <code>src/proxy.rs</code>. Any other <code>/__wsb/*</code> path is a 404 <mark>reserved</mark>. The login form carries a sanitized <code>next</code> so a successful login returns you to what you asked for. Cross-site POSTs are refused via <code>Sec-Fetch-Site</code> (<code>same-origin</code>/<code>none</code> pass), then an <code>Origin</code> that must match Host — https when cookies are Secure. A POST with neither header is refused too. Phrase checks run on the blocking pool, <mark>one Argon2 hash at a time</mark> (<code>hash_slot</code>), and at most <mark>32 logins may queue</mark> for it — extras get 503, kind <code>login_busy</code>. Authenticated requests with an <code>Upgrade</code> header get <mark>501</mark>, kind <code>upgrade</code>. Every request exits through <code>record_event</code> middleware; gate pages are <code>no-store</code> and frame-denied.',
    steps: [
      ['Route', '/__wsb/ endpoints handled here; unknown ones are 404 reserved.'],
      ['Authenticate', 'Check every wsb_session cookie offered — first valid wins; expired ones drop lazily.'],
      ['Decide', 'Login page (401), the login/logout handlers, 501 for upgrade attempts, or hand to the forwarder.'],
      ['Report', 'Attach an Outcome; middleware pushes one event per request.'],
    ],
    cond: [
      { q: 'Should GET /__wsb/logout end the session?', r: 'No — GET shows a confirm form; only POST destroys the session, and cross-site POSTs are rejected (review-1 finding 5, fixed).' },
      { q: 'Cross-site POST checks fall back to Origin only when Sec-Fetch-Site is absent; a client sending neither is allowed through. Keep that posture?', r: 'No, option B: fail closed — a POST to /__wsb/login or /__wsb/logout with neither Sec-Fetch-Site nor Origin gets 403 forbidden; every supported browser sends Origin on POST, and scripted clients must add one of the headers (2026-11-21).' },
      { q: 'A client that disconnects mid-login drops the hash_slot guard while its Argon2 run continues — rapid resets can stack many 12 MiB hashes in parallel and OOM the box. Move an owned guard inside the blocking task?', r: 'Fixed — owned hash_slot (and session_writes) guards now move inside the blocking closures, so a cancelled request cannot release them early; at most 32 logins may queue for the slot, extras get 503 login_busy (review-4 finding 1, fixed).' },
      { q: 'A non-UTF-8 byte in any sibling cookie makes parse_cookies skip the whole Cookie header — a valid wsb_session is ignored (lockout loop) and logout then revokes nothing server-side. Parse cookies on raw bytes like strip_session_cookie does?', r: 'Fixed — session_tokens parses Cookie headers on raw bytes, matching wsb_session by name and keeping only UTF-8 values (review-4 finding 3, fixed).' },
    ] },
  { id: 'S', code: 'S', name: 'Session table', short: 'SESSIONS', group: 'gate', gx: 6, gy: 7, w: 2, d: 2, h: 22, kind: 'store',
    one: 'The gate\'s memory: hashed token → user + expiry, cached in RAM and persisted in users.db.',
    what: 'A small table that answers "who is this cookie?" Login puts a random token in; every later request trades the cookie for a user name. A restart reloads the live sessions — nobody is logged out.',
    how: '<code>HashMap&lt;String, Session&gt;</code> behind a <code>Mutex</code>, write-through to the <code>sessions</code> table in <code>users.db</code>. Tokens are <mark>32 random bytes, hex</mark>; only their <mark>SHA-256 hash</mark> is stored — the raw token exists solely in the Set-Cookie header. Each session also gets a unique, increasing <code>created</code> stamp (unix µs, persisted) — when a cap is hit, expired entries drop first, then <mark>the earliest-created is evicted</mark>, so expiry changes can\'t reshuffle the order. On login the db write (insert + evictions, one transaction) lands <mark>before</mark> the map mutates; a failed save evicts nothing. Caps: 3 per user and 10,000 total. Every <code>wsb_session</code> cookie offered is checked — the first valid wins; expired ones drop lazily. The table is reloaded at startup and every 60s, dropping expired rows and picking up sessions deleted by <code>remove-user</code>.',
    steps: [
      ['Insert', 'new_token() → hash → Session{user, expires, created}; plan evictions (earliest-created first); write rows to users.db, then mutate the map.'],
      ['Check', 'Each offered cookie → SHA-256 → lookup; valid + unexpired → user name.'],
      ['Reload', 'At startup and every 60s: delete expired rows, clear the map, refill from the table — also sees remove-user deletions.'],
    ],
    cond: [
      { q: 'Sessions die on restart — acceptable while this guards one box, or should they persist?', r: 'Persisted — write-through to the sessions table in users.db, hashes only, reload at startup and on the purge tick (ADR 0006, 2026-11).' },
      'A running serve notices remove-user deletions only on the 60s reload — is up to a minute of grace acceptable?',
      { q: 'A client that disconnects while a session write is in flight drops the session_writes guard but not the blocking db call — the table can commit a session the map never learns, or keep rows the write evicted, until the next reload. Move the owned guard and the map mutation inside the blocking task?', r: 'Fixed — login, logout and the purger move the owned session_writes guard into the blocking closure, which also performs the map mutation on success (review-4 finding 1, fixed).' },
    ] },
  { id: 'R', code: 'R', name: 'Failure ledger', short: 'THROTTLE', group: 'gate', gx: 8.5, gy: 7, w: 2, d: 2, h: 22, kind: 'store',
    one: 'Ten failed logins per quarter-hour per client — and each miss costs a second.',
    what: 'The brute-force brake. Every failed login is written down against the client\'s IP; after ten in fifteen minutes the answer is "too many attempts" until the window slides past.',
    how: '<code>HashMap&lt;ip, Vec&lt;Instant&gt;&gt;</code>, keyed by client IP — <mark>IPv6 clients count per /64</mark> network, and an IPv4-mapped IPv6 address folds to plain IPv4. <mark>One attempt is reserved under a single lock</mark> before the database lookup, refunded on a db error and on success — a success only undoes its own reservation, so failures against other names keep counting. Over the limit the answer is <mark>429</mark> with the login page. Ledger bounded to 10,000 keys — when full, the key with the fewest in-window stamps (then oldest last failure) is evicted, so a throttled key keeps its budget. A wrong answer also waits 1s before responding.',
    steps: [
      ['Reserve', 'Count this attempt under one lock; refuse if the key already has 10 in-window.'],
      ['Judge', 'Lookup miss → keep the stamp; db error or success → refund it.'],
      ['Delay', 'Failed logins sleep 1s before the 401.'],
    ],
    cond: [
      'Limiting keys on client IP — visitors sharing one NAT or carrier-grade address share the 10/15min budget. Acceptable?',
      { q: 'Should failures count the attempt before the lookup (atomically)?', r: 'Yes — reserve_attempt takes the slot under one lock, then refund/clear reconciles (review-1 finding 7, fixed).' },
      { q: 'Keyed on the full IP — an IPv6 client rotating host bits inside its /64 gets a fresh 10-attempt budget every request. Key IPv6 on the /64 prefix, or add a per-user-name throttle?', r: 'IPv6 clients now rate-limit per /64 (rate_limit_key; IPv4-mapped IPv6 folds to plain IPv4) — deliberately no per-user-name throttle, which would let anyone lock a user out (review-4 finding 4, fixed).' },
    ] },
  { id: 'U', code: 'U', name: 'Phrase book', short: 'USERS.DB', group: 'gate', gx: 10, gy: 0.5, w: 2, d: 2, h: 22, kind: 'store',
    one: 'The sqlite file of who may enter — salted phrase hashes only, never phrases.',
    what: 'The list of people allowed in. It stores each user name, a random salt, the Argon2id hash of their normalized phrase, and an admin flag — not the phrase itself. The gate asks it "does this name + phrase verify?" on every login.',
    how: '<code>users.db</code>: <code>UserStore</code> opens it read-write for <code>serve</code> (it also writes the <code>sessions</code> table there — which carries a <code>created</code> stamp and cascades on user delete) and <code>list-users</code>; <code>add-user</code> creates and writes it — it reads all of stdin and hashes every phrase <mark>before</mark> opening one immediate transaction, so a running serve is never stalled, <code>remove-user NAME</code> deletes the user and their sessions in one transaction. It runs in <mark>WAL mode</mark> — users.db-wal/-shm are part of the database — for Litestream backups, with a 5s busy timeout. A db that predates the schema (users without <code>salt</code>, sessions without <code>created</code>) is <mark>refused, not migrated</mark>; new files are created mode 0600 and an over-exposed one earns a warning. Phrases are <mark>normalized — whitespace stripped, lower-cased</mark> — then hashed with <mark>Argon2id (12 MiB, t=3, p=1, 32-byte out) under a per-user salt</mark>, serialized so at most one hash runs at a time. Names are 1–64 printable ASCII, UNIQUE, and matched case-insensitively; a lookup for an unknown name still hashes against a dummy salt so timing does not reveal it. Names containing "admin" set the flag; new phrases need ≥20 non-whitespace chars, a digit, and punctuation.',
    steps: [
      ['Normalize', 'Drop all whitespace, lower-case ("Open Sesame" == "opensesame").'],
      ['Hash', 'Argon2id of the normalized phrase under a per-user salt — that hex is what is stored.'],
      ['Lookup', 'SELECT row WHERE user_name = ?1, then verify the Argon2id hash in constant time.'],
      ['Manage', 'add-user inserts; remove-user deletes the row and its sessions; list-users prints names + flags.'],
    ],
    cond: [
      { q: 'There is no remove-user or phrase-rotation command — revoking someone means editing users.db by hand. Acceptable?', r: 'remove-user NAME deletes the row — and now their sessions too (2026-11). A running serve drops those sessions on its next 60s reload; phrase rotation is still add-then-remove.' },
      'The is_admin flag is stored and shown by list-users but serve never reads it for authorization — what should admins be able to do?',
      { q: 'Why not a per-user salt on the hash?', r: 'Done — the move to user name + phrase (commit c3f8099) gave a name to salt against: Argon2id with a random per-user salt replaced unsalted SHA-512 (ADR 0001 superseded).' },
      { q: 'add-user holds the WAL write lock across stdin reads and every Argon2 hash — a large batch stalls serve logins past the 5s busy timeout, and the deferred read-then-write can fail SQLITE_BUSY outright. Hash first, then insert in one immediate transaction?', r: 'Fixed — all lines are validated and hashed with no transaction open (concurrent writers proceed), then a single BEGIN IMMEDIATE inserts the batch with ON CONFLICT DO NOTHING (review-4 finding 2, fixed).' },
    ] },
  // ---- Through to the app ----
  { id: 'F', code: 'F', name: 'Forwarder', short: 'FORWARDER', group: 'relay', gx: 10.5, gy: 3, w: 2.5, d: 2, h: 44, kind: 'box',
    one: 'Rewrites the request, scrubs it, sends it upstream, brings the answer back.',
    what: 'Once you are known, this is the actual proxy. It points your request at the protected app, removes everything that could confuse or poison it — including the session cookie itself — and returns the app\'s answer.',
    how: '<code>hyper-util</code> client in <code>forward()</code> (<code>src/proxy.rs</code>), connecting over TCP or the configured unix socket (same 10s connect timeout). Swaps scheme+authority for <code>upstream</code>; strips <code>wsb_session</code>, hop-by-hop headers (a client <code>Connection</code> header can\'t remove Host or Content-Length), and <mark>all client-sent Forwarded/X-Forwarded-*/X-Real-IP</mark>; then stamps its own X-Forwarded-For (client IP), -Proto (https when cookies are Secure), -Host. 10s connect, 60s response-header deadline → 502/504, plus a 60s body-idle timeout (<code>IdleTimeoutBody</code>) that cuts off stalled streams. At most <mark>256 requests</mark> run upstream at once — extras get 503 — and the permit is held until the response body finishes — and a client that stops reading loses the connection (and the permit) after the 60s write-stall timeout in <code>src/server.rs</code>. Upstream Cache-Control is <mark>rewritten to private</mark> (public/s-maxage/proxy-revalidate and CDN override headers dropped) so a shared cache never serves a gated page; upstream Set-Cookie for wsb_session is dropped. Upgrade requests never reach here — the gate answers them 501.',
    steps: [
      ['Rewrite', 'Keep path+query; replace scheme and authority with upstream.'],
      ['Scrub', 'Session cookie out; hop-by-hop out; client forwarding headers out.'],
      ['Stamp', 'Write X-Forwarded-For/-Proto/-Host from verified values.'],
      ['Send', '10s connect timeout, 60s to response headers; else 502/504; cap 256 concurrent, else 503.'],
      ['Return', 'Strip hop-by-hop on the way back; drop any wsb_session Set-Cookie.'],
    ],
    cond: [
      { q: 'Trust client-sent X-Forwarded-* / X-Real-IP headers?', r: 'No — inbound forwarding headers are discarded and rebuilt from verified proxy metadata (review-1 finding 1, fixed).' },
      { q: 'Only connect (10s) and response-header (60s) deadlines exist — a response that stalls mid-body streams forever. Is that a real exposure?', r: 'Fixed — a 60s body-idle timeout (IdleTimeoutBody) ends stalled streams, and a 256-permit semaphore bounds concurrent upstream requests (commit f5285b2).' },
      { q: 'The body-idle timer only runs while downstream polls frames — a slow-reading client can hold an upstream permit indefinitely. Idle the connection, not just the upstream read?', r: 'Fixed — a custom accept loop (src/server.rs) wraps each connection in StallTimeoutIo: a write stalled 60s fails the connection, plus a 30s header-read timeout; a stalled client frees its permit (review-4 finding 5, fixed).' },
    ] },
  { id: 'UP', code: 'A', name: 'Protected app', short: 'UPSTREAM', group: 'relay', gx: 14, gy: 3, w: 3, d: 2.5, h: 18, kind: 'slab',
    one: 'The web server being sheltered — bound to loopback or a unix socket, reachable only through the gate.',
    what: 'Whatever app you are protecting: a blog, a dashboard, a thing that was never hardened. It sees only requests the gate already decided to allow, carrying honest forwarding headers.',
    how: 'Any http server on <code>upstream</code> (default <code>http://127.0.0.1:3000</code>, http with no path — or <code>unix:/absolute/path.sock</code>, where <mark>file permissions</mark> keep other local processes out; a loopback TCP port cannot). It receives the visitor\'s <code>Host</code>, <code>X-Forwarded-For/Proto/Host</code> and never the <code>wsb_session</code> cookie.',
    steps: [
      ['Serve', 'Handle the request as if the caller were already trusted.'],
      ['Respond', 'Answer streams back through the forwarder to the visitor.'],
    ],
    cond: [
      { q: 'Upstream is http-on-loopback only — will a real deployment ever need https upstream or a unix socket?', r: 'Unix socket: yes — upstream = "unix:/absolute/path.sock" (2026-11-23); socket permissions keep other local processes out. https upstream: not supported; use a sidecar (stunnel/socat) if the app is off-host.' },
    ] },
  // ---- Operating it ----
  { id: 'OP', code: 'O', name: 'Operator', short: 'OPERATOR', group: 'ops', gx: -1, gy: 1, w: 2, d: 2, h: 30, kind: 'screen',
    one: 'The person with shell access who owns the box.',
    what: 'You, on the machine itself: writing the config, adding users by piping lines, starting the server, and optionally tailing the monitor with netcat.',
    how: 'Everything is one binary: <code>web-safe-block write-config | add-user | remove-user | list-users | serve</code>, plus <code>-c path</code> for a non-default <code>config.toml</code>. Watching is <code>nc 127.0.0.1 8081</code>.',
    steps: [
      ['Configure', 'write-config emits a commented config.toml; refuses to overwrite.'],
      ['Populate', 'add-user reads "name pass phrase…" lines from stdin.'],
      ['Maintain', 'list-users shows names + admin flags; remove-user NAME deletes the user and their sessions.'],
      ['Run', 'serve binds the public port and the monitor port.'],
      ['Watch', 'nc to the monitor port for a live event stream.'],
    ],
    cond: [] },
  { id: 'C', code: 'C', name: 'CLI & config', short: 'CLI+CONFIG', group: 'ops', gx: 2, gy: 0.5, w: 2.5, d: 2, h: 30, kind: 'cards',
    one: 'Five commands and one strict config file.',
    what: 'The whole control surface. write-config lays down a commented config.toml; add-user, remove-user and list-users maintain the phrase book; serve runs everything. The config is all-or-nothing: every setting must be present and no unknown keys are allowed.',
    how: '<code>src/main.rs</code> + <code>src/settings.rs</code>. Seven settings, <mark>all required, unknown keys denied</mark>: users_db, listen_addr (a literal IP:port), upstream, session_ttl_secs (1s–10y), cookie_secure, monitor_addr (loopback only), monitor_queue_len (≥1). Relative users_db resolves against the config file\'s directory.',
    steps: [
      ['write-config', 'Emit defaults with comments; refuse to overwrite an existing file.'],
      ['add-user', 'Per stdin line: first word = name, rest = phrase; weak or duplicate lines skipped; any skip fails the exit code.'],
      ['remove-user NAME', 'Deletes the row and its sessions in one transaction; errors if the name is not found.'],
      ['list-users', 'Print user_name + is_admin, sorted by name.'],
      ['serve', 'Load config + users.db (must exist, be current schema, and be non-empty), bind both ports.'],
    ],
    cond: [
      'Single config file, no environment overrides or flags — fine for a small self-hosted tool, or will it annoy deployment?',
    ] },
  { id: 'EQ', code: 'Q', name: 'Event queue', short: 'EVENT QUEUE', group: 'ops', gx: 9.5, gy: 9.5, w: 2, d: 2, h: 18, kind: 'store',
    one: 'A bounded ring of "what just happened" — handlers push without blocking.',
    what: 'Every request — page shown, login won or lost, request proxied — becomes one small record. The queue holds the most recent ones until a monitor comes to read them; when it fills, the oldest are overwritten.',
    how: '<code>VecDeque&lt;Event&gt;</code> + <code>Condvar</code> in <code>src/monitor.rs</code>. Each event: <code>{seq, time, kind, status, ip, method, path, user?, user_agent?, truncated}</code> — the middleware caps fields (method 32 B, path+query 1 KiB, UA 512 B) on char boundaries and sets <code>truncated</code>. The queue is bounded by count <mark>and ~4 MiB of retained bytes</mark>; overwrites of unsent events during a live connection are counted and later reported as <mark>{"kind":"dropped"}</mark>; events leave only after they are written to the client, at most 100 per write. Alongside the queue, <mark>per-UTC-day security counters</mark> (last 7 days, memory only) tally logins won/lost, unauthenticated non-root probes, rate-limited, login_busy, forbidden, reserved, other, login/logout errors — and events evicted while nobody is watching (<code>dropped_unseen</code>).',
    steps: [
      ['Push', 'Stamp seq + UTC time; count the kind in today\'s counters; if full, evict the oldest (dropped notice if a monitor is attached, dropped_unseen if not).'],
      ['Pending', 'Wait on the condvar; hand the batch out but keep it queued.'],
      ['Consume', 'mark_consumed only after the bytes hit the socket.'],
    ],
    cond: [
      { q: 'Events overwritten while no monitor is connected vanish silently — should that count be surfaced to the next monitor?', r: 'Yes — every eviction with no monitor attached is counted as dropped_unseen in in-memory per-UTC-day security counters (logins won/lost, unauthenticated non-root probes, rate-limited, login_busy, forbidden, reserved, other, login/logout errors); a new monitor first receives the last 7 days as daily_counts lines, and a connected monitor gets each day\'s final line at 00:00 UTC (2026-11-23).' },
    ] },
  { id: 'MO', code: 'M', name: 'Monitor port', short: 'MONITOR', group: 'ops', gx: 13, gy: 10, w: 2, d: 2, h: 26, kind: 'screen',
    one: 'One loopback TCP client at a time gets the live JSON-lines feed.',
    what: 'A peephole for the operator: connect with netcat and watch one JSON line per request scroll by. Only one watcher at a time; a second connection is told it is busy and hung up.',
    how: 'Plain <code>TcpListener</code> on <code>monitor_addr</code> (<mark>loopback enforced in config</mark>) on its own OS thread; each client is served on a further thread, writes timing out at 30s and client input discarded. Second clients get <code>{"error":"another monitor is already connected"}</code> — <mark>never the counters</mark>. On connect the client first receives one <code>daily_counts</code> line per retained UTC day (up to 7, oldest first); while it stays connected, each day that ends at 00:00 UTC is pushed with <code>"final":true</code>. Once a client half-closes, a <code>heartbeat</code> line every 10s probes for gone-aways — a reset frees the slot.',
    steps: [
      ['Accept', 'One slot: try_connect or send the busy error and close.'],
      ['Report', 'Write the retained days\' daily_counts lines first.'],
      ['Stream', 'Wait for pending events; write JSON lines + dropped notices; a finished day\'s final counts go out at 00:00 UTC.'],
      ['Probe', 'After EOF on reads, heartbeat every 10s; a reset ends the connection.'],
    ],
    cond: [
      'The monitor trusts loopback alone — any local process can watch the request stream. Is that fine, or should it take a token?',
    ] },
  // ---- Not switched on ----
  { id: 'WS', code: 'W', name: 'WebSocket relay', short: 'WEBSOCKETS', group: 'off', ghost: true, gx: 17, gy: 5.5, w: 2, d: 2, h: 34, kind: 'box',
    one: 'Designed for, not built: live upgrade connections to the app.',
    what: 'Apps that want WebSockets cannot work through the gate today — an authenticated request carrying an Upgrade header is answered 501 and never reaches the app.',
    how: '<code>proxy_or_login</code> returns <mark>501 Not Implemented</mark>, kind <code>upgrade</code>, for any authenticated request with an <code>Upgrade</code> header; the hop-by-hop scrub still removes <code>connection</code>/<code>upgrade</code> from ordinary traffic. A real relay needs an upgrade path in <code>forward()</code> and a decision about streaming bodies.',
    steps: [
      ['Upgrade', 'Detect a genuine upgrade request after the session check.'],
      ['Relay', 'Pipe the connection to upstream instead of request/response.'],
    ],
    cond: [
      { q: 'Until then: should v1 answer upgrade attempts with a clear 501 instead of forwarding a stripped request that fails mysteriously?', r: 'Yes — the gate answers 501 (kind upgrade) to authenticated Upgrade requests and forwards nothing (2026-11-17).' },
    ] },
];

// Flows for the final "whole system" chapter. Hop = [from, to, label, payload, bend('xy'|'yx')]
export const FLOWS = [
  { id: 'login', name: 'A login', hops: [
    ['BR', 'CF', 'POST /__wsb/login', { form: { user: 'chris', phrase: 'correct horse battery staple 42!', next: '/' } }, 'xy'],
    ['CF', 'G', 'name + phrase + client IP', { headers: { 'cf-connecting-ip': '203.0.113.9' } }, 'xy'],
    ['G', 'R', 'reserve attempt', { key: '203.0.113.9', in_window: 0 }, 'xy'],
    ['G', 'U', 'SELECT by user_name + Argon2id verify', { user_name: 'chris' }, 'yx'],
    ['U', 'G', 'user row', { user_name: 'chris', is_admin: false }, 'xy'],
    ['G', 'S', 'insert session (users.db first, then map)', { token: '9f3a…(32B hex)', stored: 'sha256(9f3a…)', user: 'chris', created: '<unix µs>', ttl_secs: 15552000 }, 'xy'],
    ['G', 'CF', '303 + Set-Cookie', { set_cookie: 'wsb_session=9f3a…; HttpOnly; SameSite=Lax; Path=/; Max-Age=15552000; Secure' }, 'yx'],
    ['CF', 'BR', 'redirect', { status: 303, location: '/' }, 'yx'],
  ] },
  { id: 'proxy', name: 'A proxied request', hops: [
    ['BR', 'CF', 'GET /app + cookie', { cookie: 'wsb_session=9f3a…' }, 'xy'],
    ['CF', 'G', 'http + client IP', { headers: { 'cf-connecting-ip': '203.0.113.9' } }, 'xy'],
    ['G', 'S', 'token valid?', { token: '9f3a…' }, 'xy'],
    ['S', 'G', 'user', { user: 'chris', ok: true }, 'yx'],
    ['G', 'F', 'forward', { note: 'wsb_session + hop-by-hop stripped' }, 'xy'],
    ['F', 'UP', 'GET /app', { headers: { 'x-forwarded-for': '203.0.113.9', 'x-forwarded-proto': 'https' } }, 'xy'],
    ['UP', 'F', 'response', { status: 200 }, 'yx'],
    ['F', 'G', 'response', { status: 200, note: 'Cache-Control → private; wsb_session Set-Cookie dropped' }, 'yx'],
    ['G', 'BR', 'response via tunnel', { kind: 'proxied', status: 200 }, 'yx'],
  ] },
  { id: 'fail', name: 'A failed login', hops: [
    ['BR', 'G', 'POST wrong phrase', { form: { user: 'chris', phrase: 'let me in' } }, 'xy'],
    ['G', 'R', 'reserve attempt', { key: '203.0.113.9', in_window: 'n/10' }, 'xy'],
    ['R', 'G', 'under limit', { allowed: true }, 'yx'],
    ['G', 'U', 'SELECT by user_name + Argon2id verify', { user_name: 'chris' }, 'yx'],
    ['U', 'G', 'miss', { found: false }, 'xy'],
    ['G', 'BR', '401 after 1s', { page: 'Incorrect user name or phrase.', kind: 'login_failed' }, 'yx'],
  ] },
  { id: 'logout', name: 'Logging out', hops: [
    ['BR', 'G', 'POST /__wsb/logout', { headers: { 'sec-fetch-site': 'same-origin' } }, 'xy'],
    ['G', 'S', 'remove every offered token', { token: '9f3a…' }, 'xy'],
    ['S', 'G', 'gone (users.db, then map)', { user: 'chris' }, 'yx'],
    ['G', 'BR', '303 + cookie cleared', { set_cookie: 'wsb_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0; Secure' }, 'yx'],
  ] },
  { id: 'tail', name: 'Tailing the monitor', hops: [
    ['OP', 'MO', 'nc 127.0.0.1 8081', { connect: 'only monitor slot' }, 'xy'],
    ['BR', 'G', 'any request', { method: 'POST', path: '/__wsb/login' }, 'xy'],
    ['G', 'EQ', 'push event', { kind: 'login_succeeded', status: 303, ip: '203.0.113.9', user: 'chris' }, 'xy'],
    ['EQ', 'MO', 'JSON line', { seq: 4, time: '2026-11-17T18:40:01Z' }, 'xy'],
    ['MO', 'EQ', 'mark consumed', { up_to: 4 }, 'yx'],
  ] },
];

// Chapters = progressive disclosure. ≤3 structures each; one small flow on revealed ones.
export const CH = [
  { id: 'door', title: 'The front door', reveal: ['BR', 'CF', 'G'],
    lede: `Every request arrives at one public port; everything else hides behind it.`,
    story: `<p>web-safe-block sits between the internet and a web server you don't fully trust. The <mark>tunnel terminates TLS</mark> and stamps the real client IP; the gate answers every request itself until a phrase is proved.</p>`,
    flow: [
      ['BR', 'CF', 'GET /', { method: 'GET', path: '/' }],
      ['CF', 'G', 'http + CF-Connecting-IP', { headers: { 'cf-connecting-ip': '203.0.113.9' } }],
      ['G', 'CF', '401 login page', { status: 401, kind: 'login_page' }],
      ['CF', 'BR', 'https response', { status: 401, body: 'phrase form' }],
    ] },
  { id: 'phrase', title: 'The phrase book', reveal: ['U'],
    lede: `A name and a secret per person: the phrase proves you, the name says who.`,
    story: `<p>The login form asks for a user name and a pass phrase. The phrase is <mark>normalized — whitespace stripped, lower-cased</mark> — then Argon2id'd under the user's own salt and compared in constant time; the database never stores the phrase itself. An unknown name still costs one hash against a dummy salt.</p>`,
    flow: [
      ['BR', 'G', 'POST name + phrase (via tunnel)', { form: { user: 'chris', phrase: 'correct horse … 42!' } }],
      ['G', 'U', 'SELECT by user_name + Argon2id verify', { user_name: 'chris' }],
      ['U', 'G', 'user row', { user_name: 'chris', is_admin: false }],
      ['G', 'BR', '303 + Set-Cookie', { set_cookie: 'wsb_session=…' }],
    ] },
  { id: 'session', title: 'The session table', reveal: ['S'],
    lede: `A correct phrase mints a token; the cookie is your ticket from then on.`,
    story: `<p>The gate keeps a <mark>small table — hashed token → user + expiry + created stamp</mark> — capped at 3 sessions per user and 10,000 total, earliest-created evicted. Every login writes through to the <code>sessions</code> table in users.db (SHA-256 of the token only) <mark>before</mark> the in-memory map changes, and serve reloads the table at startup and every minute — restart no longer logs anyone out.</p>`,
    flow: [
      ['BR', 'G', 'POST name + phrase', { form: { user: 'chris', phrase: '…' } }],
      ['G', 'S', 'insert hash', { cookie_string: 'sha256(9f3a…)', user: 'chris', created: '<unix µs>', ttl_secs: 15552000 }],
      ['G', 'BR', '303 + Set-Cookie', { set_cookie: 'wsb_session=9f3a…' }],
      ['BR', 'G', 'next request + cookie', { cookie: 'wsb_session=9f3a…' }],
      ['G', 'S', 'lookup', { token: '9f3a…' }],
      ['S', 'G', 'user + expiry', { user: 'chris', ok: true }],
    ] },
  { id: 'through', title: 'Through to the app', reveal: ['F', 'UP'],
    lede: `Once you're known, the gate rewrites and forwards — the app never sees the login dance.`,
    story: `<p>The forwarder <mark>rebuilds the request</mark>: the session cookie and hop-by-hop headers come out, client-sent forwarding headers are discarded, honest ones are stamped. The answer's Cache-Control is <mark>rewritten to private</mark> so a shared cache can't serve it to someone else. The app sits on loopback and trusts what arrives.</p>`,
    flow: [
      ['BR', 'G', 'GET /app + cookie', { cookie: 'wsb_session=9f3a…' }],
      ['G', 'S', 'check', { token: '9f3a…' }],
      ['S', 'G', 'ok: chris', { user: 'chris' }],
      ['G', 'F', 'forward', { note: 'scrubbed + stamped' }],
      ['F', 'UP', 'GET /app', { headers: { 'x-forwarded-for': '203.0.113.9' } }],
      ['UP', 'F', '200', { status: 200 }],
      ['F', 'G', 'response', { status: 200 }],
      ['G', 'BR', 'response via tunnel', { status: 200 }],
    ] },
  { id: 'throttle', title: 'Slowing down guessing', reveal: ['R'],
    lede: `Wrong phrase? Ten tries per quarter-hour per client — and each miss costs a second.`,
    story: `<p>Failures are counted per <mark>client IP</mark> (the tunnel's header when the connection comes from the tunnel on loopback, otherwise the peer address) in a bounded ledger. The attempt is reserved before the lookup, so concurrency can't slip extra tries through.</p>`,
    flow: [
      ['BR', 'G', 'POST wrong phrase', { form: { user: 'chris', phrase: 'let me in' } }],
      ['G', 'R', 'reserve attempt', { key: '203.0.113.9' }],
      ['R', 'G', 'under limit', { in_window: 'n/10' }],
      ['G', 'U', 'SELECT by user_name + Argon2id verify', { user_name: 'chris' }],
      ['U', 'G', 'miss', { found: false }],
      ['G', 'BR', '401 after 1s', { kind: 'login_failed' }],
    ] },
  { id: 'watch', title: 'Watching the door', reveal: ['EQ', 'MO'],
    lede: `Every request leaves a one-line trace on a loopback port.`,
    story: `<p>Handlers <mark>push events without blocking</mark> into a queue bounded by count and ~4 MiB; a separate thread serves them as JSON lines to one connected monitor, marking them consumed only after the bytes are written.</p>`,
    flow: [
      ['BR', 'G', 'any request', { method: 'POST', path: '/__wsb/login' }],
      ['G', 'EQ', 'push event', { kind: 'login_succeeded', ip: '203.0.113.9' }],
      ['EQ', 'MO', 'JSON line', { seq: 4 }],
      ['MO', 'EQ', 'mark consumed', { up_to: 4 }],
    ] },
  { id: 'operate', title: 'Running it', reveal: ['OP', 'C'],
    lede: `Five commands: write-config, add-user, remove-user, list-users, serve.`,
    story: `<p>The operator <mark>manages users by piping lines</mark> — "name pass phrase words…" — into add-user; remove-user deletes the user and their sessions, and list-users shows who is in. serve refuses to start with no users at all.</p>`,
    flow: [
      ['OP', 'C', 'add-user <<EOF', { line: 'chris correct horse … 42!' }],
      ['C', 'U', 'INSERT hash', { user_name: 'chris', salt: '<16B hex>', pass_phrase: '<argon2id hex>', is_admin: false }],
      ['OP', 'C', 'remove-user carol', { arg: 'carol' }],
      ['C', 'U', 'DELETE row', { changes: 1 }],
      ['OP', 'MO', 'nc 127.0.0.1:8081', { connect: 'monitor stream' }],
    ] },
  { id: 'later', title: 'Not switched on', reveal: ['WS'],
    lede: `Designed for, not built.`,
    story: `<p>One sketch sits on the map as a <mark>dashed ghost</mark>: a WebSocket relay — today the gate answers upgrade attempts 501. (Saved sessions were built: see the session table and ADR 0006.)</p>`,
    flow: [
      ['BR', 'G', 'GET /ws + Upgrade', { headers: { upgrade: 'websocket', cookie: 'wsb_session=9f3a…' } }],
      ['G', 'S', 'session check', { token: '9f3a…' }],
      ['S', 'G', 'ok: chris', { user: 'chris' }],
      ['G', 'BR', '501 Not Implemented', { status: 501, kind: 'upgrade' }],
    ] },
  { id: 'all', title: 'The whole system', reveal: [],
    lede: `Everything at once, for free exploration.`,
    story: `<p>Choose which flow runs (bottom left). Hover anything; click to pin; → goes inside. The <mark>Open questions</mark> tab lists every question by ID.</p>`,
    flow: null },
];

// "How it's built" tab with nothing selected (HTML).
export const HOW_HTML = `<div class="eyebrow">web-safe-block · v0.1</div><h1 class="t">How it's built</h1><div class="sub">a small Rust gate in front of a softer app</div>
<h3 class="sec">Filesystem</h3><pre>web-safe-block/
  src/
    main.rs       write-config · add-user · remove-user · list-users · serve
    lib.rs        crate root: module wiring + re-exports
    app.rs        router, event middleware, purger
    auth.rs       login/logout handlers
    proxy.rs      session check, 501 on upgrade, forwarder
    sessions.rs   session table ops + token minting
    rate_limit.rs per-IP failure ledger ops
    state.rs      Config · Limits · AppState
    util.rs       cookie/header/HTML helpers
    users.rs      users.db schema (users + sessions) + phrase policy
    monitor.rs    EventQueue + monitor thread
    settings.rs   strict config.toml
  tests/proxy.rs  end-to-end against a real upstream
  Notes/atlas/    this atlas</pre>
<h3 class="sec">Runtime shape</h3><pre>one process
  tokio runtime ─ public listener (axum + hyper)
                ├ purger task (session reload + failures, 60s)
                └ hash_slot: one Argon2 (~12 MiB) at a time, on the blocking pool
  OS thread     ─ monitor listener + per-client threads
  hyper client  ─ upstream, 10s connect / 60s headers / 60s body-idle · ≤256 live</pre>
<h3 class="sec">Ports</h3><pre>listen_addr   127.0.0.1:8080  public (via tunnel)
monitor_addr  127.0.0.1:8081  loopback only
upstream      127.0.0.1:3000  the protected app</pre>`;
