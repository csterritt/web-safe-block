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
    { k: 'Source', v: '~3,300 LOC' },
    { k: 'Seats', v: '1 public port · 1 monitor' },
  ],
  intro: `_**This file is the living source of truth for the design.** The interactive atlas (\`atlas.html\`) is built from the same data; edit this file and rebuild, never the outputs._`,
  onePara: `web-safe-block is a small Rust program that parks itself in front of a web server you don't fully trust. The internet reaches only its public port (through a TLS terminator such as Cloudflare Tunnel); it answers every request with a one-field phrase form until someone submits a phrase that hashes to a row in \`users.db\` — then it mints a session cookie (persisted as a hash in \`users.db\`) and becomes a plain reverse proxy to the protected app on loopback. A second, loopback-only port streams one JSON line per request to a single watcher. v1 answers protocol upgrades with a 501 instead of relaying them, and sessions survive a restart.`,
  costModel: [
    'Bounds, not dollars — this is one process on one box. Every in-memory structure is capped:',
    '',
    '| Resource | Bound | Where |',
    '|---|---|---|',
    '| Sessions | 3 per user, 10,000 total, TTL from `session_ttl_secs` (default 180d); persisted as hashes in users.db | `src/state.rs` `Limits` + `src/sessions.rs` |',
    '| Failed-login keys | 10,000 IPs, ≤10 stamps each, 15-minute window | `src/rate_limit.rs` `reserve_attempt` |',
    '| Event queue | `monitor_queue_len` (default 1,000), oldest overwritten | `src/monitor.rs` `EventQueue` |',
    '| Upstream waits | 10s to connect, 60s for response headers | `src/proxy.rs` `forward` |',
    '| users.db | one row per user; phrase kept only as SHA-512 hex | `src/users.rs` |',
  ],
  deepDive: '',
  platformGives: 'axum 0.8 (router, form extractor, middleware), hyper + hyper-util (HTTP/1 server and client with timeouts), rusqlite with bundled sqlite, tokio, rand.',
  weOwn: 'the gate: phrase-only login, persisted sessions (write-through to users.db behind an in-memory map), the per-IP throttle, header scrub + forwarding-header rebuild, the bounded event queue and monitor thread, strict config loading, and the users.db schema plus pass-phrase strength policy.',
  filesystem: `web-safe-block/
  src/
    main.rs       commands: write-config · add-user · remove-user · list-users · serve
    lib.rs        crate root: module wiring + re-exports
    app.rs        router, record_event middleware, 60s purger
    auth.rs       login/logout handlers
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
  { axis: 'Credential', decision: 'The pass phrase is the whole credential — it identifies the user; no username on the wire', adr: '[0001](./adr/0001-phrase-is-the-credential.md)' },
  { axis: 'Phrase storage', decision: 'Unsalted SHA-512 of the normalized phrase (per-user salt is impossible when lookup is by phrase alone); ≥20 chars + digit + punctuation enforced at add time', adr: '[0001](./adr/0001-phrase-is-the-credential.md)' },
  { axis: 'Sessions', decision: 'Write-through to a sessions table in users.db (SHA-256 of the token only), in-memory map as cache, 3/user and 10k total; reload on the 60s purge tick picks up remove-user', adr: '[0006](./adr/0006-sessions-persisted.md)' },
  { axis: 'Client IP', decision: 'CF-Connecting-IP is trusted when present — listen_addr must only ever face the tunnel', adr: '[0003](./adr/0003-trusted-edge-header.md)' },
  { axis: 'Config', decision: 'Every setting required; unknown keys rejected; relative users_db resolves against the config file', adr: '[0004](./adr/0004-strict-config.md)' },
  { axis: 'Monitor', decision: 'One loopback JSON-lines client at a time; bounded queue overwrites the oldest events', adr: '[0005](./adr/0005-one-monitor.md)' },
  { axis: 'Upstream', decision: 'http:// only, no path — the protected app stays on loopback', adr: '—' },
  { axis: 'Reserved paths', decision: '/__wsb/* is never forwarded; cross-site POSTs to it are rejected', adr: '—' },
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
    how: 'All it ever needs to send is a <code>POST /__wsb/login</code> with a <code>phrase</code> field, then carry the <code>wsb_session</code> cookie. No JavaScript on our pages; plain forms only.',
    steps: [
      ['Ask', 'GET any path — gets the phrase form back until logged in.'],
      ['Submit', 'POST the phrase to /__wsb/login.'],
      ['Carry', 'Browser sends wsb_session automatically on later requests.'],
    ],
    cond: [] },
  { id: 'CF', code: 'T', name: 'TLS terminator', short: 'TUNNEL', group: 'edge', gx: 3.5, gy: 4.5, w: 2, d: 2, h: 40, kind: 'box',
    one: 'Cloudflare Tunnel (or any TLS front) — the only road in.',
    what: 'TLS is not web-safe-block\'s job. A tunnel or reverse proxy holds the certificate and forwards plain http to the public port, stamping the real client IP in a header.',
    how: 'Forwards to <code>listen_addr</code> (default <code>127.0.0.1:8080</code>) and sets <code>CF-Connecting-IP</code>, which the gate reads <mark>and trusts</mark> for client IP, rate limiting, and event logs.',
    steps: [
      ['Terminate', 'TLS ends here; onward hop is plain http.'],
      ['Stamp', 'Adds CF-Connecting-IP with the real client address.'],
      ['Forward', 'Sends the request to listen_addr.'],
    ],
    cond: [
      'If listen_addr is ever exposed directly, CF-Connecting-IP becomes attacker-controlled — should the gate only honor it from the tunnel\'s peer address?',
    ] },
  // ---- The gate ----
  { id: 'G', code: 'G', name: 'The gate', short: 'GATE', group: 'gate', gx: 7, gy: 3, w: 3, d: 2.5, h: 56, kind: 'gate',
    one: 'The public listener: login page, session check, reserved endpoints, upgrade refusal, then forward-or-refuse.',
    what: 'One port answers every request the internet sends. Without a valid session you get the phrase form and nothing else; with one, your request is handed to the forwarder — unless it asks for a protocol upgrade, which earns a 501. A tiny /__wsb/ namespace carries login, logout, and nothing else.',
    how: '<code>axum</code> router in <code>src/app.rs</code>: <code>POST /__wsb/login</code> and <code>GET|POST /__wsb/logout</code> live in <code>src/auth.rs</code>, fallback <code>proxy_or_login</code> in <code>src/proxy.rs</code>. Any other <code>/__wsb/*</code> path is a 404 <mark>reserved</mark>. Cross-site POSTs are refused via <code>Sec-Fetch-Site</code>, then <code>Origin</code>. Authenticated requests with an <code>Upgrade</code> header get <mark>501</mark>, kind <code>upgrade</code>. Every request exits through <code>record_event</code> middleware.',
    steps: [
      ['Route', '/__wsb/ endpoints handled here; unknown ones are 404 reserved.'],
      ['Authenticate', 'Parse cookies → wsb_session → sessions table → user.'],
      ['Decide', 'Login page (401), the login/logout handlers, 501 for upgrade attempts, or hand to the forwarder.'],
      ['Report', 'Attach an Outcome; middleware pushes one event per request.'],
    ],
    cond: [
      { q: 'Should GET /__wsb/logout end the session?', r: 'No — GET shows a confirm form; only POST destroys the session, and cross-site POSTs are rejected (review-1 finding 5, fixed).' },
      'Cross-site POST checks fall back to Origin only when Sec-Fetch-Site is absent; a client sending neither is allowed through. Keep that posture?',
    ] },
  { id: 'S', code: 'S', name: 'Session table', short: 'SESSIONS', group: 'gate', gx: 6, gy: 7, w: 2, d: 2, h: 22, kind: 'store',
    one: 'The gate\'s memory: hashed token → user + expiry, cached in RAM and persisted in users.db.',
    what: 'A small table that answers "who is this cookie?" Login puts a random token in; every later request trades the cookie for a user name. A restart reloads the live sessions — nobody is logged out.',
    how: '<code>HashMap&lt;String, Session&gt;</code> behind a <code>Mutex</code>, written through to the <code>sessions</code> table in <code>users.db</code> on every login. Tokens are <mark>32 random bytes, hex</mark>; only their <mark>SHA-256 hash</mark> is stored — the raw token exists solely in the Set-Cookie header. Caps: 3 sessions per user and 10,000 total — the earliest-expiring entry is evicted from map and table together. The 60s purge tick re-reads the table, dropping expired rows and picking up sessions deleted by <code>remove-user</code>.',
    steps: [
      ['Insert', 'new_token() → hash → Session{user, expires}; evict oldest to stay inside caps; write hash + expiry to users.db.'],
      ['Check', 'Cookie → SHA-256 → lookup; valid + unexpired → user name.'],
      ['Reload', 'Every 60s: delete expired rows, clear the map, refill from the table — also sees remove-user deletions.'],
    ],
    cond: [
      { q: 'Sessions die on restart — acceptable while this guards one box, or should they persist?', r: 'Persisted — write-through to the sessions table in users.db, hashes only, reload at startup and on the purge tick (ADR 0006, 2026-11).' },
      'A running serve notices remove-user deletions only on the 60s reload — is up to a minute of grace acceptable?',
    ] },
  { id: 'R', code: 'R', name: 'Failure ledger', short: 'THROTTLE', group: 'gate', gx: 8.5, gy: 7, w: 2, d: 2, h: 22, kind: 'store',
    one: 'Ten failed phrases per quarter-hour per client — and each miss costs a second.',
    what: 'The brute-force brake. Every wrong phrase is written down against the client\'s IP; after ten in fifteen minutes the answer is "too many attempts" until the window slides past.',
    how: '<code>HashMap&lt;ip, Vec&lt;Instant&gt;&gt;</code>. <mark>One attempt is reserved under a single lock</mark> before the database lookup, refunded on a db error, cleared on success — so concurrent guesses can\'t slip past the limit. Ledger bounded to 10,000 keys; a wrong answer also waits 1s before responding.',
    steps: [
      ['Reserve', 'Count this attempt under one lock; refuse if the key already has 10 in-window.'],
      ['Judge', 'Lookup miss → keep the stamp; db error → refund it; success → clear the key.'],
      ['Delay', 'Failed logins sleep 1s before the 401.'],
    ],
    cond: [
      'Limiting keys on client IP — visitors sharing one NAT or carrier-grade address share the 10/15min budget. Acceptable?',
      { q: 'Should failures count the attempt before the lookup (atomically)?', r: 'Yes — reserve_attempt takes the slot under one lock, then refund/clear reconciles (review-1 finding 7, fixed).' },
    ] },
  { id: 'U', code: 'U', name: 'Phrase book', short: 'USERS.DB', group: 'gate', gx: 10, gy: 0.5, w: 2, d: 2, h: 22, kind: 'store',
    one: 'The sqlite file of who may enter — phrase hashes only, never phrases.',
    what: 'The list of people allowed in. It stores each user name, the SHA-512 of their normalized phrase, and an admin flag — not the phrase itself. The gate asks it "is there anyone with this phrase?" on every login.',
    how: '<code>users.db</code>: <code>UserStore</code> opens it read-write for <code>serve</code> (it also writes the <code>sessions</code> table there) and <code>list-users</code>; <code>add-user</code> creates and writes it, <code>remove-user NAME</code> deletes the user and their sessions in one transaction. Phrases are <mark>normalized — whitespace stripped, lower-cased</mark> — then hex SHA-512\'d. Name and phrase hash are both UNIQUE. Names containing "admin" set the flag; new phrases need ≥20 chars, a digit, and punctuation.',
    steps: [
      ['Normalize', 'Drop all whitespace, lower-case ("Open Sesame" == "opensesame").'],
      ['Hash', 'SHA-512 hex — that string is what is stored and searched.'],
      ['Lookup', 'SELECT user_name, is_admin WHERE pass_phrase = hash.'],
      ['Manage', 'add-user inserts; remove-user deletes by name; list-users prints names + flags.'],
    ],
    cond: [
      { q: 'There is no remove-user or phrase-rotation command — revoking someone means editing users.db by hand. Acceptable?', r: 'remove-user NAME deletes the row — and now their sessions too (2026-11). A running serve drops those sessions on its next 60s reload; phrase rotation is still add-then-remove.' },
      'The is_admin flag is stored and shown by list-users but serve never reads it for authorization — what should admins be able to do?',
      { q: 'Why not a per-user salt on the hash?', r: 'Lookup is by phrase alone — the phrase identifies the user, so there is no name to salt against before hashing. Strength is enforced at add time instead (README security notes).' },
    ] },
  // ---- Through to the app ----
  { id: 'F', code: 'F', name: 'Forwarder', short: 'FORWARDER', group: 'relay', gx: 10.5, gy: 3, w: 2.5, d: 2, h: 44, kind: 'box',
    one: 'Rewrites the request, scrubs it, sends it upstream, brings the answer back.',
    what: 'Once you are known, this is the actual proxy. It points your request at the protected app, removes everything that could confuse or poison it — including the session cookie itself — and returns the app\'s answer.',
    how: '<code>hyper-util</code> client in <code>forward()</code> (<code>src/proxy.rs</code>). Swaps scheme+authority for <code>upstream</code>; strips <code>wsb_session</code>, hop-by-hop headers, and <mark>all client-sent Forwarded/X-Forwarded-*/X-Real-IP</mark>; then stamps its own X-Forwarded-For (client IP), -Proto, -Host. 10s connect, 60s response-header deadline → 502/504. Upstream Set-Cookie for wsb_session is dropped. Upgrade requests never reach here — the gate answers them 501.',
    steps: [
      ['Rewrite', 'Keep path+query; replace scheme and authority with upstream.'],
      ['Scrub', 'Session cookie out; hop-by-hop out; client forwarding headers out.'],
      ['Stamp', 'Write X-Forwarded-For/-Proto/-Host from verified values.'],
      ['Send', '10s connect timeout, 60s to response headers; else 502/504.'],
      ['Return', 'Strip hop-by-hop on the way back; drop any wsb_session Set-Cookie.'],
    ],
    cond: [
      { q: 'Trust client-sent X-Forwarded-* / X-Real-IP headers?', r: 'No — inbound forwarding headers are discarded and rebuilt from verified proxy metadata (review-1 finding 1, fixed).' },
      'Only connect (10s) and response-header (60s) deadlines exist — a response that stalls mid-body streams forever. Is that a real exposure?',
    ] },
  { id: 'UP', code: 'A', name: 'Protected app', short: 'UPSTREAM', group: 'relay', gx: 14, gy: 3, w: 3, d: 2.5, h: 18, kind: 'slab',
    one: 'The web server being sheltered — bound to loopback, reachable only through the gate.',
    what: 'Whatever app you are protecting: a blog, a dashboard, a thing that was never hardened. It sees only requests the gate already decided to allow, carrying honest forwarding headers.',
    how: 'Any http server on <code>upstream</code> (default <code>http://127.0.0.1:3000</code>, <mark>http only, no path</mark>). It receives <code>X-Forwarded-For/Proto/Host</code> and never the <code>wsb_session</code> cookie.',
    steps: [
      ['Serve', 'Handle the request as if the caller were already trusted.'],
      ['Respond', 'Answer streams back through the forwarder to the visitor.'],
    ],
    cond: [
      'Upstream is http-on-loopback only — will a real deployment ever need https upstream or a unix socket?',
    ] },
  // ---- Operating it ----
  { id: 'OP', code: 'O', name: 'Operator', short: 'OPERATOR', group: 'ops', gx: -1, gy: 1, w: 2, d: 2, h: 30, kind: 'screen',
    one: 'The person with shell access who owns the box.',
    what: 'You, on the machine itself: writing the config, adding users by piping lines, starting the server, and optionally tailing the monitor with netcat.',
    how: 'Everything is one binary: <code>web-safe-block write-config | add-user | remove-user | list-users | serve</code>, plus <code>-c path</code> for a non-default <code>config.toml</code>. Watching is <code>nc 127.0.0.1 8081</code>.',
    steps: [
      ['Configure', 'write-config emits a commented config.toml; refuses to overwrite.'],
      ['Populate', 'add-user reads "name pass phrase…" lines from stdin.'],
      ['Maintain', 'list-users shows names + admin flags; remove-user NAME deletes a row.'],
      ['Run', 'serve binds the public port and the monitor port.'],
      ['Watch', 'nc to the monitor port for a live event stream.'],
    ],
    cond: [] },
  { id: 'C', code: 'C', name: 'CLI & config', short: 'CLI+CONFIG', group: 'ops', gx: 2, gy: 0.5, w: 2.5, d: 2, h: 30, kind: 'cards',
    one: 'Five commands and one strict config file.',
    what: 'The whole control surface. write-config lays down a commented config.toml; add-user, remove-user and list-users maintain the phrase book; serve runs everything. The config is all-or-nothing: every setting must be present and no unknown keys are allowed.',
    how: '<code>src/main.rs</code> + <code>src/settings.rs</code>. Seven settings, <mark>all required, unknown keys denied</mark>: users_db, listen_addr, upstream, session_ttl_secs, cookie_secure, monitor_addr (loopback only), monitor_queue_len. Relative users_db resolves against the config file\'s directory.',
    steps: [
      ['write-config', 'Emit defaults with comments; refuse to overwrite an existing file.'],
      ['add-user', 'Per stdin line: first word = name, rest = phrase; weak or duplicate lines skipped.'],
      ['remove-user NAME', 'Deletes the row; errors if the name is not found.'],
      ['list-users', 'Print user_name + is_admin, sorted by name.'],
      ['serve', 'Load config + users.db (must exist and be non-empty), bind both ports.'],
    ],
    cond: [
      'Single config file, no environment overrides or flags — fine for a small self-hosted tool, or will it annoy deployment?',
    ] },
  { id: 'EQ', code: 'Q', name: 'Event queue', short: 'EVENT QUEUE', group: 'ops', gx: 9.5, gy: 9.5, w: 2, d: 2, h: 18, kind: 'store',
    one: 'A bounded ring of "what just happened" — handlers push without blocking.',
    what: 'Every request — page shown, login won or lost, request proxied — becomes one small record. The queue holds the most recent ones until a monitor comes to read them; when it fills, the oldest are overwritten.',
    how: '<code>VecDeque&lt;Event&gt;</code> + <code>Condvar</code> in <code>src/monitor.rs</code>. Each event: <code>{seq, time, kind, status, ip, method, path, user?, user_agent?}</code>. Overwrites during a live connection are counted and later reported as <mark>{"kind":"dropped"}</mark>; events leave only after they are written to the client.',
    steps: [
      ['Push', 'Stamp seq + UTC time; if full, evict the oldest (count it if a monitor is attached).'],
      ['Pending', 'Wait on the condvar; hand the batch out but keep it queued.'],
      ['Consume', 'mark_consumed only after the bytes hit the socket.'],
    ],
    cond: [
      'Events overwritten while no monitor is connected vanish silently — should that count be surfaced to the next monitor?',
    ] },
  { id: 'MO', code: 'M', name: 'Monitor port', short: 'MONITOR', group: 'ops', gx: 13, gy: 10, w: 2, d: 2, h: 26, kind: 'screen',
    one: 'One loopback TCP client at a time gets the live JSON-lines feed.',
    what: 'A peephole for the operator: connect with netcat and watch one JSON line per request scroll by. Only one watcher at a time; a second connection is told it is busy and hung up.',
    how: 'Plain <code>TcpListener</code> on <code>monitor_addr</code> (<mark>loopback enforced in config</mark>) on its own OS thread; each client is served on a further thread. Second clients get <code>{"error":"another monitor is already connected"}</code>. Idle clients receive a <code>heartbeat</code> line every 10s so gone-aways are detected.',
    steps: [
      ['Accept', 'One slot: try_connect or send the busy error and close.'],
      ['Stream', 'Wait for pending events; write JSON lines + dropped notices.'],
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
    ['BR', 'CF', 'POST /__wsb/login', { form: { phrase: 'correct horse battery staple 42!' } }, 'xy'],
    ['CF', 'G', 'phrase + client IP', { headers: { 'cf-connecting-ip': '203.0.113.9' } }, 'xy'],
    ['G', 'R', 'reserve attempt', { key: '203.0.113.9', in_window: 0 }, 'xy'],
    ['G', 'U', 'SELECT by sha512', { pass_phrase: 'ddaf35…(128 hex)' }, 'yx'],
    ['U', 'G', 'user row', { user_name: 'chris', is_admin: false }, 'xy'],
    ['G', 'S', 'insert session (map + users.db)', { token: '9f3a…(32B hex)', stored: 'sha256(9f3a…)', user: 'chris', ttl_secs: 15552000 }, 'xy'],
    ['G', 'CF', '303 + Set-Cookie', { set_cookie: 'wsb_session=9f3a…; HttpOnly; SameSite=Lax; Secure' }, 'yx'],
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
    ['F', 'G', 'response', { status: 200 }, 'yx'],
    ['G', 'BR', 'response via tunnel', { kind: 'proxied', status: 200 }, 'yx'],
  ] },
  { id: 'fail', name: 'A failed login', hops: [
    ['BR', 'G', 'POST wrong phrase', { form: { phrase: 'let me in' } }, 'xy'],
    ['G', 'R', 'reserve attempt', { key: '203.0.113.9', in_window: 'n/10' }, 'xy'],
    ['R', 'G', 'under limit', { allowed: true }, 'yx'],
    ['G', 'U', 'SELECT by sha512', { pass_phrase: 'hash(letmein)' }, 'yx'],
    ['U', 'G', 'miss', { found: false }, 'xy'],
    ['G', 'BR', '401 after 1s', { page: 'Incorrect phrase.', kind: 'login_failed' }, 'yx'],
  ] },
  { id: 'logout', name: 'Logging out', hops: [
    ['BR', 'G', 'POST /__wsb/logout', { headers: { 'sec-fetch-site': 'same-origin' } }, 'xy'],
    ['G', 'S', 'remove token', { token: '9f3a…' }, 'xy'],
    ['S', 'G', 'gone', { user: 'chris' }, 'yx'],
    ['G', 'BR', '303 + cookie cleared', { set_cookie: 'wsb_session=; Max-Age=0' }, 'yx'],
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
    lede: `One secret per person: the phrase is both password and identity.`,
    story: `<p>The login form asks for a phrase, nothing else. It is <mark>normalized — whitespace stripped, lower-cased</mark> — then SHA-512'd and looked up; the database never stores the phrase itself.</p>`,
    flow: [
      ['BR', 'G', 'POST phrase (via tunnel)', { form: { phrase: 'correct horse … 42!' } }],
      ['G', 'U', 'SELECT by sha512', { pass_phrase: 'ddaf35…' }],
      ['U', 'G', 'user row', { user_name: 'chris', is_admin: false }],
      ['G', 'BR', '303 + Set-Cookie', { set_cookie: 'wsb_session=…' }],
    ] },
  { id: 'session', title: 'The session table', reveal: ['S'],
    lede: `A correct phrase mints a token; the cookie is your ticket from then on.`,
    story: `<p>The gate keeps a <mark>small table — hashed token → user + expiry</mark> — capped at 3 sessions per user and 10,000 total. Every login writes through to the <code>sessions</code> table in users.db (SHA-256 of the token only), and serve reloads it at startup and every minute — restart no longer logs anyone out.</p>`,
    flow: [
      ['BR', 'G', 'POST phrase', { form: { phrase: '…' } }],
      ['G', 'S', 'insert hash', { cookie_string: 'sha256(9f3a…)', user: 'chris', ttl_secs: 15552000 }],
      ['G', 'BR', '303 + Set-Cookie', { set_cookie: 'wsb_session=9f3a…' }],
      ['BR', 'G', 'next request + cookie', { cookie: 'wsb_session=9f3a…' }],
      ['G', 'S', 'lookup', { token: '9f3a…' }],
      ['S', 'G', 'user + expiry', { user: 'chris', ok: true }],
    ] },
  { id: 'through', title: 'Through to the app', reveal: ['F', 'UP'],
    lede: `Once you're known, the gate rewrites and forwards — the app never sees the login dance.`,
    story: `<p>The forwarder <mark>rebuilds the request</mark>: the session cookie and hop-by-hop headers come out, client-sent forwarding headers are discarded, honest ones are stamped. The app sits on loopback and trusts what arrives.</p>`,
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
    story: `<p>Failures are counted per <mark>client IP</mark> (the tunnel's header first, the peer address as fallback) in a bounded ledger. The attempt is reserved before the lookup, so concurrency can't slip extra tries through.</p>`,
    flow: [
      ['BR', 'G', 'POST wrong phrase', { form: { phrase: 'let me in' } }],
      ['G', 'R', 'reserve attempt', { key: '203.0.113.9' }],
      ['R', 'G', 'under limit', { in_window: 'n/10' }],
      ['G', 'U', 'lookup', { pass_phrase: 'hash(letmein)' }],
      ['U', 'G', 'miss', { found: false }],
      ['G', 'BR', '401 after 1s', { kind: 'login_failed' }],
    ] },
  { id: 'watch', title: 'Watching the door', reveal: ['EQ', 'MO'],
    lede: `Every request leaves a one-line trace on a loopback port.`,
    story: `<p>Handlers <mark>push events without blocking</mark> into a bounded queue; a separate thread serves them as JSON lines to one connected monitor, marking them consumed only after the bytes are written.</p>`,
    flow: [
      ['BR', 'G', 'any request', { method: 'POST', path: '/__wsb/login' }],
      ['G', 'EQ', 'push event', { kind: 'login_succeeded', ip: '203.0.113.9' }],
      ['EQ', 'MO', 'JSON line', { seq: 4 }],
      ['MO', 'EQ', 'mark consumed', { up_to: 4 }],
    ] },
  { id: 'operate', title: 'Running it', reveal: ['OP', 'C'],
    lede: `Five commands: write-config, add-user, remove-user, list-users, serve.`,
    story: `<p>The operator <mark>manages users by piping lines</mark> — "name pass phrase words…" — into add-user; remove-user deletes by name and list-users shows who is in. serve refuses to start with no users at all.</p>`,
    flow: [
      ['OP', 'C', 'add-user <<EOF', { line: 'chris correct horse … 42!' }],
      ['C', 'U', 'INSERT hash', { user_name: 'chris', pass_phrase: '<sha512 hex>', is_admin: false }],
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
                └ purger task (session reload + failures, 60s)
  OS thread     ─ monitor listener + per-client threads
  hyper client  ─ upstream, 10s connect / 60s headers</pre>
<h3 class="sec">Ports</h3><pre>listen_addr   127.0.0.1:8080  public (via tunnel)
monitor_addr  127.0.0.1:8081  loopback only
upstream      127.0.0.1:3000  the protected app</pre>`;
