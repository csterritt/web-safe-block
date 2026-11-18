# web-safe-block — System Definition

_**This file is the living source of truth for the design.** The interactive atlas (`atlas.html`) is built from the same data; edit this file and rebuild, never the outputs._

_Question status: **11 open · 6 resolved**._

## One paragraph

web-safe-block is a small Rust program that parks itself in front of a web server you don't fully trust. The internet reaches only its public port (through a TLS terminator such as Cloudflare Tunnel); it answers every request with a one-field phrase form until someone submits a phrase that hashes to a row in `users.db` — then it mints an in-memory session cookie and becomes a plain reverse proxy to the protected app on loopback. A second, loopback-only port streams one JSON line per request to a single watcher. v1 answers protocol upgrades with a 501 instead of relaying them, and sessions vanish on restart.

## Decisions locked

| Axis | Decision | ADR |
|---|---|---|
| Runtime | Rust + axum/hyper on one tokio runtime; a plain OS thread runs the monitor | — |
| Credential | The pass phrase is the whole credential — it identifies the user; no username on the wire | [0001](./adr/0001-phrase-is-the-credential.md) |
| Phrase storage | Unsalted SHA-512 of the normalized phrase (per-user salt is impossible when lookup is by phrase alone); ≥20 chars + digit + punctuation enforced at add time | [0001](./adr/0001-phrase-is-the-credential.md) |
| Sessions | In-memory token→user map, 10/user and 10k total, TTL from config; lost on restart by design | [0002](./adr/0002-sessions-in-memory.md) |
| Client IP | CF-Connecting-IP is trusted when present — listen_addr must only ever face the tunnel | [0003](./adr/0003-trusted-edge-header.md) |
| Config | Every setting required; unknown keys rejected; relative users_db resolves against the config file | [0004](./adr/0004-strict-config.md) |
| Monitor | One loopback JSON-lines client at a time; bounded queue overwrites the oldest events | [0005](./adr/0005-one-monitor.md) |
| Upstream | http:// only, no path — the protected app stays on loopback | — |
| Reserved paths | /__wsb/* is never forwarded; cross-site POSTs to it are rejected | — |
| Protocol upgrades | An Upgrade header gets 501 after the session check — never proxied (a real WS relay is still a ghost) | — |

## Cost model

Bounds, not dollars — this is one process on one box. Every in-memory structure is capped:

| Resource | Bound | Where |
|---|---|---|
| Sessions | 10 per user, 10,000 total, TTL from `session_ttl_secs` (default 7d) | `src/state.rs` `Limits` + `src/sessions.rs` |
| Failed-login keys | 10,000 IPs, ≤10 stamps each, 15-minute window | `src/rate_limit.rs` `reserve_attempt` |
| Event queue | `monitor_queue_len` (default 1,000), oldest overwritten | `src/monitor.rs` `EventQueue` |
| Upstream waits | 10s to connect, 60s for response headers | `src/proxy.rs` `forward` |
| users.db | one row per user; phrase kept only as SHA-512 hex | `src/users.rs` |
## Reading order (the atlas chapters)

1. **The front door** — Every request arrives at one public port; everything else hides behind it. _(adds BR, CF, G)_
2. **The phrase book** — One secret per person: the phrase is both password and identity. _(adds U)_
3. **The session table** — A correct phrase mints a token; the cookie is your ticket from then on. _(adds S)_
4. **Through to the app** — Once you're known, the gate rewrites and forwards — the app never sees the login dance. _(adds F, UP)_
5. **Slowing down guessing** — Wrong phrase? Ten tries per quarter-hour per client — and each miss costs a second. _(adds R)_
6. **Watching the door** — Every request leaves a one-line trace on a loopback port. _(adds EQ, MO)_
7. **Running it** — Five commands: write-config, add-user, remove-user, list-users, serve. _(adds OP, C)_
8. **Not switched on** — Designed for, not built. _(adds WS, PS)_
9. **The whole system** — Everything at once, for free exploration.

## Structures

### The edge

#### B · Visitor's browser

**In one line.** A person with a browser, outside, who wants in.

**What it does.** Anyone on the internet. They see exactly two things from web-safe-block itself: the phrase form, and — once they are in — whatever the protected app serves.

**How it's built.** All it ever needs to send is a `POST /__wsb/login` with a `phrase` field, then carry the `wsb_session` cookie. No JavaScript on our pages; plain forms only.

**Steps in execution.**

1. **Ask** — GET any path — gets the phrase form back until logged in.
2. **Submit** — POST the phrase to /__wsb/login.
3. **Carry** — Browser sends wsb_session automatically on later requests.

#### T · TLS terminator

**In one line.** Cloudflare Tunnel (or any TLS front) — the only road in.

**What it does.** TLS is not web-safe-block's job. A tunnel or reverse proxy holds the certificate and forwards plain http to the public port, stamping the real client IP in a header.

**How it's built.** Forwards to `listen_addr` (default `127.0.0.1:8080`) and sets `CF-Connecting-IP`, which the gate reads **and trusts** for client IP, rate limiting, and event logs.

**Steps in execution.**

1. **Terminate** — TLS ends here; onward hop is plain http.
2. **Stamp** — Adds CF-Connecting-IP with the real client address.
3. **Forward** — Sends the request to listen_addr.

**Questions.**

- **Q-T1** If listen_addr is ever exposed directly, CF-Connecting-IP becomes attacker-controlled — should the gate only honor it from the tunnel's peer address?

### The gate

#### G · The gate

**In one line.** The public listener: login page, session check, reserved endpoints, upgrade refusal, then forward-or-refuse.

**What it does.** One port answers every request the internet sends. Without a valid session you get the phrase form and nothing else; with one, your request is handed to the forwarder — unless it asks for a protocol upgrade, which earns a 501. A tiny /__wsb/ namespace carries login, logout, and nothing else.

**How it's built.** `axum` router in `src/app.rs`: `POST /__wsb/login` and `GET|POST /__wsb/logout` live in `src/auth.rs`, fallback `proxy_or_login` in `src/proxy.rs`. Any other `/__wsb/*` path is a 404 **reserved**. Cross-site POSTs are refused via `Sec-Fetch-Site`, then `Origin`. Authenticated requests with an `Upgrade` header get **501**, kind `upgrade`. Every request exits through `record_event` middleware.

**Steps in execution.**

1. **Route** — /__wsb/ endpoints handled here; unknown ones are 404 reserved.
2. **Authenticate** — Parse cookies → wsb_session → sessions table → user.
3. **Decide** — Login page (401), the login/logout handlers, 501 for upgrade attempts, or hand to the forwarder.
4. **Report** — Attach an Outcome; middleware pushes one event per request.

**Questions.**

- ~~**Q-G1** Should GET /__wsb/logout end the session?~~ ✓ No — GET shows a confirm form; only POST destroys the session, and cross-site POSTs are rejected (review-1 finding 5, fixed).
- **Q-G2** Cross-site POST checks fall back to Origin only when Sec-Fetch-Site is absent; a client sending neither is allowed through. Keep that posture?

#### S · Session table

**In one line.** The gate's memory: random token → user + expiry, in RAM only.

**What it does.** A small table that answers "who is this cookie?" Login puts a random token in; every later request trades the cookie for a user name. Restart the process and everyone is logged out.

**How it's built.** `HashMap<String, Session>` behind a `Mutex`. Tokens are **32 random bytes, hex**. Caps: 10 sessions per user and 10,000 total — the earliest-expiring entry is evicted; a background task purges expired rows every 60s.

**Steps in execution.**

1. **Insert** — new_token() → Session{user, expires}; evict oldest to stay inside caps.
2. **Check** — Valid + unexpired → user name; expired → removed on sight.
3. **Sweep** — Purger task drops expired entries every 60 seconds.

**Questions.**

- **Q-S1** Sessions die on restart — acceptable while this guards one box, or should they persist? (see ghost P)

#### R · Failure ledger

**In one line.** Ten failed phrases per quarter-hour per client — and each miss costs a second.

**What it does.** The brute-force brake. Every wrong phrase is written down against the client's IP; after ten in fifteen minutes the answer is "too many attempts" until the window slides past.

**How it's built.** `HashMap<ip, Vec<Instant>>`. **One attempt is reserved under a single lock** before the database lookup, refunded on a db error, cleared on success — so concurrent guesses can't slip past the limit. Ledger bounded to 10,000 keys; a wrong answer also waits 1s before responding.

**Steps in execution.**

1. **Reserve** — Count this attempt under one lock; refuse if the key already has 10 in-window.
2. **Judge** — Lookup miss → keep the stamp; db error → refund it; success → clear the key.
3. **Delay** — Failed logins sleep 1s before the 401.

**Questions.**

- **Q-R1** Limiting keys on client IP — visitors sharing one NAT or carrier-grade address share the 10/15min budget. Acceptable?
- ~~**Q-R2** Should failures count the attempt before the lookup (atomically)?~~ ✓ Yes — reserve_attempt takes the slot under one lock, then refund/clear reconciles (review-1 finding 7, fixed).

#### U · Phrase book

**In one line.** The sqlite file of who may enter — phrase hashes only, never phrases.

**What it does.** The list of people allowed in. It stores each user name, the SHA-512 of their normalized phrase, and an admin flag — not the phrase itself. The gate asks it "is there anyone with this phrase?" on every login.

**How it's built.** `users.db`: `UserStore` opens it read-only for `serve` and `list-users`; `add-user` creates and writes it, `remove-user NAME` deletes one row. Phrases are **normalized — whitespace stripped, lower-cased** — then hex SHA-512'd. Name and phrase hash are both UNIQUE. Names containing "admin" set the flag; new phrases need ≥20 chars, a digit, and punctuation.

**Steps in execution.**

1. **Normalize** — Drop all whitespace, lower-case ("Open Sesame" == "opensesame").
2. **Hash** — SHA-512 hex — that string is what is stored and searched.
3. **Lookup** — SELECT user_name, is_admin WHERE pass_phrase = hash.
4. **Manage** — add-user inserts; remove-user deletes by name; list-users prints names + flags.

**Questions.**

- ~~**Q-U1** There is no remove-user or phrase-rotation command — revoking someone means editing users.db by hand. Acceptable?~~ ✓ remove-user NAME deletes the row and list-users shows who is in (2026-11-17). Caveat kept: sessions already held keep working until their TTL or a restart — it revokes the phrase, not live sessions. Phrase rotation is still add-then-remove.
- **Q-U2** The is_admin flag is stored and shown by list-users but serve never reads it for authorization — what should admins be able to do?
- ~~**Q-U3** Why not a per-user salt on the hash?~~ ✓ Lookup is by phrase alone — the phrase identifies the user, so there is no name to salt against before hashing. Strength is enforced at add time instead (README security notes).

### Through to the app

#### F · Forwarder

**In one line.** Rewrites the request, scrubs it, sends it upstream, brings the answer back.

**What it does.** Once you are known, this is the actual proxy. It points your request at the protected app, removes everything that could confuse or poison it — including the session cookie itself — and returns the app's answer.

**How it's built.** `hyper-util` client in `forward()` (`src/proxy.rs`). Swaps scheme+authority for `upstream`; strips `wsb_session`, hop-by-hop headers, and **all client-sent Forwarded/X-Forwarded-*/X-Real-IP**; then stamps its own X-Forwarded-For (client IP), -Proto, -Host. 10s connect, 60s response-header deadline → 502/504. Upstream Set-Cookie for wsb_session is dropped. Upgrade requests never reach here — the gate answers them 501.

**Steps in execution.**

1. **Rewrite** — Keep path+query; replace scheme and authority with upstream.
2. **Scrub** — Session cookie out; hop-by-hop out; client forwarding headers out.
3. **Stamp** — Write X-Forwarded-For/-Proto/-Host from verified values.
4. **Send** — 10s connect timeout, 60s to response headers; else 502/504.
5. **Return** — Strip hop-by-hop on the way back; drop any wsb_session Set-Cookie.

**Questions.**

- ~~**Q-F1** Trust client-sent X-Forwarded-* / X-Real-IP headers?~~ ✓ No — inbound forwarding headers are discarded and rebuilt from verified proxy metadata (review-1 finding 1, fixed).
- **Q-F2** Only connect (10s) and response-header (60s) deadlines exist — a response that stalls mid-body streams forever. Is that a real exposure?

#### A · Protected app

**In one line.** The web server being sheltered — bound to loopback, reachable only through the gate.

**What it does.** Whatever app you are protecting: a blog, a dashboard, a thing that was never hardened. It sees only requests the gate already decided to allow, carrying honest forwarding headers.

**How it's built.** Any http server on `upstream` (default `http://127.0.0.1:3000`, **http only, no path**). It receives `X-Forwarded-For/Proto/Host` and never the `wsb_session` cookie.

**Steps in execution.**

1. **Serve** — Handle the request as if the caller were already trusted.
2. **Respond** — Answer streams back through the forwarder to the visitor.

**Questions.**

- **Q-A1** Upstream is http-on-loopback only — will a real deployment ever need https upstream or a unix socket?

### Operating it

#### O · Operator

**In one line.** The person with shell access who owns the box.

**What it does.** You, on the machine itself: writing the config, adding users by piping lines, starting the server, and optionally tailing the monitor with netcat.

**How it's built.** Everything is one binary: `web-safe-block write-config | add-user | remove-user | list-users | serve`, plus `-c path` for a non-default `config.toml`. Watching is `nc 127.0.0.1 8081`.

**Steps in execution.**

1. **Configure** — write-config emits a commented config.toml; refuses to overwrite.
2. **Populate** — add-user reads "name pass phrase…" lines from stdin.
3. **Maintain** — list-users shows names + admin flags; remove-user NAME deletes a row.
4. **Run** — serve binds the public port and the monitor port.
5. **Watch** — nc to the monitor port for a live event stream.

#### C · CLI & config

**In one line.** Five commands and one strict config file.

**What it does.** The whole control surface. write-config lays down a commented config.toml; add-user, remove-user and list-users maintain the phrase book; serve runs everything. The config is all-or-nothing: every setting must be present and no unknown keys are allowed.

**How it's built.** `src/main.rs` + `src/settings.rs`. Seven settings, **all required, unknown keys denied**: users_db, listen_addr, upstream, session_ttl_secs, cookie_secure, monitor_addr (loopback only), monitor_queue_len. Relative users_db resolves against the config file's directory.

**Steps in execution.**

1. **write-config** — Emit defaults with comments; refuse to overwrite an existing file.
2. **add-user** — Per stdin line: first word = name, rest = phrase; weak or duplicate lines skipped.
3. **remove-user NAME** — Deletes the row; errors if the name is not found.
4. **list-users** — Print user_name + is_admin, sorted by name.
5. **serve** — Load config + users.db (must exist and be non-empty), bind both ports.

**Questions.**

- **Q-C1** Single config file, no environment overrides or flags — fine for a small self-hosted tool, or will it annoy deployment?

#### Q · Event queue

**In one line.** A bounded ring of "what just happened" — handlers push without blocking.

**What it does.** Every request — page shown, login won or lost, request proxied — becomes one small record. The queue holds the most recent ones until a monitor comes to read them; when it fills, the oldest are overwritten.

**How it's built.** `VecDeque<Event>` + `Condvar` in `src/monitor.rs`. Each event: `{seq, time, kind, status, ip, method, path, user?, user_agent?}`. Overwrites during a live connection are counted and later reported as **{"kind":"dropped"}**; events leave only after they are written to the client.

**Steps in execution.**

1. **Push** — Stamp seq + UTC time; if full, evict the oldest (count it if a monitor is attached).
2. **Pending** — Wait on the condvar; hand the batch out but keep it queued.
3. **Consume** — mark_consumed only after the bytes hit the socket.

**Questions.**

- **Q-Q1** Events overwritten while no monitor is connected vanish silently — should that count be surfaced to the next monitor?

#### M · Monitor port

**In one line.** One loopback TCP client at a time gets the live JSON-lines feed.

**What it does.** A peephole for the operator: connect with netcat and watch one JSON line per request scroll by. Only one watcher at a time; a second connection is told it is busy and hung up.

**How it's built.** Plain `TcpListener` on `monitor_addr` (**loopback enforced in config**) on its own OS thread; each client is served on a further thread. Second clients get `{"error":"another monitor is already connected"}`. Idle clients receive a `heartbeat` line every 10s so gone-aways are detected.

**Steps in execution.**

1. **Accept** — One slot: try_connect or send the busy error and close.
2. **Stream** — Wait for pending events; write JSON lines + dropped notices.
3. **Probe** — After EOF on reads, heartbeat every 10s; a reset ends the connection.

**Questions.**

- **Q-M1** The monitor trusts loopback alone — any local process can watch the request stream. Is that fine, or should it take a token?

### Not switched on (designed for, not built)

#### W · WebSocket relay _(not switched on)_

**In one line.** Designed for, not built: live upgrade connections to the app.

**What it does.** Apps that want WebSockets cannot work through the gate today — an authenticated request carrying an Upgrade header is answered 501 and never reaches the app.

**How it's built.** `proxy_or_login` returns **501 Not Implemented**, kind `upgrade`, for any authenticated request with an `Upgrade` header; the hop-by-hop scrub still removes `connection`/`upgrade` from ordinary traffic. A real relay needs an upgrade path in `forward()` and a decision about streaming bodies.

**Steps in execution.**

1. **Upgrade** — Detect a genuine upgrade request after the session check.
2. **Relay** — Pipe the connection to upstream instead of request/response.

**Questions.**

- ~~**Q-W1** Until then: should v1 answer upgrade attempts with a clear 501 instead of forwarding a stripped request that fails mysteriously?~~ ✓ Yes — the gate answers 501 (kind upgrade) to authenticated Upgrade requests and forwards nothing (2026-11-17).

#### P · Saved sessions _(not switched on)_

**In one line.** Designed for, not built: sessions that survive a restart.

**What it does.** Today, restarting web-safe-block logs everyone out, because the session table lives only in memory. This ghost is a small persistent store — a file or a sqlite table — written on login and read on boot.

**How it's built.** A write-through table next to `users.db`, or a second file, holding `{token, user, expiry}`; `serve` would reload unexpired rows at startup. The caps and the 60s sweep stay the same.

**Steps in execution.**

1. **Write-through** — Insert session → also append/update the store.
2. **Reload** — On boot, load rows with expiry in the future.

**Questions.**

- **Q-P1** Worth doing? It trades "restart clears the decks" (a nice property after an incident) for nobody being logged out on deploys.

## Flows (representative packets)

Payload shapes are what the design implies, not measured traffic.

### A login

| # | From → To | Packet | Representative payload |
|---|---|---|---|
| 1 | BR → CF | POST /__wsb/login | `{"form":{"phrase":"correct horse battery staple 42!"}}` |
| 2 | CF → G | phrase + client IP | `{"headers":{"cf-connecting-ip":"203.0.113.9"}}` |
| 3 | G → R | reserve attempt | `{"key":"203.0.113.9","in_window":0}` |
| 4 | G → U | SELECT by sha512 | `{"pass_phrase":"ddaf35…(128 hex)"}` |
| 5 | U → G | user row | `{"user_name":"chris","is_admin":false}` |
| 6 | G → S | insert session | `{"token":"9f3a…(32B hex)","user":"chris","ttl_secs":604800}` |
| 7 | G → CF | 303 + Set-Cookie | `{"set_cookie":"wsb_session=9f3a…; HttpOnly; SameSite=Lax; Secure"}` |
| 8 | CF → BR | redirect | `{"status":303,"location":"/"}` |

### A proxied request

| # | From → To | Packet | Representative payload |
|---|---|---|---|
| 1 | BR → CF | GET /app + cookie | `{"cookie":"wsb_session=9f3a…"}` |
| 2 | CF → G | http + client IP | `{"headers":{"cf-connecting-ip":"203.0.113.9"}}` |
| 3 | G → S | token valid? | `{"token":"9f3a…"}` |
| 4 | S → G | user | `{"user":"chris","ok":true}` |
| 5 | G → F | forward | `{"note":"wsb_session + hop-by-hop stripped"}` |
| 6 | F → UP | GET /app | `{"headers":{"x-forwarded-for":"203.0.113.9","x-forwarded-proto":"https"}}` |
| 7 | UP → F | response | `{"status":200}` |
| 8 | F → G | response | `{"status":200}` |
| 9 | G → BR | response via tunnel | `{"kind":"proxied","status":200}` |

### A failed login

| # | From → To | Packet | Representative payload |
|---|---|---|---|
| 1 | BR → G | POST wrong phrase | `{"form":{"phrase":"let me in"}}` |
| 2 | G → R | reserve attempt | `{"key":"203.0.113.9","in_window":"n/10"}` |
| 3 | R → G | under limit | `{"allowed":true}` |
| 4 | G → U | SELECT by sha512 | `{"pass_phrase":"hash(letmein)"}` |
| 5 | U → G | miss | `{"found":false}` |
| 6 | G → BR | 401 after 1s | `{"page":"Incorrect phrase.","kind":"login_failed"}` |

### Logging out

| # | From → To | Packet | Representative payload |
|---|---|---|---|
| 1 | BR → G | POST /__wsb/logout | `{"headers":{"sec-fetch-site":"same-origin"}}` |
| 2 | G → S | remove token | `{"token":"9f3a…"}` |
| 3 | S → G | gone | `{"user":"chris"}` |
| 4 | G → BR | 303 + cookie cleared | `{"set_cookie":"wsb_session=; Max-Age=0"}` |

### Tailing the monitor

| # | From → To | Packet | Representative payload |
|---|---|---|---|
| 1 | OP → MO | nc 127.0.0.1 8081 | `{"connect":"only monitor slot"}` |
| 2 | BR → G | any request | `{"method":"POST","path":"/__wsb/login"}` |
| 3 | G → EQ | push event | `{"kind":"login_succeeded","status":303,"ip":"203.0.113.9","user":"chris"}` |
| 4 | EQ → MO | JSON line | `{"seq":4,"time":"2026-11-17T18:40:01Z"}` |
| 5 | MO → EQ | mark consumed | `{"up_to":4}` |

## Questions — index

Reference by ID. ✓ resolved (with date) · otherwise open.

- **Q-T1** (T) If listen_addr is ever exposed directly, CF-Connecting-IP becomes attacker-controlled — should the gate only honor it from the tunnel's peer address?
- ~~**Q-G1**~~ (G) ✓ No — GET shows a confirm form; only POST destroys the session, and cross-site POSTs are rejected (review-1 finding 5, fixed).
- **Q-G2** (G) Cross-site POST checks fall back to Origin only when Sec-Fetch-Site is absent; a client sending neither is allowed through. Keep that posture?
- **Q-S1** (S) Sessions die on restart — acceptable while this guards one box, or should they persist? (see ghost P)
- **Q-R1** (R) Limiting keys on client IP — visitors sharing one NAT or carrier-grade address share the 10/15min budget. Acceptable?
- ~~**Q-R2**~~ (R) ✓ Yes — reserve_attempt takes the slot under one lock, then refund/clear reconciles (review-1 finding 7, fixed).
- ~~**Q-U1**~~ (U) ✓ remove-user NAME deletes the row and list-users shows who is in (2026-11-17). Caveat kept: sessions already held keep working until their TTL or a restart — it revokes the phrase, not live sessions. Phrase rotation is still add-then-remove.
- **Q-U2** (U) The is_admin flag is stored and shown by list-users but serve never reads it for authorization — what should admins be able to do?
- ~~**Q-U3**~~ (U) ✓ Lookup is by phrase alone — the phrase identifies the user, so there is no name to salt against before hashing. Strength is enforced at add time instead (README security notes).
- ~~**Q-F1**~~ (F) ✓ No — inbound forwarding headers are discarded and rebuilt from verified proxy metadata (review-1 finding 1, fixed).
- **Q-F2** (F) Only connect (10s) and response-header (60s) deadlines exist — a response that stalls mid-body streams forever. Is that a real exposure?
- **Q-A1** (A) Upstream is http-on-loopback only — will a real deployment ever need https upstream or a unix socket?
- **Q-C1** (C) Single config file, no environment overrides or flags — fine for a small self-hosted tool, or will it annoy deployment?
- **Q-Q1** (Q) Events overwritten while no monitor is connected vanish silently — should that count be surfaced to the next monitor?
- **Q-M1** (M) The monitor trusts loopback alone — any local process can watch the request stream. Is that fine, or should it take a token?
- ~~**Q-W1**~~ (W) ✓ Yes — the gate answers 501 (kind upgrade) to authenticated Upgrade requests and forwards nothing (2026-11-17).
- **Q-P1** (P) Worth doing? It trades "restart clears the decks" (a nice property after an incident) for nobody being logged out on deploys.

## What the platform gives vs what we own

**Platform gives:** axum 0.8 (router, form extractor, middleware), hyper + hyper-util (HTTP/1 server and client with timeouts), rusqlite with bundled sqlite, tokio, rand.

**We own:** the gate: phrase-only login, in-memory sessions, the per-IP throttle, header scrub + forwarding-header rebuild, the bounded event queue and monitor thread, strict config loading, and the users.db schema plus pass-phrase strength policy.

## Planned filesystem

```
web-safe-block/
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
  Notes/atlas/    this atlas
```

## How this file is maintained

Generated from `Notes/atlas/data.mjs` by `bun Notes/atlas/build.mjs`, which also builds the interactive atlas (`atlas.html`). Edit the data file, rebuild, republish — never edit this file by hand.
