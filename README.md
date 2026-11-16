# Web-Safe Block

A simple program called `web-safe-block` in rust, which does the following.

The idea is that you have a web server program running that may or may not be super hardened. Its port is not available to the outside world. The `web-safe-block` program will be connected to the internet on another port, and will forward requests to the protected web server in the following way.

`web-safe-block` will listen on its internet port, and for a new connection, send a very simple no-css HTML page with a single form with a text entry box, labeled "Phrase", and a button labeled "Submit" which submits the form.

Users are stored in a sqlite3 database (`users.db` in the current directory), added with the `add-user` command. Each user has a user name, a unique pass phrase, and an admin flag (set when the user name contains "admin"). When the html page submit happens with a phrase, all whitespace is removed and it is lower-cased, then it is looked up in the database.

When the input matches a user's phrase, then it sets a cookie with a large random value. For page requests from then on that have the cookie set with a value stored in memory, it passes the request on to the other progarm's port.

## Usage

```sh
cargo build --release

# Add users: one per line, "user-name pass phrase words...".
./target/release/web-safe-block add-user <<'EOF'
chris correct horse battery staple
site-admin Purple Monkey Dishwasher
EOF

UPSTREAM=http://127.0.0.1:3000 \
LISTEN_ADDR=127.0.0.1:8080 \
./target/release/web-safe-block serve
```

Then point Cloudflare Tunnel (or another TLS terminator) at `http://127.0.0.1:8080`.

### `add-user`

Reads lines from stdin into `./users.db`, creating it if needed. Each line is split on whitespace: the first word is the user name and the rest is the pass phrase.

- Pass phrases are normalized: all whitespace is removed and the phrase is lower-cased. `Open Sesame` and `opensesame` are the same phrase.
- The database stores the hex SHA-512 of the normalized phrase, not the phrase itself.
- User names and pass phrases must both be unique, including against users already in the database.
- A user whose name contains `admin` (any case) is an admin.
- Blank lines are ignored. Bad lines (no phrase, duplicate name, phrase already in use) are reported on stderr and skipped. The other lines are still added, and the command exits with status 1 if anything was skipped.

### `serve`

Runs the proxy, using `./users.db` from the current directory. It exits with an error if the database is missing or has no users. Users added while the server is running can log in right away. Logins are logged to stdout with the user name.

| Variable | Default | Meaning |
|---|---|---|
| `UPSTREAM` | `http://127.0.0.1:3000` | Protected server (must be `http://`). |
| `LISTEN_ADDR` | `127.0.0.1:8080` | Address web-safe-block listens on. |
| `SESSION_TTL_SECS` | `604800` (7 days) | Session lifetime. |
| `COOKIE_SECURE` | `true` | Set to `false`/`0` to omit the `Secure` cookie flag (plain-http testing on a non-localhost host). |
| `MONITOR_ADDR` | `127.0.0.1:8081` | Local monitor port. Must be a loopback address. |
| `MONITOR_QUEUE_LEN` | `1000` | How many unreported events are kept. |

Visit `/__wsb/logout` to end a session.

### Monitor port

`serve` also listens on `MONITOR_ADDR` (loopback only) and reports every request to the public port as one JSON object per line:

```sh
$ nc 127.0.0.1 8081
{"seq":4,"time":"2026-11-16T18:40:01Z","kind":"login_succeeded","status":303,"ip":"203.0.113.9","method":"POST","path":"/__wsb/login","user":"chris","user_agent":"Mozilla/5.0 ..."}
```

- `kind` is one of:
  - `login_page`: unauthenticated request, shown the form.
  - `login_failed`, `login_succeeded`, `rate_limited`, `logout`.
  - `proxied`: authenticated request forwarded upstream; `status` is the upstream's, or 502.
  - `reserved`: an unknown `/__wsb/` path.
  - `other`: e.g. wrong method or a malformed form.
- `ip` is `CF-Connecting-IP` if present, otherwise the peer address. `user` is set for `login_succeeded`, `proxied` and `logout`.
- The request handlers add events to a bounded in-memory queue without blocking. A separate thread sends them to the monitor and marks them consumed only after they have been written.
- When the queue is full, the oldest events are overwritten.
  - With no monitor connected this happens silently. A monitor that connects later first receives whatever is still queued.
  - If events are overwritten before a connected monitor gets them, it receives `{"kind":"dropped","count":N}`.
- Only one monitor can be connected at a time. Another connection gets `{"error":"another monitor is already connected"}` and is closed.
- If the monitor client stops sending (e.g. `nc 127.0.0.1 8081 < /dev/null`), it gets a `{"kind":"heartbeat",...}` line every 10s while idle; this is how the server finds out when it has gone away.

## Security notes

- Bind the protected server to `127.0.0.1` so it is reachable only through web-safe-block.
- The session cookie `wsb_session` is `HttpOnly`, `SameSite=Lax`, and stripped from requests before they are forwarded; any `Set-Cookie` for `wsb_session` coming from the backend is dropped.
- Login attempts are limited to 10 failures per 15 minutes per client (keyed on `CF-Connecting-IP`, falling back to the peer IP), with a 1s delay on each failure. Because `CF-Connecting-IP` is trusted, don't expose `LISTEN_ADDR` anywhere except to the tunnel.
- Sessions live in memory and are lost on restart.
- Pass phrases are stored as unsalted SHA-512 hashes (lookup is by phrase alone, so a per-user salt isn't possible). This keeps phrases out of plain view if `users.db` leaks, but short or common phrases can still be brute-forced, so use long phrases and keep `users.db` private.
- WebSockets are not supported in v1.
- Paths under `/__wsb/` are reserved and never forwarded.
- Cookies are not port-scoped: other services on the same hostname will also receive `wsb_session`.
