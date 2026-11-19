# Web-Safe Block

A simple program called `web-safe-block` in rust, which does the following.

The idea is that you have a web server program running that may or may not be super hardened. Its port is not available to the outside world. The `web-safe-block` program will be connected to the internet on another port, and will forward requests to the protected web server in the following way.

`web-safe-block` will listen on its internet port, and for a new connection, send a very simple no-css HTML page with a single form with a text entry box, labeled "Phrase", and a button labeled "Submit" which submits the form.

Settings come from a `config.toml` file (`./config.toml` by default, or `-c path`). Users are stored in a sqlite3 database (set by `users_db` in the config), managed with the `add-user` and `remove-user` commands. Each user has a user name, a unique pass phrase, and an admin flag (set when the user name contains "admin"). When the html page submit happens with a phrase, all whitespace is removed and it is lower-cased, then it is looked up in the database.

When the input matches a user's phrase, then it sets a cookie with a large random value. For page requests from then on that have the cookie set with a value stored in memory, it passes the request on to the other progarm's port.

## Usage

```sh
cargo build --release

# Write ./config.toml with default values, then edit it.
./target/release/web-safe-block write-config

# Add users: one per line, "user-name pass phrase words...".
./target/release/web-safe-block add-user <<'EOF'
chris correct horse battery staple 42!
site-admin Purple Monkey Dishwasher, 1999.
EOF

./target/release/web-safe-block serve
```

Then point Cloudflare Tunnel (or another TLS terminator) at `http://127.0.0.1:8080`.

Every command accepts `-c path-to-config` (before or after the command name) to use a config file other than `./config.toml`:

```sh
web-safe-block -c /etc/web-safe-block/config.toml serve
```

### Configuration

`add-user` and `serve` exit with an error if the config file is missing, can't be parsed, is missing any setting, or contains an unknown one.

| Setting | Default | Meaning |
|---|---|---|
| `users_db` | `"users.db"` | sqlite3 users database. A relative path is relative to the config file's directory. |
| `listen_addr` | `"127.0.0.1:8080"` | Public-facing address web-safe-block listens on. |
| `upstream` | `"http://127.0.0.1:3000"` | Protected server (must be `http://` with no path). |
| `session_ttl_secs` | `604800` (7 days) | Session lifetime. |
| `cookie_secure` | `true` | Set to `false` to omit the `Secure` cookie flag (plain-http testing on a non-localhost host). |
| `monitor_addr` | `"127.0.0.1:8081"` | Local monitor port. Must be a loopback address. |
| `monitor_queue_len` | `1000` | How many unreported events are kept. |

### `write-config`

Writes a config file with all the default values above, with comments, to `./config.toml` or the `-c` path. It refuses to overwrite an existing file.

### `add-user`

Reads lines from stdin into the users database, creating it if needed. Each line is split on whitespace: the first word is the user name and the rest is the pass phrase.

- Pass phrases are normalized: all whitespace is removed and the phrase is lower-cased. `Open Sesame` and `opensesame` are the same phrase.
- New pass phrases must have at least 20 non-whitespace characters, at least one number, and at least one punctuation character. Lines with weaker phrases are reported and skipped.
- The database stores the hex SHA-512 of the normalized phrase, not the phrase itself.
- User names and pass phrases must both be unique, including against users already in the database.
- A user whose name contains `admin` (any case) is an admin.
- Blank lines are ignored. Bad lines (no phrase, duplicate name, phrase already in use) are reported on stderr and skipped. The other lines are still added, and the command exits with status 1 if anything was skipped.

### `remove-user`

`web-safe-block remove-user <user-name>` deletes that user and their sessions from the users database. It exits with an error if the database is missing or there is no such user. The user's pass phrase stops working immediately; a running `serve` drops their live sessions within 60 seconds.

### `list-users`

`web-safe-block list-users` prints one line per user — `user_name`, a tab, then `is_admin` (`true`/`false`) — sorted by name. It exits with an error if the users database is missing or empty.

### `serve`

Runs the proxy. It exits with an error if the users database is missing or has no users. Users added while the server is running can log in right away. Logins are logged to stdout with the user name.

Visit `/__wsb/logout` to get a log-out button, or POST to it to end the session. Cross-site POSTs to `/__wsb/` endpoints are rejected.

### Monitor port

`serve` also listens on `monitor_addr` (loopback only) and reports every request to the public port as one JSON object per line:

```sh
$ nc 127.0.0.1 8081
{"seq":4,"time":"2026-11-16T18:40:01Z","kind":"login_succeeded","status":303,"ip":"203.0.113.9","method":"POST","path":"/__wsb/login","user":"chris","user_agent":"Mozilla/5.0 ..."}
```

- `kind` is one of:
  - `login_page`: unauthenticated request, shown the form.
  - `login_failed`, `login_succeeded`, `login_error` (user lookup failed), `rate_limited`, `logout_page`, `logout`, `forbidden` (cross-site POST rejected).
  - `proxied`: authenticated request forwarded upstream; `status` is the upstream's, or 502/504.
  - `upgrade`: authenticated request with an `Upgrade` header; answered 501.
  - `reserved`: an unknown `/__wsb/` path.
  - `other`: e.g. wrong method or a malformed form.
- `ip` is `CF-Connecting-IP` if present, otherwise the peer address. `user` is set for `login_succeeded`, `proxied`, `logout_page` and `logout`.
- The request handlers add events to a bounded in-memory queue without blocking. A separate thread sends them to the monitor and marks them consumed only after they have been written.
- When the queue is full, the oldest events are overwritten.
  - With no monitor connected this happens silently. A monitor that connects later first receives whatever is still queued.
  - If events are overwritten before a connected monitor gets them, it receives `{"kind":"dropped","count":N}`.
- Only one monitor can be connected at a time. Another connection gets `{"error":"another monitor is already connected"}` and is closed.
- If the monitor client stops sending (e.g. `nc 127.0.0.1 8081 < /dev/null`), it gets a `{"kind":"heartbeat",...}` line every 10s while idle; this is how the server finds out when it has gone away.

## Security notes

- Bind the protected server to `127.0.0.1` so it is reachable only through web-safe-block.
- The session cookie `wsb_session` is `HttpOnly`, `SameSite=Lax`, and stripped from requests before they are forwarded; any `Set-Cookie` for `wsb_session` coming from the backend is dropped.
- Login attempts are limited to 10 failures per 15 minutes per client (keyed on `CF-Connecting-IP`, falling back to the peer IP), with a 1s delay on each failure. Because `CF-Connecting-IP` is trusted, don't expose `listen_addr` anywhere except to the tunnel.
- Sessions are kept in `users.db` as SHA-256 hashes of the cookie token (the raw token is never stored) and survive a restart; a fast in-memory map fronts the table. At most 3 live sessions per user (the oldest is dropped) and 10,000 in total are kept.
- Incoming `Forwarded`, `X-Forwarded-*` and `X-Real-IP` headers are discarded; the upstream gets `X-Forwarded-For` (the client IP), `X-Forwarded-Proto` (`https` if `cookie_secure`, else `http`) and `X-Forwarded-Host`.
- Upstream requests time out after 10s to connect and 60s waiting for response headers (504).
- Pass phrases are stored as unsalted SHA-512 hashes (lookup is by phrase alone, so a per-user salt isn't possible). This keeps phrases out of plain view if `users.db` leaks, but short or common phrases can still be brute-forced. `add-user` therefore enforces a minimum strength (see above); users added before that policy existed are not re-checked. Keep `users.db` private.
- WebSockets and other protocol upgrades are not supported in v1; authenticated requests with an `Upgrade` header are answered 501 and never forwarded.
- Paths under `/__wsb/` are reserved and never forwarded.
- Cookies are not port-scoped: other services on the same hostname will also receive `wsb_session`.
