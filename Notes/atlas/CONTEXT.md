# web-safe-block — Context (glossary)

The nouns, one line each. Edited by hand; everything else in this folder is generated.

- **pass phrase** — the only credential: a multi-word secret typed into the login form; identifies the user all by itself (no username on the wire)
- **normalized phrase** — the phrase with all whitespace removed, lower-cased; "Open Sesame" and "opensesame" are the same phrase
- **users.db** — the sqlite file holding one row per user: name, hex SHA-512 of the normalized phrase, admin flag; managed by `add-user`, `remove-user`, and `list-users`
- **session** — a random 32-byte hex token mapped to a user name and expiry; lives in memory only, carried by the browser as the `wsb_session` cookie
- **the gate** — the public listener and its handlers: phrase form, login, logout, session check, forward-or-refuse
- **upstream** — the protected web server, always `http://` on loopback; only reachable through the gate
- **the tunnel** — the TLS terminator in front of the public port (e.g. Cloudflare Tunnel); stamps `CF-Connecting-IP`
- **client IP** — `CF-Connecting-IP` when present and parseable, else the TCP peer address; used for rate limiting and event logs
- **reserved namespace** — `/__wsb/*`: login, logout, and nothing else; never forwarded upstream
- **failure ledger** — the per-client-IP list of recent failed logins; 10 within 15 minutes → "too many attempts"
- **event** — one record per request: `{seq, time, kind, status, ip, method, path, user?, user_agent?}`; pushed to the bounded queue
- **monitor** — the loopback TCP port streaming events as JSON lines to a single connected client
- **admin flag** — `is_admin`, set when a user name contains "admin" (any case); shown by `list-users` but still unused for authorization in `serve`
- **ghost** — a structure on the atlas that is designed but not built (WebSocket relay, saved sessions)
