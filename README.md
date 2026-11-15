# Web-Safe Block

A simple program called `web-safe-block` in rust, which does the following.

The idea is that you have a web server program running that may or may not be super hardened. Its port is not available to the outside world. The `web-safe-block` program will be connected to the internet on another port, and will forward requests to the protected web server in the following way.

`web-safe-block` will listen on its internet port, and for a new connection, send a very simple no-css HTML page with a single form with a text entry box, labeled "Phrase", and a button labeled "Submit" which submits the form.

There will be a env variable named `PASS_PHRASE` - and `web-safe-block` exits with an error if that phrase is not set. When it's set, and the html page submit happens with a phrase, it trims leading and trailing whitespace off of the input and compare it to the `PASS_PHRASE` value.

When the input matches the phrase, then it sets a cookie with a large random value. For page requests from then on that have the cookie set with a value stored in memory, it passes the request on to the other progarm's port.

## Usage

```sh
cargo build --release
PASS_PHRASE='correct horse battery staple' \
UPSTREAM=http://127.0.0.1:3000 \
LISTEN_ADDR=127.0.0.1:8080 \
./target/release/web-safe-block
```

Then point Cloudflare Tunnel (or another TLS terminator) at `http://127.0.0.1:8080`.

| Variable | Default | Meaning |
|---|---|---|
| `PASS_PHRASE` | (required) | Phrase that unlocks access. Exits with an error if unset or blank. |
| `UPSTREAM` | `http://127.0.0.1:3000` | Protected server (must be `http://`). |
| `LISTEN_ADDR` | `127.0.0.1:8080` | Address web-safe-block listens on. |
| `SESSION_TTL_SECS` | `604800` (7 days) | Session lifetime. |
| `COOKIE_SECURE` | `true` | Set to `false`/`0` to omit the `Secure` cookie flag (plain-http testing on a non-localhost host). |

Visit `/__wsb/logout` to end a session.

## Security notes

- Bind the protected server to `127.0.0.1` so it is reachable only through web-safe-block.
- The session cookie `wsb_session` is `HttpOnly`, `SameSite=Lax`, and stripped from requests before they are forwarded; any `Set-Cookie` for `wsb_session` coming from the backend is dropped.
- Login attempts are limited to 10 failures per 15 minutes per client (keyed on `CF-Connecting-IP`, falling back to the peer IP), with a 1s delay on each failure. Because `CF-Connecting-IP` is trusted, don't expose `LISTEN_ADDR` anywhere except to the tunnel.
- Sessions live in memory and are lost on restart.
- WebSockets are not supported in v1.
- Paths under `/__wsb/` are reserved and never forwarded.
- Cookies are not port-scoped: other services on the same hostname will also receive `wsb_session`.
