# ADR 0003 — CF-Connecting-IP is trusted only from a loopback peer

Status: accepted (2026-11); amended 2026-11-21 (Q-T1, option A)

## Decision

The client IP for rate limiting, event logs and `X-Forwarded-For` is `CF-Connecting-IP` **only when the TCP peer is a loopback address** (`127.0.0.0/8`, `::1`, or IPv4-mapped loopback) and the header parses as an IP; otherwise it is the TCP peer address. `serve` prints a warning at startup when `listen_addr` is not a loopback address. No config setting was added.

## Why

Behind Cloudflare Tunnel the TCP peer is always the local `cloudflared` process, so the peer address alone can't distinguish visitors. The header is the only source of the real client IP — and it's only honest if it came through the tunnel. Originally (2026-11) this was guarded by deployment alone: `listen_addr` must never be reachable except via the tunnel. If it ever was, a direct client could send a fresh fake `CF-Connecting-IP` per request, getting a new 10-per-15-minutes login budget each time and forging event IPs. Checking the peer makes the code enforce what the deployment rule assumed.

## Consequences

- `cloudflared` must run on the same machine. A tunnel on another host or in a Docker container (non-loopback peer) makes every visitor share that peer's address: one rate-limit budget, one IP in the logs.
- Any local process can still set the header; local users are trusted.
- Exposing `listen_addr` is no longer a rate-limit bypass, but it is still not recommended (warned at startup).
- Related hardening already landed: inbound `Forwarded`, `X-Forwarded-*`, `X-Real-IP` are discarded and rebuilt from verified values before forwarding (review-1 finding 1).

## Alternatives considered

- Trust the header from any peer, deployment-guarded (the original decision): one misconfigured bind or firewall rule silently disables the rate limit.
- A `trusted_proxies` CIDR setting (option B): supports remote/Docker tunnels, but adds a required setting under the strict-config rule (ADR 0004), forcing every existing `config.toml` to be edited. Deferred until a non-local tunnel is needed.
- A shared-secret header from the tunnel: more moving parts for the same guarantee.
