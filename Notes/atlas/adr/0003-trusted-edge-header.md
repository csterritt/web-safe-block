# ADR 0003 — CF-Connecting-IP is trusted; the listener faces only the tunnel

Status: accepted (2026-11)

## Decision

The client IP for rate limiting and event logs is `CF-Connecting-IP` when it parses as an IP, else the TCP peer address. Correspondingly, `listen_addr` is deployment-guarded, not code-guarded: it must only ever be reached through the tunnel/TLS terminator.

## Why

Behind Cloudflare Tunnel the TCP peer is always a local tunnel process, so the peer address alone can't distinguish visitors. The header is the only source of the real client IP — and it's only honest if clients can't reach the port themselves.

## Consequences

- If `listen_addr` is exposed to the internet, `CF-Connecting-IP` becomes attacker-controlled: rate-limit evasion and forged event IPs. Open question Q-T1 asks whether the gate should only honor the header from the tunnel's peer address.
- Related hardening already landed: inbound `Forwarded`, `X-Forwarded-*`, `X-Real-IP` are discarded and rebuilt from verified values before forwarding (review-1 finding 1).

## Alternatives considered

- Verify the tunnel by peer address range or shared secret header: more config knobs for the same guarantee; deferred unless the deployment gets more complicated.
