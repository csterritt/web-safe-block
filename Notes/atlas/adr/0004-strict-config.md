# ADR 0004 — Strict config: every setting required, unknown keys rejected

Status: accepted (2026-11)

## Decision

`config.toml` must contain all eight settings (`users_db`, `listen_addr`, `upstream`, `front_page_message`, `session_ttl_secs`, `cookie_secure`, `monitor_addr`, `monitor_queue_len`); `serde(deny_unknown_fields)` rejects anything extra. `write-config` emits a commented template and refuses to overwrite. A relative `users_db` resolves against the config file's directory. `monitor_addr` must be loopback or `unix:/absolute/path` (socket created 0600; added 2026-11-23); `upstream` must be `http://` with no path, or `unix:/absolute/path` (added 2026-11-23).

## Why

For a security boundary, silent defaults are how deployments end up permissive by accident. Requiring every setting means the operator reads — or at least sees — each knob once. Refusing unknown keys catches typos like `listen_port` that would otherwise be ignored.

## Trade-off accepted

Adding a setting later forces every existing config to add a line; there are no env-var overrides. Acceptable for a single-instance tool with one config file.
