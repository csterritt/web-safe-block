## Notes from the sixth review code implementation

Decisions:

- `max_header_size`, `max_buf_size` and `max_connections` are new required settings (16384 / 16384 / 100). Old config files must add them.
- The monitor `path` is the URL path only. A trailing `?` shows that a query was present, but never what it contained.
- `list-users` on an empty database is an error, which matches the README.
- Every request must have exactly one valid `Host`, whatever the HTTP version.
- The unix monitor socket is guarded by a flocked `.<name>` directory next to it. The socket is bound inside that directory, then hard-linked into place.

Left alone on purpose:

- The temporary socket path `.<name>/s` is 3 bytes longer than the final path. A final path within 3 bytes of the `sun_path` limit fails, and the bind error names the temporary path.
- Hard-linking a unix socket was only tested on Linux; it hasn't been checked on macOS.
- Non-Unix builds and clippy aren't covered by any test run here.
- Rate-limit refunds pop the newest timestamp rather than the exact attempt being refunded.
- `reload_sessions` trusts the rows in the database and doesn't re-check the caps.
- Splitting `src/monitor.rs` and `tests/proxy.rs` into smaller files, and a consistent logging convention.
- Cookie-tossing docs, and the long default session TTL.
- A test for `max_login_waiters` saturation.
