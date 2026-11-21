# Agent notes

- Build/test on this machine: no `cc` on PATH; use `RUSTFLAGS="-C linker=gcc-16" CC=gcc-16 cargo test`.
- Checks: `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
- `tests/proxy.rs` `monitor_reports` and `monitor_half_closed_client` fail here ("monitor slot never freed") on clean HEAD too (2026-11-21).
- Atlas: edit `Notes/atlas/data.mjs`, then `bun Notes/atlas/build.mjs` (never hand-edit `atlas.html`/`SYSTEM.md`); preview with `cd Notes/atlas && python3 -m http.server 8777`.
