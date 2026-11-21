# Agent notes

- Build/test on this machine: no `cc` on PATH; use `RUSTFLAGS="-C linker=gcc-16" CC=gcc-16 cargo test`.
- Checks: `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
- Atlas: edit `Notes/atlas/data.mjs`, then `bun Notes/atlas/build.mjs` (never hand-edit `atlas.html`/`SYSTEM.md`); preview with `cd Notes/atlas && python3 -m http.server 8777`.
