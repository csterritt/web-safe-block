# Agent notes

- This project uses `jj` instead of `git`. Please use `jj` commands when working with the repository.
- Build/test on macOS: plain `cargo test` works (system `/usr/bin/cc`); `gcc-16` is not installed.
- Checks: `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
- Atlas: edit `Notes/atlas/data.mjs`, then `bun Notes/atlas/build.mjs` (never hand-edit `atlas.html`/`SYSTEM.md`); preview with `cd Notes/atlas && python3 -m http.server 8777`.
