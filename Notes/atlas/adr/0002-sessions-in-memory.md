# ADR 0002 — Sessions live in memory only

Status: accepted (2026-11)

## Decision

Sessions are a `HashMap` in the process: token → {user, expiry}. Caps are 10 sessions per user and 10,000 total (oldest evicted); an in-task sweep drops expired entries every 60 seconds. Nothing is written to disk, so a restart logs everyone out.

## Why

The box guards one app for a handful of people. In-memory keeps `serve` single-file, adds no schema migration or file lifecycle, and gives a pleasant security property: **restart clears the decks** — after an incident or a config change, every token in circulation dies.

## Trade-off accepted

Deploys and crashes log everyone out. For a small user base with pass phrases they already have, re-login is cheap. If it becomes annoying, the atlas keeps a ghost ("Saved sessions", question Q-P1) describing a write-through store next to `users.db`.

## Alternatives considered

- Persist sessions in `users.db`: simple, but mixes durable identity with volatile tokens and complicates the read-only `UserStore`.
- Signed stateless cookies (no server state): can't be revoked server-side and puts trust in a signing key — rejected.
