# ADR 0006 — Sessions persisted in users.db

Status: accepted (2026-11)

## Decision

Sessions are written through to a `sessions` table in `users.db` — `(user_name REFERENCES users ON DELETE CASCADE, cookie_string UNIQUE, timestamp)` — while the in-memory `HashMap` remains the fast lookup path. `cookie_string` is the hex SHA-256 of the cookie token; the raw token only ever travels in `Set-Cookie`. Caps are 3 sessions per user and 10,000 total; a new login evicts the earliest-expiring session from both the map and the table in one step. `serve` loads unexpired rows at startup and re-reads the whole table on its 60-second purge tick, which is also how a `remove-user` from another process kills that user's live sessions.

## Why

Deploys and crashes logged everyone out (the trade-off accepted in [0002](./0002-sessions-in-memory.md)), and `remove-user` revoked the phrase but left live sessions running until their TTL. Persistence fixes both: restart no longer clears the decks, and removing a user removes their sessions — picked up within one purge tick. Storing only the hash keeps `users.db` from becoming a list of live bearer tokens; the 3-per-user cap keeps the write-through small.

## Trade-off accepted

`remove-user` does not invalidate sessions instantly in a running `serve` — there is up to a 60-second lag until the next reload. And restart no longer clears sessions after an incident: to kill everything, `DELETE FROM sessions` (or remove the file and re-add users).

## Alternatives considered

- Keep memory-only sessions (0002): restart-clear is a nice incident property, but losing every login on each deploy and letting removed users keep surfing were judged worse.
- A separate sessions file or database: one more file to manage and back up; the sessions table is small and the FK to `users` keeps it consistent for free.
- Stateless signed cookies: still can't be revoked server-side — rejected again.
