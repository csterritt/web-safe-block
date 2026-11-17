# ADR 0001 — The pass phrase is the whole credential

Status: accepted (2026-11)

## Decision

Login takes a pass phrase and nothing else — no username field. A submitted phrase is normalized (whitespace stripped, lower-cased), SHA-512'd, and looked up directly in `users.db`; the matching row *is* the user. The database stores the unsalted hash, never the phrase. `add-user` enforces strength: ≥20 non-whitespace characters, at least one digit, at least one punctuation character.

## Why

The design goal was the simplest possible gate: one text box, one secret. A username + password pair would be a bigger surface for a marginal gain, since a phrase long enough to be unique doubles as the identifier.

## Trade-off accepted

- Unsalted, unsalted SHA-512 is fast, so a leaked `users.db` permits offline dictionary attacks. A per-user salt is *impossible* here: lookup is by phrase alone, so there is no name to salt against before hashing. Mitigation is the add-time strength policy and keeping `users.db` private — documented in README security notes.
- Phrases can't be scoped or rotated per user through the CLI yet (no `remove-user`); revocation means editing sqlite by hand. Tracked as open question Q-U1 in the atlas.

## Alternatives considered

- Username + per-user salted slow hash (bcrypt/argon2): stronger at rest, but two fields on the form and per-user lookup — rejected as more machinery than the threat model needs today.
- HMAC with a server-side secret (keyed lookup tag): would blind the table without changing the form, but needs a second secret store — noted as a possible follow-up, not taken.
