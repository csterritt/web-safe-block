# ADR 0005 — One monitor client, bounded queue

Status: accepted (2026-11)

## Decision

The monitor is a loopback-only TCP port serving JSON-lines events to exactly one client at a time; additional connections get a busy error and close. The event queue is bounded (`monitor_queue_len`, default 100) and overwrites the oldest events when full — reported to a connected monitor as `{"kind":"dropped","count":N}`. Events are marked consumed only after being written to the socket.

## Why

The monitor is a debugging peephole, not a metrics pipeline. One client keeps ordering trivially simple (a single seq stream), and the bounded queue means request handling never blocks on observability — the failure mode is losing history, not slowing the gate.

## Trade-off accepted

- Only one watcher at a time (no fan-out).
- Events dropped while nobody is watching vanish silently; open question Q-Q1 asks whether that count should be surfaced to the next monitor.
- Loopback is the only access control; open question Q-M1 asks whether any local process should be able to watch.
