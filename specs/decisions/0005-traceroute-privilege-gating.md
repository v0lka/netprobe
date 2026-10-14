# ADR-0005: Traceroute degrades, never crashes or blocks the session

## Status

Superseded by [0006](./0006-traceroute-startup-privilege-gating.md)

## Context

Traceroute (unlike ping) has no unprivileged socket path on Unix — raw ICMP/UDP needs `CAP_NET_RAW`/root. A monitoring session must not fail to start, and must not hang, when privileges are missing. Windows offers `tracert.exe` with no privileges at all. The original design doc prescribed a hard startup disable (no traceroute task, panel shows "unavailable", flag in `session_start`).

## Decision

Traceroute is **best-effort with graceful degradation**:

- The traceroute task always spawns (Unix: trippy-core ICMP prober; Windows: `tracert.exe` parsing).
- `TracerouteProber` construction cannot fail; the privilege check (`trippy_privilege::Privilege::discover()`) happens per trace on Unix — missing privileges yield an error result ("Insufficient privileges. Run with sudo.") that lands in the store's traceroute error slot and renders in the trace panel.
- Traces run on a dedicated OS thread bounded by `--timeout-trace` (default 30 s); timeouts abandon the round without killing the task.
- The session always starts; `traceroute_available` is recorded in `session_start` (with the current implementation it is always `true` — the real gating is per-trace; see [../domains/probing/traceroute.md](../domains/probing/traceroute.md) for the documented divergence from the design doc).

## Consequences

Positive:

- Monitoring (ICMP/DNS/TCP/TLS/HTTP) never depends on traceroute privileges — the common unprivileged case still yields a fully useful session.
- Per-trace checking tolerates privilege changes and avoids false startup decisions (e.g. capabilities present but seccomp-blocked).
- Windows gets traceroute with no special handling beyond output parsing.

Negative:

- The trace panel on an unprivileged Unix host shows a persistent error instead of being hidden (the design doc's original UX).
- `traceroute_available` in `session_start` is currently not a reliable privilege signal for log consumers; per-trace errors are not in the JSONL file at all (loop writes store only).
- A timed-out trace leaks a worker thread per occurrence (bounded by cadence; acceptable at 60 s intervals).

## Alternatives Considered

- **Hard startup disable (design-doc original)** — rejected in favor of per-trace checking because `TracerouteProber::new` has no natural failure mode; implementing the original would require moving the `Privilege::discover()` probe into construction (a small, planned change — see the domain spec's extension notes).
- **Fallback to TCP/UDP traceroute without privileges** — rejected for v1: different hop semantics, most intermediate routers drop non-ICMP probes.
- **Subprocess `traceroute`/`tracepath` on Unix (mirroring Windows)** — rejected: `tracepath` lacks TTL control, `traceroute` has the same privilege need as trippy.

## Related Specs

- [../domains/probing/traceroute.md](../domains/probing/traceroute.md) — implementation, divergences, extension points
- [../domains/tui/panels-and-layout.md](../domains/tui/panels-and-layout.md) — how the trace panel renders the error slot
