# ADR-0006: Traceroute privilege gating at startup with accurate `traceroute_available`

## Status

Accepted

## Context

[ADR-0005](./0005-traceroute-privilege-gating.md) chose per-trace-only privilege checking: `TracerouteProber::new` construction could not fail, `Privilege::discover()` ran inside `trace_unix`, and the traceroute task always spawned. That decision produced three documented negative consequences:

- `traceroute_available` in `session_start` was always `true` — not a reliable privilege signal for log consumers.
- The trace panel on an unprivileged Unix host showed a persistent per-run error instead of an explicit "unavailable" state (platform-specific privilege hint included).
- Traceroute results never reached the JSONL file (the probe loop wrote the store only), so per-trace errors were invisible to log consumers.

Meanwhile `architecture/concurrency.md` invariant 6 already specified the intended behavior: the traceroute task's existence must match the `traceroute_available` flag recorded in `session_start`. The domain spec flagged both divergences as the extension point "wire `log_tx`, `notify`, and `ip_rx` into `traceroute_probe_loop`".

## Decision

- `TracerouteProber::new` performs `trippy_privilege::Privilege::discover()` at construction on Unix. Without raw-socket privileges (root or `cap_net_raw`) it fails with `ProbeError::PermissionDenied`; a discovery error fails with `ProbeError::Other`. On Windows construction always succeeds (`tracert.exe` needs no privileges).
- `app.rs` derives `traceroute_available` from the construction result. The store slot, the `session_start` record, the TUI trace panel's "unavailable" rendering, and the spawn gate (`if traceroute_available`) all follow the same flag — the task exists if and only if the flag is set (concurrency invariant 6).
- The per-trace privilege check inside `trace_unix` remains as a safety net for privileges dropped mid-session.
- `traceroute_probe_loop` now uses its full parameter set: one `TracerouteRecord` per attempt is written to the JSONL log (error attempts included, with `status: error` and empty `hops`), `route_change` and `hop_rtt_anomaly` findings go through `AnomalyDetector` into the store events deque and the JSONL as `event` records, the `t` hotkey forces an out-of-schedule trace via `Notify`, and `ip_rx` retargets the prober (`update_target` resets route history and hop statistics).

## Consequences

Positive:

- `traceroute_available` in `session_start` is a reliable privilege signal for log consumers.
- The trace panel shows an "unavailable: insufficient privileges" state with a platform-specific hint instead of a stream of per-run errors.
- Traceroute attempts and route-change/hop-anomaly events are present in the JSONL file; `traceroute_available: false` sessions are explainable from the log alone.
- Unprivileged sessions still start and monitor ICMP/DNS/TCP/TLS/HTTP — ADR-0005's core "session never fails to start" guarantee is preserved.

Negative:

- Privileges granted after startup (e.g. `setcap` applied or a sudo re-launch consideration) do not spawn the traceroute task until restart; per-trace checking tolerates privileges being dropped, not gained.
- Privilege discovery runs at two startup sites (the availability probe `TracerouteProber::new(...).is_ok()` and the spawn-time construction) plus once per trace as the safety-net check inside `trace_unix`.

## Alternatives Considered

- **Keep per-trace-only gating (ADR-0005 as-is)** — rejected: the flag stayed unreliable and the "unavailable" UX and JSONL traceroute records remained unreachable without wiring the loop anyway.
- **Accurate flag but always spawn the task** — rejected: the trace panel would simultaneously render "unavailable" (from the flag) and stream per-run error results, and unprivileged traces would burn CPU on doomed raw-socket attempts every interval.
- **Broader capability probing beyond `trippy_privilege` (seccomp/landlock awareness)** — rejected: no evidence of need; the per-trace safety net still catches exotic denials as error results.

## Related Specs

- [../domains/probing/traceroute.md](../domains/probing/traceroute.md) — implementation, probe loop, extension points
- [../architecture/concurrency.md](../architecture/concurrency.md) — task existence invariant
- [../contracts/jsonl-log-format.md](../contracts/jsonl-log-format.md) — `traceroute` and `event` record schemas
