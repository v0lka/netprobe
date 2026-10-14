# Traceroute Prober

## Role

Periodically traces the network path to the active target IP (trippy ICMP traceroute on Unix, `tracert.exe` on Windows), maintains per-hop RTT statistics for anomaly detection, and diff-checks the hop list against the previous run to detect route changes.

## Key Files

- `src/probe/traceroute.rs` — `TracerouteProber`, `TracerouteResult`, `RouteChangeInfo`, `HopRttAnomalyInfo`, `traceroute_probe_loop`

## Behavior

### Implementation dispatch

`TracerouteProber::trace()` is synchronous and platform-dispatched at compile time:

- **Unix (`trace_unix`)**: `trippy_privilege::Privilege::discover()`; if `!has_privileges()` → error result `"Insufficient privileges. Run with sudo."`. Otherwise builds a `trippy_core` tracer: `Protocol::Icmp`, `PrivilegeMode::Privileged`, `max_rounds 10`, `first_ttl 1`, `max_ttl 30`, `max_inflight 24`. The tracer runs on a dedicated OS thread; the caller blocks on a channel with `recv_timeout(timeout_trace_ms)`, then snapshots `trippy_core::State` after a 500 ms settle sleep.
- **Windows (`trace_windows`)**: `tracert -h 30 -w <per-hop-ms> <ip>` via `std::process::Command` inside `tokio::task::block_in_place`; the per-hop wait `<per-hop-ms>` is derived from `--timeout-trace` (`timeout_trace_ms / 30`, floored at 100 ms) so the flag bounds Windows traces too; output parsed with regexes (IPv4 addresses, `<n> ms` RTTs — averaged per hop).

> Note: `TracerouteProber::new()` performs privilege discovery up front on Unix (`trippy_privilege::Privilege::discover()`) and fails with `ProbeError::PermissionDenied` when raw-socket privileges are missing; on Windows it always succeeds (`tracert.exe` needs no privileges). The `traceroute_available` flag recorded in `session_start` (set from `TracerouteProber::new(...).is_ok()` in `app.rs`) therefore reflects real privileges, the traceroute task is spawned only when the flag is set, and the trace panel renders the "unavailable" state instead of probing (see [ADR-0006](../../decisions/0006-traceroute-startup-privilege-gating.md), which supersedes [ADR-0005](../../decisions/0005-traceroute-privilege-gating.md)). The per-trace check inside `trace_unix` remains as a safety net for privileges dropped mid-session.

### Per-hop processing

For every hop (Unix: `state.hops()` → `ttl`, `last_ms()` RTT, first address; Windows: parsed line):

1. Update `hop_rtt_stats`, keyed by **hop IP** (`Option<IpAddr>`) — a `WindowedWelford::hop` (window 10 samples); if the path changes and this TTL now resolves to a different router, the new router starts a fresh window instead of inheriting the old router's samples.
2. If the window is warm and `|(rtt - mean)/stddev| > 2.0` → collect `HopRttAnomalyInfo { hop, ip, rtt_ms, mean, stddev, sigma }`.
3. Build `HopData { hop, rtt_ms: Option<f64>, ip: Option<IpAddr>, host: Option<String> }` — `host` is currently `None` on Unix (no reverse DNS in this path) and set to the IP string on Windows.

### Route-change detection

`detect_route_change(current_hops)` compares the runs position-wise and considers only hops where **both** runs have an answered IP (`Some(ip)` — a router that rate-limits or filters Time-Exceeded for a single trace is "unknown", not a changed address):

- First run, or no answered hop changed its address → `None`.
- A pure hop-count difference (hops appearing or going silent) is not a change by itself.
- An answered hop whose IP differs from the previous run's IP at the same position → `"Route changed at hop k: <new-ip>"` for each differing position (Display-formatted new IP), joined after `"Route changed at "`.

`previous_hops` is updated after every completed run.

### Probe loop (`traceroute_probe_loop`)

The loop owns an `AnomalyDetector` and waits in a `tokio::select!` biased toward cancellation:

- `cancel.cancelled()` breaks the loop; cancellation is re-checked before probing.
- `ip_rx.changed()` retargets the prober via `TracerouteProber::update_target` (route history and hop statistics reset).
- `notify.notified()` forces an immediate trace (the TUI `t` hotkey notifies).
- `interval.tick()` fires every `interval_trace_sec`.

After each trace it, in order:

1. Updates the store: `store.set_latest_traceroute(trace_data, result.error)` — `trace_data` is `Some(TracerouteData { hops })` on a successful trace and `None` on a failed one (the slot keeps the data-XOR-error invariant: `data.is_some()` reliably means "the last trace succeeded").
2. Publishes a `route_change` event when `detect_route_change` reports one, and one `hop_rtt_anomaly` event per anomalous hop — each through the anomaly detector, pushed into the store's events deque and sent as a `LogRecord::Event`.
3. Sends exactly one `LogRecord::Traceroute` per attempt, including error attempts (`status: error`, empty `hops`).

Log send failures are ignored (`let _ =`) — a dead logger must not stop probing.

## Error Handling

- Construction fails on Unix when raw-socket privileges are missing (`ProbeError::PermissionDenied`) or privilege discovery itself errors (`ProbeError::Other`); `app.rs` turns a construction failure into `traceroute_available: false` in the store and in `session_start`, and no traceroute task is spawned.
- Every per-trace failure mode (missing privileges, builder failure, run failure, timeout, thread disconnect) becomes a `TracerouteResult { status: Error, error: Some(msg), hops: [] }`; the store's latest-error slot displays it, the attempt is recorded in the JSONL log, and the loop continues on the next tick.
- A trace longer than `timeout_trace_ms` is abandoned: the worker OS thread finishes in the background (trippy's blocking `run()` cannot be cancelled) and its result is dropped, but the prober refuses to start a new trace while that worker is still running — the next round returns an error result ("Previous traceroute still running …") instead of leaking one thread per tick.

## Invariants

1. Traceroute state published to the TUI always comes from the last completed run (full replacement via `set_latest_traceroute`).
2. Per-hop statistics persist across runs in `hop_rtt_stats` and reset only when the prober is recreated (process lifetime) or the target IP changes (`update_target`).
3. Route-change comparison is position-wise over answered IPs only: `route_change` fires exclusively when a hop that answered in both runs changed its address between them; non-answers ("unknown" hops), RTT changes, and pure hop-count differences never fire the event.
4. Hop RTT anomalies use the 2σ threshold with the 10-sample window and its warm-up (see [../anomaly-detection.md](../anomaly-detection.md)).
5. Retargeting clears the route history: the first run against a new target never reports a route change against the old target's route.
6. Every trace attempt — successful or failed — writes exactly one `traceroute` record to the JSONL log.

## Extension Points

- **Reverse DNS for hops**: populate `HopData.host` on the Unix path.
- **Privilege-gained mid-session traceroute**: the task spawns only when construction finds privileges; re-scanning privileges inside the running loop would require a new control signal.

## Related Specs

- [README.md](README.md) — loop pattern, configuration table
- [../anomaly-detection.md](../anomaly-detection.md) — `WindowedWelford::hop`, warm-up
- [../metrics-store.md](../metrics-store.md) — `latest_traceroute` slot and `TracerouteData`
- [../../decisions/0006-traceroute-startup-privilege-gating.md](../../decisions/0006-traceroute-startup-privilege-gating.md) — privilege model
