# ICMP Prober

## Role

Measures per-second round-trip latency to the active target IP using a hybrid socket strategy with subprocess fallback, feeding RTT samples to the anomaly detector, the store aggregates, and the JSONL log.

## Key Files

- `src/probe/icmp.rs` — `IcmpProber`, `IcmpResult`, `icmp_probe_loop`, `parse_ping_output`

## Behavior

### Strategy selection (once, at startup)

`IcmpProber::new(target, timeout)` selects the ICMP family from the target address (`ICMP::V6` for IPv6 targets, `ICMP::V4` otherwise), tries socket kinds in a fixed order and returns the chosen strategy:

```
kind = ICMP::V6 if target is IPv6 else ICMP::V4

Client::new(kind + sock_type_hint(DGRAM))  ok ──▶ IcmpStrategy::Unprivileged   (SOCK_DGRAM + IPPROTO_ICMP[6];
        │ fail                                                                works unprivileged on Linux
        ▼                                                                     with ping_group_range)
Client::new(kind + sock_type_hint(RAW))    ok ──▶ IcmpStrategy::Raw            (SOCK_RAW; needs CAP_NET_RAW/root)
        │ fail
        ▼
no client                                  ──▶ IcmpStrategy::Subprocess        (system `ping` command; macOS
                                                                                uses `ping6` for IPv6 targets —
                                                                                its `ping` rejects IPv6 literals)
```

The strategy is part of `session_start.config.icmp_strategy`; the startup `info!("ICMP strategy: …")` line surfaces transiently in the TUI logs panel (via `TuiTracingLayer`), and no panel renders the strategy itself.

### Single probe

`IcmpProber::ping(seq) -> Result<IcmpResult, ProbeError>`:

- **Surge path** (`Unprivileged`/`Raw`): `surge_ping` client, 56-byte payload, wrapped in `tokio::time::timeout(timeout_icmp_ms)`. On reply: extract TTL (V4 packets only), mark `status: Ok`. On an ICMP error that is not a lost packet (destination unreachable, time exceeded, malformed reply): `status: Error`, `rtt: None`. On the elapsed outer timeout: `status: Timeout`, `rtt: None`.
- **Subprocess path** (`Subprocess`): `ping -c 1 -W <wait>` (Unix — `<wait>` is seconds on Linux iputils but milliseconds on macOS/BSD) / `ping -n 1 -w <ms>` (Windows) via `tokio::process::Command`; the whole wait is additionally bounded by an outer `timeout(timeout_icmp_ms)` — a platform-agnostic backstop (macOS `ping6` takes no wait flag, and a wedged `ping` must not stall the loop) whose expiry maps to `status: Timeout`. Output parsed by `parse_ping_output` with regexes for macOS/Linux (`ttl=… time=… ms`) and Windows (`time=…ms TTL=…`) formats. Timeout indicators ("Request timed out", "Request timeout", "100% packet loss", "100.0% packet loss", "0 received", "0 packets received", "Destination Host Unreachable") map to `status: Timeout`.

`IcmpResult` carries duplicate/reorder flags:

```rust
pub struct IcmpResult {
    pub rtt: Option<Duration>, pub ttl: Option<u8>, pub seq: u16,
    pub status: IcmpStatus,              // Ok | Timeout | Error
    pub duplicate: bool,                 // seq already seen (HashSet<u16> seen_seqs)
    pub reordered: bool,                 // seq < last_seq (monotonic high-water mark)
}
```

Duplicate/reorder detection is only meaningful on the surge paths, where the reply echoes the session-unique sequence the client sent: the flags compare that echoed sequence against `seen_seqs`/`last_seq`. On the subprocess path both flags are always `false` — each one-shot `ping -c 1` is an independent process whose reply echoes that run's own constant counter (`icmp_seq=0` on macOS/BSD and `ping6`, `icmp_seq=1` on Linux iputils; Windows omits it entirely), so the echoed value carries no session-unique information.

### Probe loop

`icmp_probe_loop` per tick (interval `interval_icmp_ms`):

1. `store.inc_icmp_sent()` (write lock, released).
2. `prober.ping(seq)`.
3. On `Ok` with RTT: write lock — `push_icmp_rtt(ms)`, `inc_icmp_duplicate`/`inc_icmp_reordered` when flagged, run `detector.on_icmp_ok(rtt_ms)` (may yield `rtt_spike`/`jitter_spike`); on loss/timeout/error: `detector.on_icmp_loss()` (may yield `loss_burst`). Events go to `store.push_event` and `log_tx` (`LogRecord::Event`) before the probe record.
4. Send `LogRecord::Icmp(IcmpRecord)` — always, for every attempt.
5. `seq = seq.wrapping_add(1)`.

The loop waits in a `tokio::select!` biased toward cancellation and re-checks `cancel` before each probe; besides the tick it consumes two control signals:

- `ip_rx.changed()` retargets: `prober.update_target(new_ip)` (which also clears the duplicate/reorder tracking state), `seq` back to 0, and the `AnomalyDetector` is re-created — the previous target's RTT/jitter samples must not score the new endpoint's first samples.
- `reset_notify.notified()` (the TUI `r` hotkey) also re-creates the `AnomalyDetector` — `store.reset()` cleared the histories the detector's windows were built from. `icmp_probe_loop` is the only loop consuming `reset_notify`; the other loops' detectors are stateless `&self` checks with nothing to re-warm.

## Error Handling

- Probe failures never kill the loop: `Err(_)` from `prober.ping` produces an `IcmpRecord` with `status: Error` (no `rtt_ms`/`ttl`) and runs loss-burst detection; send errors to `log_tx` are ignored (`let _ =`).
- Subprocess parse failure returns `ProbeError::ParseError`, surfaced as `status: Error`.
- Channel send failures are ignored — the logger being gone must not stop monitoring.

## Invariants

1. The strategy is selected exactly once per process, at `IcmpProber::new`.
2. Every ICMP attempt (ok, timeout, or error) produces exactly one `icmp` JSONL record.
3. `duplicate`/`reordered` tracking state resets when the target IP changes (`update_target`); it persists across `seq` wrap-around — after a full 16-bit wrap, previously seen sequence numbers can re-flag as `duplicate` (bounded in practice by 65 536 tracked seqs).
4. TTL is recorded for IPv4 replies only (`None` for IPv6 — surge-ping exposes no V6 hop limit here).
5. Anomaly evaluation happens inline inside the loop, before the record send, using the same RTT sample pushed to the store.

## Related Specs

- [README.md](README.md) — domain-wide loop pattern and configuration table
- [../anomaly-detection.md](../anomaly-detection.md) — `on_icmp_ok` / `on_icmp_loss` detectors, warm-up rules
- [../../contracts/jsonl-log-format.md](../../contracts/jsonl-log-format.md) — `icmp` and `event` record schema
- [../../decisions/0002-hybrid-icmp-strategy.md](../../decisions/0002-hybrid-icmp-strategy.md) — why the fallback chain exists
