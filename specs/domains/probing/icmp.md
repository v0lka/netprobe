# ICMP Prober

## Role

Measures per-second round-trip latency to the active target IP using a hybrid socket strategy with subprocess fallback, feeding RTT samples to the anomaly detector, the store aggregates, and the JSONL log.

## Key Files

- `src/probe/icmp.rs` — `IcmpProber`, `IcmpResult`, `icmp_probe_loop`, `parse_ping_output`

## Behavior

### Strategy selection (once, at startup)

`IcmpProber::new(target, timeout)` tries socket kinds in a fixed order and returns the chosen strategy:

```
Client::new(sock_type_hint(DGRAM))   ok ──▶ IcmpStrategy::Unprivileged   (SOCK_DGRAM + IPPROTO_ICMP;
        │ fail                                                               works unprivileged on Linux
        ▼                                                                    with ping_group_range)
Client::new(sock_type_hint(RAW))     ok ──▶ IcmpStrategy::Raw            (SOCK_RAW; needs CAP_NET_RAW/root)
        │ fail
        ▼
no client                            ──▶ IcmpStrategy::Subprocess        (system `ping` command)
```

The strategy is part of `session_start.config.icmp_strategy` and displayed in the TUI.

### Single probe

`IcmpProber::ping(seq) -> Result<IcmpResult, ProbeError>`:

- **Surge path** (`Unprivileged`/`Raw`): `surge_ping` client, 56-byte payload, wrapped in `tokio::time::timeout(timeout_icmp_ms)`. On reply: extract TTL (V4 packets only), mark `status: Ok`. On ICMP error or timeout: `status: Timeout`, `rtt: None`.
- **Subprocess path** (`Subprocess`): `ping -c 1 -W <sec>` (Unix) / `ping -n 1 -w <ms>` (Windows) via `tokio::process::Command`; output parsed by `parse_ping_output` with regexes for macOS/Linux (`ttl=… time=… ms`) and Windows (`time=…ms TTL=…`) formats. Timeout indicators ("Request timed out", "100% packet loss", "0 received", "Destination Host Unreachable") map to `status: Timeout`.

`IcmpResult` carries duplicate/reorder flags:

```rust
pub struct IcmpResult {
    pub rtt: Option<Duration>, pub ttl: Option<u8>, pub seq: u16,
    pub status: IcmpStatus,              // Ok | Timeout | Error
    pub duplicate: bool,                 // seq already seen (HashSet<u16> seen_seqs)
    pub reordered: bool,                 // seq < last_seq (monotonic high-water mark)
}
```

### Probe loop

`icmp_probe_loop` per tick (interval `interval_icmp_ms`):

1. `store.inc_icmp_sent()` (write lock, released).
2. `prober.ping(seq)`.
3. On `Ok` with RTT: write lock — `push_icmp_rtt(ms)`, `inc_icmp_duplicate`/`inc_icmp_reordered` when flagged, run `detector.on_icmp_ok(rtt_ms)` (may yield `rtt_spike`/`jitter_spike`); on loss/timeout/error: `detector.on_icmp_loss()` (may yield `loss_burst`). Events go to `store.push_event` and `log_tx` (`LogRecord::Event`) before the probe record.
4. Send `LogRecord::Icmp(IcmpRecord)` — always, for every attempt.
5. `seq = seq.wrapping_add(1)`.

The loop also watches `ip_rx` (TUI IP switch): on change it calls `prober.update_target(new_ip)` and resets `seq` to 0 (which also clears duplicate/reorder tracking).

## Error Handling

- Probe failures never kill the loop: `Err(_)` from `prober.ping` produces an `IcmpRecord` with `status: Error` (no `rtt_ms`/`ttl`) and runs loss-burst detection; send errors to `log_tx` are ignored (`let _ =`).
- Subprocess parse failure returns `ProbeError::ParseError`, surfaced as `status: Error`.
- Channel send failures are ignored — the logger being gone must not stop monitoring.

## Invariants

1. The strategy is selected once per process and never re-negotiated.
2. Every ICMP attempt (ok, timeout, or error) produces exactly one `icmp` JSONL record.
3. `duplicate`/`reordered` tracking state resets when the target IP changes or `seq` wraps through 0.
4. TTL is recorded for IPv4 replies only (`None` for IPv6 — surge-ping exposes no V6 hop limit here).
5. Anomaly evaluation happens inline inside the loop, before the record send, using the same RTT sample pushed to the store.

## Related Specs

- [README.md](README.md) — domain-wide loop pattern and configuration table
- [../anomaly-detection.md](../anomaly-detection.md) — `on_icmp_ok` / `on_icmp_loss` detectors, warm-up rules
- [../../contracts/jsonl-log-format.md](../../contracts/jsonl-log-format.md) — `icmp` and `event` record schema
- [../../decisions/0002-hybrid-icmp-strategy.md](../../decisions/0002-hybrid-icmp-strategy.md) — why the fallback chain exists
