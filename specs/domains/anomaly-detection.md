# Anomaly Detection

## Purpose

Real-time anomaly detection over streaming probe metrics. All logic is pure (`src/anomaly.rs` depends only on `models`): sliding-window statistics (`WindowedWelford`) plus an `AnomalyDetector` facade that probe loops call after each sample. Detected anomalies become `event` JSONL records and entries in the store's events deque.

## Key Files

- `src/anomaly.rs` — `WindowedWelford`, `AnomalyDetector`, `AnomalyEvent`
- `src/probe/icmp.rs`, `src/probe/dns.rs`, `src/probe/tcp.rs` — call sites (ICMP/DNS/TLS/HTTP triggers)
- `src/probe/traceroute.rs` — per-hop statistics (uses `WindowedWelford::hop` directly)

## Core Types

```rust
pub struct WindowedWelford { /* VecDeque buffer, window_size, warm_up, count, mean, m2 */ }
impl WindowedWelford {
    pub fn new(window_size: usize, warm_up: usize) -> Self;
    pub fn icmp() -> Self;   // window 60, warm-up 30
    pub fn hop() -> Self;    // window 10, warm-up 5
    pub fn push(&mut self, value: f64);   // evict oldest, re-add via Welford
    pub fn mean(&self) -> f64;
    pub fn stddev(&self) -> f64;          // sample stddev (n-1); 0.0 below 2 samples
    pub fn is_warm(&self) -> bool;        // count >= warm_up
}

pub struct AnomalyEvent {
    pub event_type: String, pub severity: Severity,
    pub value: Option<f64>, pub threshold: Option<f64>, pub sigma: Option<f64>,
    pub message: String,
}
```

**Window semantics (verified against implementation):** on eviction the statistics are recomputed from the remaining window contents (O(n) per evicted sample, n ≤ 60 — not amortized O(1)). Detection activates once `count >= warm_up`; between warm-up and full window, mean/σ are computed over the samples collected so far.

## Detectors

| Trigger | Detector | Event | Severity | Rule |
| ------- | -------- | ----- | -------- | ---- |
| ICMP success | `on_icmp_ok(rtt)` | `rtt_spike` | Warning | `\|(rtt − mean) / σ\| > 3.0` over the 60-sample RTT window (fires on unusually **low** RTT too — the check is on the absolute sigma) |
| ICMP success | `on_icmp_ok(rtt)` | `jitter_spike` | Warning | same rule on `jitter = |rtt − last_rtt|`, own 60-sample window |
| ICMP loss/timeout/error | `on_icmp_loss()` | `loss_burst` | Critical | 3 consecutive losses; fires once per burst (a success resets the counter) |
| DNS IP-set change | `on_dns_change(old, new)` | `dns_change` | Info | lists added/removed IPs in the message |
| Route change | `on_route_change(desc)` | `route_change` | Warning | invoked by the traceroute loop on every `detect_route_change` report |
| Per-hop RTT | `on_hop_rtt_anomaly(...)` | `hop_rtt_anomaly` | Warning | invoked per anomalous hop; `TracerouteProber` computes anomalies with `WindowedWelford::hop` (2σ, warm-up 5) |
| TLS handshake | `on_cert_expiry(days)` | `cert_expiry_warning` | Warning / Critical | `days < 30` → Warning; `days < 7` → Critical; evaluated on every successful handshake |
| HTTP response | `on_http_error(code, msg)` | `http_error` | Critical | status ≥ 400 or failed request |
| TCP connect | `on_tcp_refused(msg)` | `tcp_refused` | Critical | connection refused |

## Flow

```
probe sample ──▶ detector.on_*() ──▶ Vec<AnomalyEvent>
                                        │ per event:
                                        ├─▶ store.push_event(type, severity, message)   (events deque, max 200)
                                        └─▶ detector.to_event_record(&e, target)
                                              └─▶ log_tx.send(LogRecord::Event(record))  (JSONL + TUI events panel)
```

- ICMP loop: `on_icmp_ok` on success (after `push_icmp_rtt`), `on_icmp_loss` on timeout/error.
- DNS loop: `on_dns_change` only when `DnsResult.change_info` is present.
- TCP pipeline: `on_cert_expiry` per handshake, `on_http_error` per HTTP failure/4xx+, `on_tcp_refused` on refused connects.

## Error Handling

Detection never fails: every method returns an event or an empty vector. Statistics states (e.g. `stddev == 0`) suppress the sigma checks rather than panicking.

## Invariants

1. `anomaly.rs` stays pure — all state lives in its own fields; probes own the trigger points.
2. `rtt_spike`/`jitter_spike` activate at 30 samples (`is_warm`); `loss_burst` fires from the first sample.
3. A successful probe resets `consecutive_losses` to 0.
4. Detector statistics update **after** the checks, so the current sample never contributes to its own baseline.
5. Both spike detectors use the same sample count and windows (60/30); per-hop statistics are independent per hop (keyed by hop IP) and reset when the prober is recreated or the target IP changes (`update_target` clears `hop_rtt_stats`).
6. Every published event goes to both the store deque and the logger channel.

## Configuration

All detector knobs are compile-time constants in `src/anomaly.rs` — no runtime options:

- `WindowedWelford::icmp()`: window 60, warm-up 30 (used by both the RTT and the jitter windows).
- `WindowedWelford::hop()`: window 10, warm-up 5.
- `rtt_spike`/`jitter_spike` rule: `|(value − mean) / σ| > 3.0` (absolute sigma — fires on unusually low values too).
- `hop_rtt_anomaly` rule: `|(value − mean) / σ| > 2.0` per hop.
- `loss_burst`: fires at 3 consecutive losses (inline literal `3`), once per burst — consecutive losses beyond the third do not re-fire (the counter keeps counting; a success resets it).
- `cert_expiry_warning`: Warning below 30 days, Critical below 7 days (inline literals).

## Extension Points

To add a detector:

1. Add a pure `on_*(&mut self, ...) -> Option<AnomalyEvent>` (or `Vec<AnomalyEvent>`) method to `AnomalyDetector` in `src/anomaly.rs`; keep it free of store/channel/I/O access (Invariant 1) and update statistics after the check (Invariant 4).
2. Call it from the owning probe loop after the sample's store push, sending each returned event via `store.push_event` + `detector.to_event_record` → `log_tx` (see Flow).
3. Add a row to the Detectors table above — this table is the authoritative `event` catalog that `contracts/jsonl-log-format.md` references; new discriminants need no JSONL-contract edit beyond the link.
4. If the detector needs a new window, add a `WindowedWelford::<name>()` constructor and document its sizes in Configuration.

## Related Specs

- [probing/README.md](probing/README.md) — probe loops that host the detectors
- [metrics-store.md](metrics-store.md) — events deque and `push_log_event`
- [../contracts/jsonl-log-format.md](../contracts/jsonl-log-format.md) — `event` record schema
