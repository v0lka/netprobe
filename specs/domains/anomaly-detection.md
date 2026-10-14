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
| ICMP loss/timeout/error | `on_icmp_loss()` | `loss_burst` | Critical | ≥ 3 consecutive losses; re-fires for every additional consecutive loss |
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

1. `anomaly.rs` stays pure — no store, channel, or I/O access; probes own the trigger points.
2. `rtt_spike`/`jitter_spike` cannot fire before 30 samples (`is_warm`); `loss_burst` has no warm-up.
3. A successful probe resets `consecutive_losses` to 0.
4. Detector statistics update **after** the checks, so the current sample never contributes to its own baseline.
5. Both spike detectors use the same sample count and windows (60/30); per-hop statistics are independent per hop and reset only with the prober.
6. Every published event goes to both the store deque and the logger channel.

## Related Specs

- [probing/README.md](probing/README.md) — probe loops that host the detectors
- [metrics-store.md](metrics-store.md) — events deque and `push_log_event`
- [../contracts/jsonl-log-format.md](../contracts/jsonl-log-format.md) — `event` record schema
