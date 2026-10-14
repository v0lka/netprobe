# Metrics Store

## Purpose

`MetricsStore` is the single shared in-memory state of a session: ring-buffer histories per metric, ICMP aggregates, latest probe results, bounded event/log deques, and target/IP metadata. Probe loops write it under a tokio write lock; the TUI, quiet-mode shutdown, and `session_end` aggregation read it under a read lock (`SharedStore = Arc<tokio::sync::RwLock<MetricsStore>>`).

## Key Files

- `src/store.rs` — `MetricsStore`, `SharedStore`, `RingBuffer<T>`, `IcmpAggregates`, `ProbeResult<T>`, per-domain data structs (`DnsData`, `TcpData`, `TlsData`, `HttpData`, `HopData`, `TracerouteData`), `EventEntry`

## Core Types

```rust
pub type SharedStore = Arc<RwLock<MetricsStore>>;

pub struct RingBuffer<T> { /* fixed capacity, push evicts oldest */ }
impl<T> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self;
    pub fn push(&mut self, value: T);
    pub fn as_slice(&self) -> &[T];      // chronological order
    pub fn latest(&self) -> Option<&T>;
    pub fn clear(&mut self);
    pub fn capacity(&self) -> usize;
}

pub struct IcmpAggregates {
    pub min_rtt: f64, pub max_rtt: f64, pub avg_rtt: f64,
    pub p50_rtt: f64, pub p95_rtt: f64, pub p99_rtt: f64,
    pub jitter: f64,                     // mean |Δ| of consecutive samples in window
    pub sent: u64, pub received: u64,
    pub loss_pct: f64, pub duplicates: u64, pub reordered: u64,
}

pub struct ProbeResult<T> { pub data: Option<T>, pub error: Option<String>, pub timestamp: DateTime<Utc> }
```

## State Layout

| Slot | Type | Writer | Notes |
| ---- | ---- | ------ | ----- |
| `icmp_rtt_history` | `RingBuffer<f64>` (capacity `config.history`, default 3600) | ICMP loop | successful RTTs only |
| `dns_resolve_history` | `RingBuffer<f64>` | DNS loop | successful resolutions only |
| `tcp_connect_history` | `RingBuffer<f64>` | TCP pipeline | successful connects only |
| `tls_handshake_history` | `RingBuffer<f64>` | TCP pipeline | successful handshakes only |
| `ttfb_history` | `RingBuffer<f64>` | TCP pipeline | successful HTTP probes only |
| `icmp_aggregates` | `IcmpAggregates` | ICMP loop + store | recomputed on every `push_icmp_rtt` |
| `latest_dns/tcp/tls/http/traceroute` | `ProbeResult<_>` | respective loops | data XOR error |
| `events` | `VecDeque<EventEntry>` (max 200) | probe loops | network anomalies only |
| `logs` | `VecDeque<EventEntry>` (max 200) | tracing consumer | TUI logs panel entries |
| `session_start` | `DateTime<Utc>` | app | reset by `r` hotkey |
| `traceroute_available` | `bool` | app | result of traceroute privilege discovery at startup (see [probing/traceroute.md](probing/traceroute.md)) |
| `target`, `resolved_target`, `resolved_ip`, `resolved_ips`, `active_ip_index` | metadata | app | set once at startup |

## Behavior

- **Aggregate recomputation**: `push_icmp_rtt` appends to the ring and calls `recalculate_icmp_aggregates`, which recomputes min/max/avg/percentiles/jitter/loss from the whole current window (`util::calculate_percentile`, linear interpolation). Cost is O(window) per sample — fine at 1 Hz with window ≤ 3600, but keep new aggregates out of per-push paths if larger.
- **Jitter**: mean absolute difference between consecutive RTT values in the window (`Σ|v[i]−v[i−1]| / (n−1)`).
- **Loss**: `loss_pct = (sent − received) / sent × 100`; `sent` increments on every attempt (`inc_icmp_sent`), `received` only on RTT pushes. `duplicates`/`reordered` increment via dedicated counters.
- **IP switching**: `next_ip()`/`prev_ip()` cycle `active_ip_index` within `resolved_ips` (wrap-around, `false` when only one IP). The new active IP is returned to the TUI, which publishes it on the `watch` channel for probe loops.
- **`push_log_event(level, target, message)`**: maps tracing levels to `log_error`/`log_warn`/`log_info`/`log_debug`/`log_trace` entries with severity mapping (Critical/Warning/Info), sanitizes control characters, shortens the module path to its last segment, and evicts the oldest entry at capacity.
- **`reset()`** (`r` hotkey): clears all five histories, zeroes aggregates, resets `session_start` to now. Deliberately **keeps** `events` and all `latest_*` results — a "new sub-session" for statistics, not a full wipe.

## Invariants

1. The store is the only shared mutable state; nothing outside `MetricsStore` persists per-session data.
2. Histories contain successful measurements only — failures are recorded in `ProbeResult.error` of the matching slot, never in history buffers.
3. `sent ≥ received` and `loss_pct ∈ [0, 100]` at all times.
4. `events` and `logs` never exceed 200 entries; eviction is FIFO.
5. Store critical sections never perform I/O or channel sends (see [../architecture/concurrency.md](../architecture/concurrency.md)).

## Configuration

- `history` (CLI `--history`, default 3600) → capacity of all five ring buffers at construction; changing it requires a restart.
- `DEFAULT_MAX_EVENTS = 200` (compile-time constant) → bounds for both deques.

## Extension Points

- **New metric history**: add a `RingBuffer` field + `push_<metric>`/`<metric>_history` accessors in `store.rs`; wire the pushing loop; add a sparkline/panel consumer if needed.
- **New aggregate**: extend `IcmpAggregates` (or add a struct) and recompute inside the same `recalculate_*` path; update `session_end` summary if it should persist.

## Related Specs

- [anomaly-detection.md](anomaly-detection.md) — how events enter the `events` deque
- [logging.md](logging.md) — JSONL side (records derived from, but not stored in, the store)
- [../contracts/store-readers.md](../contracts/store-readers.md) — read-path rules
- [../architecture/layers.md](../architecture/layers.md) — why the store depends only on `models`
