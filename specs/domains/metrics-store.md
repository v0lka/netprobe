# Metrics Store

## Purpose

`MetricsStore` is the single shared in-memory state of a session: ring-buffer histories per metric, ICMP aggregates, latest probe results, bounded event/log deques, and target/IP metadata. Probe loops write it under a tokio write lock; the TUI reads it per frame under a read lock and writes it only through the `r` reset and the n/p IP-cycle accessors (`next_ip`/`prev_ip`, each under a write lock); quiet-mode shutdown and `session_end` aggregation read it under a read lock (`SharedStore = Arc<tokio::sync::RwLock<MetricsStore>>`).

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
    pub fn clear(&mut self);
}

pub struct IcmpAggregates {
    pub min_rtt: f64, pub max_rtt: f64, pub avg_rtt: f64,
    pub p95_rtt: f64,
    pub jitter: f64,                     // mean |Δ| of consecutive samples in window
    pub sent: u64, pub received: u64,
    pub loss_pct: f64, pub duplicates: u64, pub reordered: u64,
}

pub struct ProbeResult<T> { pub data: Option<T>, pub error: Option<String> }
```

## Flow

- **Write path** (probe loops, tracing consumer, TUI `r`/`n`/`p`): take `store.write().await` → bounded pushes/counter updates/`set_latest_*`/`reset()` → drop the guard — all before any channel send or await-point I/O.
- **Read path** (TUI): one `store.read().await` per 250 ms frame; `draw(&MetricsStore)` works on the snapshot and the guard is dropped before input polling.
- **Summary path** (shutdown): `app.rs::create_session_end_record` takes one read lock and derives `SessionSummary` from `icmp_aggregates()`, `events_total()`, and `session_start()` (`events_total()` is the uncapped monotonic counter; the `events()` deque is FIFO-capped at 200).

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
| `session_start` | `DateTime<Utc>` | store (seed + `reset()`) | seeded by `Store::new`, re-seeded by the `r` hotkey |
| `traceroute_available` | `bool` | app | result of traceroute privilege discovery at startup (see [probing/traceroute.md](probing/traceroute.md)) |
| `target`, `resolved_target`, `resolved_ips` | metadata | app | set once at startup; the active address is derived via `active_ip()` from `resolved_ips[active_ip_index]` |
| `active_ip_index` | metadata | app (seed) + TUI (`n`/`p`) | mutable at runtime — the n/p hotkeys cycle it |

## Behavior

- **Aggregate recomputation**: `push_icmp_rtt` appends to the ring and calls `recalculate_icmp_aggregates`, which recomputes min/max/avg/percentiles/jitter/loss from the whole current window (percentile via the shared `util::calculate_percentile` — rank `⌊p·(n−1)⌋` into the ascending window, a lower-index quantile). Cost is O(window) per sample — fine at 1 Hz with window ≤ 3600, but keep new aggregates out of per-push paths if larger.
- **Jitter**: mean absolute difference between consecutive RTT values in the window (`Σ|v[i]−v[i−1]| / (n−1)`).
- **Loss**: `loss_pct = (sent − received) / sent × 100`; `sent` increments on every attempt (`inc_icmp_sent`), `received` only on RTT pushes. `duplicates`/`reordered` increment via dedicated counters.
- **IP switching**: `next_ip()`/`prev_ip()` cycle `active_ip_index` within `resolved_ips` (wrap-around; both return `bool` — `false` when only one IP is resolved). A successful switch also clears the per-endpoint ICMP statistics (RTT history + aggregates) so the two endpoints' numbers are never blended. The TUI then reads the new address via `active_ip()` and publishes it on the `watch` channel for probe loops.
- **`push_log_event(level, target, message)`**: maps tracing levels to `log_error`/`log_warn`/`log_info`/`log_debug`/`log_trace` entries with severity mapping (Critical/Warning/Info), sanitizes control characters, shortens the module path to its last segment, and evicts the oldest entry at capacity.
- **`reset()`** (`r` hotkey): clears all five histories, zeroes aggregates, resets `session_start` to now. Deliberately **keeps** `events` and all `latest_*` results — a "new sub-session" for statistics, not a full wipe.

## Invariants

1. The store is the only shared mutable state; `MetricsStore` owns all per-session data.
2. Histories contain successful measurements only; failures live in the matching slot's `ProbeResult.error`.
3. `sent ≥ received` and `loss_pct ∈ [0, 100]` hold between reset boundaries; a `reset()` (`r` hotkey) or a successful n/p IP switch (which clears the ICMP statistics) racing an in-flight probe can transiently show `received > sent` until the in-flight sample lands, and duplicate replies keep it violated for as long as they arrive — each duplicate pushes an RTT sample, so `received` rises without `sent` (`loss_pct` stays at 0 % via `saturating_sub`).
4. `events` and `logs` hold at most 200 entries; eviction is FIFO.
5. Store critical sections perform bounded pushes/copies only; I/O and channel sends happen outside the lock (see [../architecture/concurrency.md](../architecture/concurrency.md)).

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
- [../architecture/layers.md](../architecture/layers.md) — the store's dependency set (`models` + `util` + std/tokio/chrono/tracing) and why probe/tui stay out of it
