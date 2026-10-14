# Probing

## Purpose

The probing domain measures network quality to a single target across four layers — ICMP ping, DNS resolution, TCP connect / TLS handshake / HTTP healthcheck, and traceroute. Each layer runs as an independent tokio task ("probe loop") that periodically performs a measurement, publishes the result to the shared `MetricsStore`, and emits a JSONL `LogRecord` through the logger channel.

## Key Files

- `src/probe/mod.rs` — shared `ProbeError` enum and `IcmpStrategy` enum
- `src/probe/icmp.rs` — `IcmpProber` (hybrid strategy) + `icmp_probe_loop`
- `src/probe/dns.rs` — `DnsProber` (hickory-resolver) + `dns_probe_loop`
- `src/probe/tcp.rs` — `tcp_connect` (socket2) + `tcp_tls_http_probe_loop` (pipeline owner)
- `src/probe/tls.rs` — `tls_handshake` (tokio-rustls) + certificate parsing (x509-parser)
- `src/probe/http.rs` — `http_probe` (raw HTTP/1.1 GET, TTFB measurement)
- `src/probe/traceroute.rs` — `TracerouteProber` (trippy-core / tracert.exe) + `traceroute_probe_loop`

## Core Types

```rust
// src/probe/mod.rs
pub enum ProbeError { Timeout, SocketError(String), PermissionDenied, ParseError(String), Other(String) }

pub enum IcmpStrategy { Unprivileged, Raw, Subprocess }   // Display: "unprivileged" | "raw" | "subprocess"
```

```rust
// Probe result carrier used by the store (src/store.rs)
pub struct ProbeResult<T> { pub data: Option<T>, pub error: Option<String> }
```

Every loop follows the same signature shape (see `src/app.rs` spawn sites):

```rust
pub async fn <name>_probe_loop(
    prober: <X>Prober,
    store: SharedStore,                  // Arc<RwLock<MetricsStore>>
    log_tx: mpsc::Sender<LogRecord>,     // JSONL output channel
    interval: u64,
    target: String,
    cancel: CancellationToken,
    // icmp.rs / tcp.rs / traceroute.rs additionally take:
    ip_rx: watch::Receiver<IpAddr>,      // active target IP (TUI n/p switch)
) -> anyhow::Result<()>
```

## Flow

```
app.rs spawns loop ──▶ loop {
    tokio::select! (biased) {
        cancel.cancelled()  => break
        ip_rx.changed()     => retarget prober          (icmp, tcp)
        ticker.tick()       => {}
    }
    if cancel.is_cancelled() { break }
    run one probe
    write lock store: push sample / set latest / push events   (bounded, no I/O inside)
    send LogRecord(s) to log_tx                                (probe result + any events)
}
```

- The TCP/TLS/HTTP loop runs a three-stage pipeline per tick: TCP connect → TLS handshake (unless `--no-tls`) → HTTP GET (unless `--no-http`), emitting one record per completed stage.
- The DNS loop performs one resolution immediately on startup, then ticks.
- The traceroute loop calls a blocking implementation (trippy on a dedicated OS thread; `tracert.exe` via `block_in_place` on Windows).

## Invariants

1. **Probe errors are never fatal.** Every probe attempt converts failures into a record with an error/timeout `status` plus (for TCP refused, HTTP errors, cert expiry) an anomaly event; the loop keeps running.
2. **Every loop prioritizes cancellation** via `tokio::select! { biased; _ = cancel.cancelled() => break, ... }` and re-checks `cancel.is_cancelled()` before probing.
3. **Store critical sections are short.** A loop takes the write lock only to push samples/events and drops it before awaiting channel sends.
4. **One log record per attempt per stage.** ICMP/DNS produce one record per tick; the TCP pipeline produces one `tcp` record plus optionally one `tls` and one `http` record per tick.
5. **ICMP strategy is chosen once at startup** (unprivileged DGRAM → raw → subprocess) and reported in `session_start.config.icmp_strategy`.
6. **Loops react to target IP changes** (where applicable) without restarting: `IcmpProber::update_target` resets duplicate/reorder tracking; the TCP loop just swaps the connect address.

## Configuration

All values come from `Config` (`src/config.rs`; CLI in `src/main.rs`):

| Parameter | Default | Used by |
| --------- | ------- | ------- |
| `interval_icmp_ms` | 1000 | `icmp_probe_loop` |
| `interval_dns_sec` | 30 | `dns_probe_loop` |
| `interval_tcp_sec` | 10 | `tcp_tls_http_probe_loop` |
| `interval_trace_sec` | 60 | `traceroute_probe_loop` |
| `timeout_icmp_ms` | 2000 | per-ping timeout |
| `timeout_dns_ms` | 5000 | resolver timeout + attempts=2 |
| `timeout_tcp_ms` | 5000 | TCP connect and TLS handshake timeout |
| `timeout_http_ms` | 10000 | HTTP request timeout |
| `timeout_trace_ms` | 30000 | traceroute overall timeout |
| `port` | 443 | TCP/TLS/HTTP pipeline |
| `http_path` | `/` | HTTP GET path |
| `no_http` | false | disables the HTTP stage entirely |
| `no_tls` | false | disables the TLS stage (plain HTTP on `port`) |
| `dns_server` | system | explicit resolver for DNS prober and startup resolve |

## Extension Points

- **New probe layer**: add `src/probe/<name>.rs` with a `Prober` struct + `<name>_probe_loop` following the loop template; spawn it in `src/app.rs`; add record type in `src/models.rs`, store slots in `src/store.rs`, and a JSONL schema entry in `contracts/jsonl-log-format.md`.
- **New ICMP strategy**: extend the fallback chain in `IcmpProber::new` and the `IcmpStrategy` enum (`session_start` schema gains a new value).
- **New per-layer anomaly**: detectors live in `src/anomaly.rs`; call them from the owning probe loop after pushing the sample (see [../anomaly-detection.md](../anomaly-detection.md)).

## Related Specs

- [icmp.md](icmp.md) — hybrid ICMP strategy and duplicate/reorder detection
- [dns.md](dns.md) — resolver setup and IP-set change detection
- [tcp-tls-http.md](tcp-tls-http.md) — the three-stage L4/L7 pipeline
- [traceroute.md](traceroute.md) — trippy integration, privilege gating, route diff
- [../../contracts/probe-pipeline.md](../../contracts/probe-pipeline.md) — loop obligations toward store and logger
- [../anomaly-detection.md](../anomaly-detection.md) — detector wiring used by probe loops
