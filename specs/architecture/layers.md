# Layers

## Context

netprobe is a single-crate Rust application (edition 2024) that monitors network quality at four layers — ICMP, DNS, TCP/TLS/HTTP, and traceroute (the same four-layer set named in [../domains/probing/README.md](../domains/probing/README.md)) — renders a TUI dashboard, and persists structured JSONL logs. Its architecture separates pure probe logic from shared state and from two independent output consumers (logger and TUI). Understanding the layer hierarchy and its import rules is required before adding probes, panels, or log record types — every layer addition must respect the dependency direction described here.

## Layer Hierarchy

```
                ┌─────────────────────────────┐
                │  main.rs                    │   CLI parsing (clap), tracing init
                └──────────────┬──────────────┘
                               │
                ┌──────────────▼──────────────┐
                │  app.rs                     │   orchestration: resolve target,
                │  (orchestrator)             │   spawn tasks, run TUI/quiet, shutdown
                └──┬──────────┬───────────┬───┘
                   │          │           │
        ┌──────────▼─┐  ┌─────▼────────┐ ┌▼──────────────┐
        │ probe/     │  │ store.rs     │ │ output tasks  │
        │ probe loops│─▶│MetricsStore  │◀│ tui/ (reader) │
        │ + anomaly  │  │(Arc<RwLock>) │ │ logger (writer│
        └──────┬─────┘  └──────┬───────┘ │  via mpsc)    │
               │               │         └───────┬───────┘
               ▼               ▼                 ▼
        ┌─────────────────────────────────────────────┐
        │ foundation leaves:                          │
        │   models.rs (serde records)                 │
        │   config.rs (Config)                        │
        │   anomaly.rs (pure detection logic)         │
        │   util.rs (MOS, formatting)                 │
        │   tui_tracing.rs (tracing -> TUI bridge)    │
        └─────────────────────────────────────────────┘
```

Data flows left-to-right/downward only: probe loops push results into `MetricsStore` and emit `LogRecord`s; the TUI reads the store per frame and writes it only through the `r` reset and the n/p IP-cycle accessors (each under a write lock); the logger drains an mpsc channel into the JSONL file. Nothing flows back up except control signals (cancellation, IP change watch, traceroute notify, reset notify — see [concurrency.md](concurrency.md)).

## Module Responsibilities

| Module | Responsibility | Depends on |
| ------ | -------------- | ---------- |
| `src/main.rs` | CLI parsing (`clap` derive), tracing subscriber init, `app::run` invocation | `config`, `app`, `tui_tracing` |
| `src/config.rs` | `Config` struct + all `DEFAULT_*` constants | std only |
| `src/app.rs` | Startup sequence, task spawning, shutdown, `session_start`/`session_end` records | `config`, `logger`, `models`, `probe`, `store`, `tui`, `tui_tracing`, `util` |
| `src/probe/icmp.rs` | ICMP probe loop: hybrid strategy, inline RTT/jitter anomaly detection | `store`, `models`, `anomaly`, `probe` |
| `src/probe/dns.rs` | DNS probe loop: resolution + IP-set change detection | `store`, `models`, `anomaly`, `probe` |
| `src/probe/tcp.rs` | Combined TCP/TLS/HTTP probe loop (owns the pipeline) | `store`, `models`, `anomaly`, `probe`, `config` |
| `src/probe/tls.rs` | TLS handshake helper (used by `tcp.rs`) | `probe` |
| `src/probe/http.rs` | Raw HTTP/1.1 healthcheck helper (used by `tcp.rs`) | `probe` |
| `src/probe/traceroute.rs` | Traceroute probe loop: hop capture, route diff, per-hop anomalies | `store`, `models`, `anomaly`, `probe` |
| `src/anomaly.rs` | Sliding-Welford statistics and all anomaly detectors (pure logic) | `models` |
| `src/store.rs` | `MetricsStore`: ring buffers, aggregates, event/log deques, IP switching | `models`, `util` (plus std/tokio/chrono/tracing) |
| `src/logger.rs` | JSONL writer task: mpsc receiver → `BufWriter<File>` | `models` (plus std/tokio/tokio_util/anyhow) |
| `src/models.rs` | All serde structs/enums for JSONL records (`LogRecord`, per-type records) | serde/chrono only |
| `src/tui/mod.rs` | `run_tui`: terminal lifecycle, event loop, hotkeys, focus | `store`, `config`, `tui` submodules |
| `src/tui/*.rs` | Panel renderers, layout, theme, braille sparkline | `store`, `models`, `util` |
| `src/tui_tracing.rs` | `tracing` layer that captures log events for the TUI logs panel | std/tracing/tracing-subscriber/tokio only |
| `src/util.rs` | `compute_mos`, `mos_to_grade`, formatting helpers | std only |

## Invariants

1. **Foundation leaves never depend on upper layers.** `models.rs`, `config.rs`, `util.rs`, `anomaly.rs`, `tui_tracing.rs` import nothing from `store`, `probe`, `tui`, `logger`, or `app`.
2. **`store.rs` depends only on `models.rs` and the pure `util` helpers** (`calculate_percentile`/`compute_jitter`; plus std/tokio/chrono/tracing — `chrono` for timestamps, `tracing::Level` for log-event severity mapping). The store must stay free of probing and rendering logic.
3. **Probe loops depend on `store` + `models` + `anomaly`, never on `logger` or `tui`.** Probe results reach the log file only via the `mpsc::Sender<LogRecord>` handed to them by `app.rs`; probe results reach the dashboard only via the store.
4. **`logger.rs` depends only on `models.rs`** for the record schema (plus std/tokio/tokio_util/anyhow for the async writer, channel, cancellation, and error plumbing). It knows nothing about probes or the store.
5. **`tui/` depends on `store` + `config`; it reads the store per frame and writes it only through the `r` reset and the n/p IP-cycle accessors (each under a write lock), and it never depends on `probe`.** Panels render store state; they never call probers.
6. **Only `app.rs` is wired to everything.** Only `main.rs` calls `app::run`. No module depends on `app` or `main`.
7. **`anomaly.rs` stays pure.** Detectors take metric samples and return events; they do not touch the store, channels, or I/O. (Probe loops own the calling of detectors.)

## Anti-Patterns

- **Probe → logger direct dependency.** Adding `use crate::logger` inside `src/probe/*` bypasses the channel boundary and breaks testability. Probes must only receive `mpsc::Sender<LogRecord>`.
- **Panel → probe calls.** A TUI panel that triggers a probe directly (instead of using the existing control signals: `Notify` for traceroute, `watch` for IP switch) violates the panels-read-only rule — the only sanctioned store writes from the TUI are `TuiApp`'s `r`/`n`/`p` handlers via `reset()`/`next_ip()`/`prev_ip()`.
- **Stateful anomaly detectors.** Moving store/history access into `anomaly.rs` couples pure math to shared state and makes thresholds untestable.
- **New cross-cutting side channels.** Adding another `Arc<Mutex<...>>` global besides `MetricsStore` fragments the state model; extend `MetricsStore` instead.
- **Business logic in `main.rs`.** `main.rs` only parses args, initializes tracing, and calls `app::run`.

## Related Specs

- [concurrency.md](concurrency.md) — task model, channels, shutdown sequence behind this layering
- [../contracts/probe-pipeline.md](../contracts/probe-pipeline.md) — obligations of each probe loop
- [../contracts/store-readers.md](../contracts/store-readers.md) — how TUI and session_end consume the store
- [../domains/probing/README.md](../domains/probing/README.md) — the probe layer in detail
