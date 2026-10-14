# Contract: Probe Loops <-> Store / Logger / Control Signals

## Boundary Rule

Probe loops depend on `store` (write), `models` (records), and `anomaly` (detectors) — never on `logger` or `tui`. Output crosses only via the `mpsc::Sender<LogRecord>` handle; dashboard state crosses only via `SharedStore`. Control enters only via `CancellationToken`, `watch::Receiver<IpAddr>`, and `Notify`.

## Interfaces

| Interface | Type | Producer | Consumed By | Purpose |
| --------- | ---- | -------- | ----------- | ------- |
| `store: SharedStore` | `Arc<RwLock<MetricsStore>>` | `app.rs` | all probe loops | publish results/events |
| `log_tx: mpsc::Sender<LogRecord>` | channel buffer 1024 | `Logger::new` via `app.rs` | all probe loops, `app.rs` | JSONL output |
| `cancel: CancellationToken` | `tokio_util` | `app.rs` | all tasks | cooperative shutdown |
| `ip_rx: watch::Receiver<IpAddr>` | watch channel | `app.rs` (TUI writes) | icmp, tcp, traceroute | active target IP |
| `trace_notify: Arc<Notify>` | notify | `app.rs` (TUI notifies) | traceroute loop | forced trace signal |

## Initialization

`app::run` creates store, logger channel, token, watch channel (seeded with the resolved IP), and `Notify`; clones the handles per task; spawns each loop (`src/app.rs` step 8–9). The traceroute task is spawned only when the availability flag is set — the flag comes from `TracerouteProber::new` privilege discovery (see [../domains/probing/traceroute.md](../domains/probing/traceroute.md) and [ADR-0006](../decisions/0006-traceroute-startup-privilege-gating.md)). Loop cadences come from `Config`; probers are constructed before spawning (ICMP strategy detection happens there and is fatal on failure).

## Data Flow Across Boundary

Per probe attempt, a loop must (in this order):

1. **Write lock** the store: push successful samples into history, update `ProbeResult` slot (data XOR error), increment counters, push anomaly events into the events deque. Drop the guard.
2. **Send** `LogRecord`s: one per stage/attempt, plus one `LogRecord::Event` per anomaly. Send errors are ignored (`let _ =`) — a dead logger must not stop probing.
3. **React to control**: `cancel` breaks the loop (checked in `select! { biased }` and before probing); `ip_rx.changed()` retargets the prober (ICMP resets duplicate/reorder tracking; TCP swaps address; hostname/SNI unchanged; traceroute resets route history and hop statistics).

## Error Propagation

- Probe-internal failures are **values, not errors**: statuses (`timeout`, `refused`, `nxdomain`, …), `ProbeResult.error` strings, and anomaly events. A loop function returns `Result` only for unexpected internal failures (it currently always returns `Ok` on cancellation).
- Any `panic` in a loop task is contained: `app.rs` joins with a 5 s timeout, logs, and continues shutdown — but the layer stops updating until restart.

## Breaking Change Checklist

- **New loop parameter**: update the loop signature, its `app.rs` spawn site, and [../domains/probing/README.md](../domains/probing/README.md) loop template together.
- **New store slot**: add field + accessor in `store.rs`, writer call in the owning loop, reader in the consuming panel; if it feeds `session_end`, update `models.rs::SessionSummary` and `contracts/jsonl-log-format.md`.
- **New LogRecord variant**: update `models.rs`, the sending loop, and `contracts/jsonl-log-format.md`.
- **Changing shutdown semantics** (join timeouts, ordering): update `../architecture/concurrency.md` — the logger must keep receiving `session_end` last.
