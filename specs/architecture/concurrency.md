# Concurrency

## Context

netprobe runs four probe cadences concurrently (ICMP ~1s, DNS ~30s, TCP/TLS/HTTP ~10s, traceroute ~60s) plus a TUI redraw at 250 ms and a file writer, all coordinated through one shared `MetricsStore` and one JSONL output. The concurrency model is "shared state via `Arc<RwLock<MetricsStore>>` + message passing for I/O" — chosen over full actor-style message passing (see [ADR-0003](../decisions/0003-shared-state-architecture.md)). Any new probe or output channel must fit this model.

## Task Model

All tasks are spawned inside `app::run` (`src/app.rs`) — the TUI's signal forwarders transitively, inside `tui::run_tui` — on the global tokio runtime (`#[tokio::main]`):

| Task | Spawned from | Body | Exit condition |
| ---- | ------------ | ---- | -------------- |
| Logger | Step 8 | `Logger::run`: mpsc receiver → `BufWriter<File>` | Channel closed (all senders dropped); cancellation triggers one flush, then the loop keeps draining until the channel closes |
| Tracing consumer | Step 8b, TUI mode only | forwards `TracingLogReceiver` entries into store log deque | `cancel.cancelled()` |
| ICMP probe loop | Step 9 | `probe::icmp::icmp_probe_loop` | `cancel.cancelled()` |
| DNS probe loop | Step 9 | `probe::dns::dns_probe_loop` | `cancel.cancelled()` |
| TCP/TLS/HTTP probe loop | Step 9 | `probe::tcp::tcp_tls_http_probe_loop` | `cancel.cancelled()` |
| Traceroute probe loop | Step 9, only if `traceroute_available` | `probe::traceroute::traceroute_probe_loop` | `cancel.cancelled()` |
| Signal forwarders | `run_tui` (`spawn_signal_forwarder`), TUI mode only, Unix only | two tasks forwarding SIGINT/SIGTERM into `cancel`; a repeat during the shutdown window force-exits | first signal → `cancel.cancel()`; repeat → `std::process::exit` (130 for SIGINT, 143 for SIGTERM) |
| TUI (foreground) | Step 10, non-quiet | `tui::run_tui` on the main task | `q` hotkey or Ctrl+C → cancels token; delivered SIGINT/SIGTERM likewise (via the signal forwarders) |
| Quiet wait (foreground) | Step 10, quiet | `run_quiet_mode`: `select!` on `ctrl_c()` vs `cancelled()` | Ctrl+C or external cancel |
| Quiet repeat-Ctrl+C watchdog | `run_quiet_mode`, quiet only, armed after the first Ctrl+C | a repeat during the shutdown window force-exits | repeat → `std::process::exit` (130); otherwise ends with the process |

Probe loops are driven by `tokio::time::interval` cadences from `Config` and are fully independent of each other — a slow or failing probe never blocks another.

## Coordination Primitives

| Primitive | Type | Direction | Purpose |
| --------- | ---- | --------- | ------- |
| `cancel` | `tokio_util::sync::CancellationToken` | app → all tasks | graceful shutdown signal |
| `log_sender` | `tokio::sync::mpsc::Sender<LogRecord>` (buffer 1024, `Logger::CHANNEL_BUFFER_SIZE`) | probes/app → logger task | JSONL records out |
| `ip_change` | `tokio::sync::watch::channel<IpAddr>` | TUI → probes | active target IP switch (n/p hotkeys); ICMP/TCP/traceroute re-point their next probe at the new IP (the DNS prober ignores this watch — see [../domains/probing/dns.md](../domains/probing/dns.md)) |
| `trace_notify` | `Arc<tokio::sync::Notify>` | TUI → traceroute task | force out-of-schedule traceroute (`t` hotkey) |
| `reset_notify` | `Arc<tokio::sync::Notify>` | TUI → ICMP probe loop | statistics reset (`r` hotkey): the ICMP anomaly detector is recreated so its baselines re-warm against the fresh store statistics |
| `store` | `Arc<tokio::sync::RwLock<MetricsStore>>` (`SharedStore`) | probes write (plus the TUI's `r`/`n`/`p` handlers); TUI/app read | shared dashboard state |

**Lock discipline:**
- Probe loops take a **write lock** for short, bounded critical sections: push one sample, update aggregates, append events. The guard is dropped before the loop's `log_tx.send(...).await` — no I/O and no channel send happens while holding the guard.
- The TUI takes a **read lock** once per draw frame (250 ms cadence) and copies out what it renders.
- `session_end` aggregation (in `app.rs::create_session_end_record`) takes a single read lock and computes MOS/uptime/summary from store accessors.

## Shutdown Sequence

Verified against `app::run` steps 10–12 (`src/app.rs`):

```
q / Ctrl+C      or delivered SIGINT/SIGTERM (Unix, TUI mode) — a repeat
   │            signal or Ctrl+C during this window force-exits (130 / 143)
   ▼
run_tui / run_quiet_mode returns      (cancels the CancellationToken)
   │
   ▼
cancel.cancel()
   │
   ▼
join probe tasks, 5 s timeout each    (ICMP → DNS → TCP → Traceroute)
   │
   ▼
build session_end from store (read lock), send to logger channel
   │
   ▼
drop(log_sender)  ── channel closes ──▶  logger flushes remaining records and exits
   │
   ▼
join logger task (5 s timeout), tracing consumer (1 s timeout)
   │
   ▼
app::run returns; main prints error only on failure
```

The logger flushes on cancellation (once), on every `event` record (immediate), and on channel close. Probe tasks that miss the 5 s join timeout are **aborted** (`handle.abort()` + `warn!`) so they cannot send a record after `session_end` and their sender clones cannot keep the log channel open; a task that panicked is logged via `error!` during the join.

## TUI Loop

`src/tui/mod.rs::run_tui`:

- Draw cadence: 250 ms (`draw_interval`, ~4 FPS); one store read lock per frame.
- Input: `crossterm::event::poll` with a short timeout between frames; key handling is async (`handle_key`).
- Hotkeys verified in `handle_key`: `q`/`Q` quit, `t`/`T` force traceroute (`trace_notify`), `r`/`R` reset stats (`store.reset()`), `?` help popup, `↑`/`↓` scroll focused panel, `Tab` cycle focus, `n`/`N` / `p`/`P` next/previous resolved IP (writes `ip_change` watch), `Esc` close popup.
- Terminal lifecycle: raw mode + alternate screen on entry; restore on exit; a panic hook installed in `TuiApp::run` (`src/tui/mod.rs`) restores the terminal before delegating to the previous panic hook, but only for panics located under `src/tui/` — the multi-threaded runtime migrates tasks between worker threads, so thread identity cannot discriminate, and a panic from a probe task must leave the live dashboard up (its unwind is contained by the shutdown join). Panics surfacing from dependencies restore the terminal during unwinding via `TerminalGuard`.

## Invariants

1. **Exactly one writer group.** Probe loops and `app.rs` (session records) are the only `LogRecord` senders; the logger task is the only file writer.
2. **Cancellation is cooperative.** Every record-producing/store-writing task observes `cancel` (directly or via channel close); the signal forwarders and the quiet-mode repeat-`Ctrl+C` watchdog are process-lifetime helpers — they end with the process rather than observing the token. The shutdown join is the single forced-abort point — a straggler missing the 5 s join timeout is aborted so the next shutdown steps stay ordered.
3. **`session_end` is the last data record.** It is sent after every probe task has been joined or aborted at the 5 s timeout, so its summary reflects the full session and the aborted stragglers cannot follow it.
4. **The log channel closes before the logger is awaited** (`drop(log_sender)`), guaranteeing the logger observes end-of-stream and flushes — overrunning producers have been aborted by then, so their sender clones are gone.
5. **Store critical sections are bounded pushes/copies** — the guard is dropped before any `await` that can block, including channel sends.
6. **Traceroute task existence matches `traceroute_available`** recorded in `session_start` — the task is spawned only when startup privilege discovery succeeds.

## Anti-Patterns

- **Blocking the store guard across I/O.** Holding the write lock while performing a network probe or a channel send stalls the TUI and all other probes.
- **Busy-wait polling loops.** New events must use the existing primitives (`Notify`, `watch`, `mpsc`, `interval`) instead of sleep-polling the store.
- **Sending records after `cancel` from probes without checking `cancel`** — the logger drains the channel, but unbounded post-cancel flooding delays shutdown past the join timeouts.
- **Direct file writes outside `logger.rs`.** Any component writing to the JSONL file bypassing the channel breaks the single-writer invariant and flush guarantees.

## Related Specs

- [layers.md](layers.md) — which modules may hold which handles
- [../contracts/probe-pipeline.md](../contracts/probe-pipeline.md) — per-loop channel/lock obligations
- [../contracts/store-readers.md](../contracts/store-readers.md) — read-path rules for TUI and shutdown
- [../domains/logging.md](../domains/logging.md) — logger flush policy details
