# TUI Dashboard

## Purpose

Interactive terminal dashboard (ratatui + crossterm) that renders live session state from the metrics store at ~4 FPS, handles keyboard control (quit, force traceroute, reset, IP switching, scrolling, focus), and captures `tracing` diagnostics into an in-dashboard logs panel.

## Key Files

- `src/tui/mod.rs` — `run_tui` entry, `TuiApp` state, event loop, key handling, help popup, panic-hook terminal restore
- `src/tui/layout.rs` — `DashboardLayout` (adaptive vertical stack, compact mode)
- `src/tui/theme.rs` — `Theme` color palette and severity styles
- `src/tui/header.rs`, `ping_panel.rs`, `dns_panel.rs`, `tcp_tls_panel.rs`, `trace_panel.rs`, `events_panel.rs`, `logs_panel.rs`, `footer.rs` — panel widgets
- `src/tui/sparkline.rs` — `BrailleSparkline` widget (see [sparkline.md](sparkline.md))
- `src/tui_tracing.rs` — `TuiTracingLayer`/`TracingLogReceiver` bridging `tracing` into the store logs deque

## Core Types

```rust
// src/tui/mod.rs
pub enum FocusPanel { Traceroute, Events, Logs }   // Tab cycles; default: Logs

pub struct TuiApp {
    store: SharedStore,
    config: Config,
    cancel: CancellationToken,                    // cancels on q / Ctrl+C
    trace_notify: Arc<Notify>,                    // t hotkey → traceroute force signal
    ip_change_tx: watch::Sender<IpAddr>,          // n/p hotkeys → probe retarget
    show_help: bool,
    focused_panel: FocusPanel,
    trace_scroll: usize,
    events_scroll: usize,  events_auto_scroll: bool,
    logs_scroll: usize,    logs_auto_scroll: bool,
}
```

## Flow

```
run_tui(store, config, cancel, trace_notify, ip_change_tx)
  ├─ enable_raw_mode + EnterAlternateScreen + EnableMouseCapture
  ├─ install panic hook (restore terminal, then delegate to previous hook)
  ├─ loop {                                    // draw_interval = 250 ms
  │    cancel.is_cancelled()? → break
  │    if 250 ms elapsed:
  │       store.read().await ──▶ terminal.draw(|f| self.draw(f, &store))  // guard dropped right after
  │    event::poll(timeout) → Key(Press) → handle_key()
  │       returns true → break
  │  }
  └─ disable_raw_mode + LeaveAlternateScreen + show cursor
```

`draw` is synchronous and receives the already-acquired read guard; panels are plain ratatui widgets constructed per frame from `&MetricsStore` + `Theme`.

## Hotkeys (verified in `handle_key`)

| Key | Action |
| --- | ------ |
| `q` / `Q` / Ctrl+C | graceful shutdown (cancels token; `session_end` written by app) |
| `t` / `T` | notify `trace_notify` (force traceroute signal) |
| `r` / `R` | `store.reset()` — clear histories + aggregates, new sub-session |
| `?` | toggle help popup; `Esc` closes it |
| `↑` / `↓` | scroll the focused panel (traceroute, events, or logs) |
| `Tab` | cycle focus Traceroute → Events → Logs (scrolls disable auto-scroll) |
| `n` / `N` | next resolved IP → `ip_change_tx` (probe loops retarget) |
| `p` / `P` | previous resolved IP → `ip_change_tx` |

Only `KeyEventKind::Press` is handled (safe for Windows key-repeat events).

## Invariants

1. The TUI consumes the store read-only: no panel or key handler writes metrics; the only outward signals are the cancel token, `trace_notify`, and `ip_change_tx`.
2. Exactly one store read lock is held per frame and dropped before polling input.
3. Terminal state (raw mode, alternate screen, cursor) is restored on every exit path, including panics (hook) — quiet mode never touches the terminal.
4. The dashboard renders only what is in the store; panels never call probers or I/O.
5. Draw cadence is 250 ms regardless of probe rates.

## Configuration

- Draw interval: 250 ms (constant `draw_interval` in `run_loop`).
- Layout thresholds: height ≥ 24 rows and width ≥ 80 columns for the full layout — see [panels-and-layout.md](panels-and-layout.md).
- Quiet mode (`-q`) skips the TUI entirely (no terminal setup, plain stderr tracing).

## Extension Points

- **New panel**: add a widget module, a `FocusPanel` variant if scrollable, an area in `DashboardLayout::build` (update both constraint branches + tests), and render it in `TuiApp::draw`.
- **New hotkey**: add a match arm in `handle_key`; update the help popup text.

## Related Specs

- [panels-and-layout.md](panels-and-layout.md) — panel set, proportions, adaptive rules
- [sparkline.md](sparkline.md) — braille widget used by ping/dns/tcp panels
- [../metrics-store.md](../metrics-store.md) — the state being rendered
- [../../architecture/concurrency.md](../../architecture/concurrency.md) — loop timing and shutdown interaction
