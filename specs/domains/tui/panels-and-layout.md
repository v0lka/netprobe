# Panels and Layout

## Role

Defines the dashboard's vertical stack (`DashboardLayout`), the per-panel widgets and their data sources, and the adaptive/compact behavior for small terminals.

## Key Files

- `src/tui/layout.rs` — `DashboardLayout` (constraints, visibility flags, compact mode)
- `src/tui/header.rs` — `HeaderWidget`
- `src/tui/ping_panel.rs` — `PingPanel`
- `src/tui/dns_panel.rs` — `DnsPanel`
- `src/tui/tcp_tls_panel.rs` — `TcpTlsPanel`
- `src/tui/trace_panel.rs` — `TracePanel`
- `src/tui/events_panel.rs` — `EventsPanel`
- `src/tui/logs_panel.rs` — `LogsPanel`
- `src/tui/footer.rs` — `FooterWidget`
- `src/tui/theme.rs` — `Theme`

## Layout

`DashboardLayout::new(area)` decides visibility from the terminal size; `build()` returns seven areas:

```
Full (height ≥ 24):                 Short (height < 24):
┌ Header (1 row) ┐                  ┌ Header (1 row) ┐
│ Ping     32%   │                  │ Ping     45%   │
│ DNS      13%   │                  │ DNS      20%   │
│ TCP/TLS/HTTP 16%│                 │ TCP/TLS/HTTP 25%│
│ Traceroute 21% │                  │ Traceroute — hidden
│ Events+Logs 18%│                  │ Events/Logs — hidden
└ Footer (1 row) ┘                  └ Footer (1 row) ┘
```

- **Compact width** (`compact = width < 80`, `MIN_WIDTH_FULL`): panels shorten numeric formatting; layout rows are unchanged.
- **Events + Logs share one area**: when visible, the events area is split horizontally 50/50 — events left, tracing logs right.
- Hidden panels return `Rect::default()` (zero-sized); renderers skip them.

## Panel Data Sources

| Panel | Reads (all read-only from `MetricsStore`) |
| ----- | ----------------------------------------- |
| `HeaderWidget` | `target`, resolved IP (with active index), MOS/grade (recomputed from aggregates), session duration |
| `PingPanel` | `icmp_rtt_history` (braille sparkline), `icmp_aggregates` (now/avg/min/max/p95/jitter/loss/sent/recv) |
| `DnsPanel` | `latest_dns` (`DnsData` or error), `dns_resolve_history` sparkline |
| `TcpTlsPanel` | `latest_tcp`, `latest_tls` (version, cipher, cert days), `latest_http` (TTFB, status), `tcp_connect_history` (sparkline) |
| `TracePanel` | `latest_traceroute` (`TracerouteData.hops`), `traceroute_available`; hop bars + per-hop scroll (`trace_scroll`, focus highlight) |
| `EventsPanel` | `events()` deque, severity-colored, scroll + auto-scroll (stick to newest until user scrolls) |
| `LogsPanel` | `logs()` deque (tracing entries), scroll + auto-scroll |
| `FooterWidget` | static hotkey hints |

Panels taking a `compact: bool` (Ping) or `port` (TcpTlsPanel) receive it from `TuiApp::draw`.

## Behavior

- **Scroll model**: each scrollable panel keeps an offset in `TuiApp` plus an `auto_scroll` flag. Scrolling manually turns auto-scroll off; the flag resets per panel implementation to stick to the newest entry. `Tab` moves focus; the focused panel draws a focus indicator and receives `↑`/`↓`.
- **Help popup**: `?` toggles a centered 60%×60% overlay (`Clear` + rounded border) listing hotkeys; `Esc` closes.

## Error Handling

- When a `ProbeResult` slot carries `error`, the owning panel shows the error text instead of metrics (e.g. the trace panel shows the "Insufficient privileges" message); panels render empty states for `None`/empty slices and never unwrap.
- Terminal-level failures (setup, draw, event read) propagate out of `run_tui` to `main`; the panic hook restores the terminal before delegating for panics located under `src/tui/`, and any panic unwinding through `run()` restores it via `TerminalGuard`. Error rendering never writes back to the store.

## Invariants

1. Layout thresholds are compile-time constants (`MIN_HEIGHT_FULL = 24`, `MIN_WIDTH_FULL = 80`) applied identically to both constraint branches.
2. The full branch always emits the 7-constraint sequence header/ping/dns/tcp/trace/events/footer; the compact branch header/ping/dns/tcp/footer.
3. Panel widgets are stateless — all interactive state (scroll, focus, help) lives in `TuiApp`.
4. Panels only read the store; frame rendering depends only on the store snapshot and `TuiApp` state — store writes come exclusively from `TuiApp`'s `r`/`n`/`p` handlers.

## Related Specs

- [README.md](README.md) — event loop, hotkeys, terminal lifecycle
- [sparkline.md](sparkline.md) — the braille widget embedded in ping/dns/tcp panels
- [../metrics-store.md](../metrics-store.md) — exact slot semantics behind each panel
- Color palette lives in `src/tui/theme.rs` (btop-inspired grays/blues with green→red severity ramp); it is code, not a spec file.
