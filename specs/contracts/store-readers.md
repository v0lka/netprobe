# Contract: MetricsStore <-> Readers (TUI, Session Summary)

## Boundary Rule

Readers depend on `store` + public accessors only and must hold the read lock for bounded, non-async work; they never mutate state through back doors — the `r` hotkey calling `store.reset()` and the n/p IP-cycle accessors (`next_ip`/`prev_ip`) are the only sanctioned reader-initiated mutations, each executed under a write lock.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |
| `SharedStore = Arc<RwLock<MetricsStore>>` | `store.rs` / `tokio` | `TuiApp`, `app.rs` (tracing consumer, `session_end`) | shared state handle |
| `*_history()` accessors (`icmp_rtt_history`, `dns_resolve_history`, `tcp_connect_history`, `tls_handshake_history`, `ttfb_history`) | `store.rs` | panels → sparklines; `tls_handshake_history`/`ttfb_history` currently have **no rendering consumer** (buffers are populated and reset only — extension points for future sparklines) | `&[f64]` window snapshots |
| `icmp_aggregates()` | `store.rs` | `PingPanel`, header (MOS recompute), `app.rs` | `IcmpAggregates` snapshot |
| `latest_dns/tcp/tls/http/traceroute()` | `store.rs` | dns/tcp/trace panels | `&ProbeResult<T>` (data XOR error) |
| `events()` / `logs()` | `store.rs` | events/logs panels; `app.rs` (via the separate uncapped `events_total()` counter, for the `session_end` summary) | `&VecDeque<EventEntry>` |
| metadata accessors (`target`, `session_start`, `traceroute_available`, `active_ip`, `active_ip_index`, `resolved_ip_count`) | `store.rs` | header, trace panel, `app.rs` | display + summary |
| `next_ip()` / `prev_ip()` | `store.rs` | `TuiApp` (n/p keys) | cycle active IP (write lock) |
| `reset()` | `store.rs` | `TuiApp` (r key) | clear histories/aggregates, reset session clock (write lock) |

## Initialization

`app.rs` builds the store, seeds metadata (`set_resolved_target`, `set_resolved_ips_with_active`, `set_traceroute_available`) under a write lock before spawning anything, then hands clones to the TUI and probe loops. The TUI receives the same `SharedStore` — no second channel or snapshot mechanism exists.

## Data Flow Across Boundary

- **TUI frame (every 250 ms)**: one `store.read().await` → `TuiApp::draw(&MetricsStore)` renders synchronously → guard dropped before input polling. All figures on screen come from this snapshot.
- **IP switch (n/p)**: `TuiApp` calls `next_ip`/`prev_ip` under a write lock (they return `bool`, indicating the index moved); the TUI then reads the new address via `active_ip()` and publishes it on the `watch` channel — the store itself is not the transport to probe loops.
- **Tracing consumer task**: forwards log entries via `push_log_event` (write lock per entry) — the only other writer besides probe loops and `app.rs`.
- **`session_end` (shutdown)**: `app.rs::create_session_end_record` takes one read lock and derives `SessionSummary` from `icmp_aggregates()`, `events_total()`, `session_start()`, plus `util::compute_mos`/`mos_to_grade`; uptime = received/sent. The event count uses `events_total()` — the unbounded monotonic counter — because the `events()` deque is FIFO-capped at 200 and would undercount.

## Error Propagation

Read accessors are infallible. `ProbeResult.error` carries per-probe error text to panels; missing data is `Option::None`/empty slices — readers must render empty states, never unwrap.

## Breaking Change Checklist

- **Changing an accessor signature/semantics**: update all panels and `create_session_end_record` in the same change; panels are the only allowed consumers.
- **Adding a history buffer**: pair it with an accessor and a rendering consumer (or document why not) — no write-only state.
- **Changing `reset()` semantics**: coordinate `domains/metrics-store.md` (documents that events/latest results survive reset) and the TUI README.
- **Changing summary derivation** (MOS, uptime, counters): `contracts/jsonl-log-format.md` `session_end` schema is affected.
- **Replacing the RwLock with channels/actors**: this contract and `architecture/concurrency.md` must be rewritten together; every panel's data path changes.
