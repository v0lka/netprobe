# ADR-0003: Shared-state concurrency (`Arc<RwLock<MetricsStore>>` + mpsc logger)

## Status

Accepted

## Context

Five concurrent producers (four probe cadences + tracing consumer) feed two consumers (TUI renderer at 4 FPS, JSONL writer) with very different consumption patterns: the TUI wants a coherent snapshot of everything on every frame; the logger wants a durable ordered stream. A pure actor/message-passing design would force the TUI to accumulate every record type locally, and a pure shared-state design would couple file I/O to probe loops.

## Decision

Hybrid model, implemented in `src/store.rs`, `src/logger.rs`, `src/app.rs`:

- **Dashboard state**: one `MetricsStore` behind `Arc<tokio::sync::RwLock>` (`SharedStore`). Probes take short write-lock sections to push samples/events; the TUI takes one read lock per 250 ms frame and writes only through the `r` reset and the n/p IP-cycle accessors (each under a write lock); `session_end` takes one read lock for the summary.
- **Persistence**: an `mpsc` channel (buffer 1024) carries `LogRecord`s to the single logger task that owns the file writer.
- **Control**: `CancellationToken` (shutdown), `watch<IpAddr>` (target switching), `Notify` (forced traceroute, statistics reset).

## Consequences

Positive:

- Panels read any metric combination from one coherent snapshot — trivial rendering code, no message replay.
- Adding a probe touches only the store schema and its own loop; consumers are unaffected.
- The read-heavy/write-light pattern (1 write/s per probe vs 4 reads/s) fits an RwLock well; critical sections are sub-microsecond pushes.
- Backpressure is structural: a slow logger blocks senders (never drops records silently).

Negative:

- Store schema is a central coupling point — every metric addition edits `store.rs`.
- Lock discipline is a convention, not enforced: holding a guard across I/O would stall the TUI (documented as an invariant + anti-pattern).
- `recalculate_icmp_aggregates` is O(window) per sample inside the write lock; acceptable at 1 Hz/3600 samples, but a pattern to watch for higher-rate metrics.

## Alternatives Considered

- **Full message passing (everything through channels)** — rejected: TUI must then mirror all state locally (duplicated eviction/aggregation logic) or request snapshots (extra protocol); the file writer would still need its own channel.
- **Per-metric `Arc<Mutex<>>` cells** — rejected: coherent cross-metric snapshots (header shows MOS from RTT + loss simultaneously) would need multi-lock reads with ordering hazards.
- **Single-threaded select loop** — rejected: subprocess ping and trippy tracer block; isolating them per task prevents one slow probe from stalling others.

## Related Specs

- [../architecture/concurrency.md](../architecture/concurrency.md) — task model, lock discipline, shutdown
- [../architecture/layers.md](../architecture/layers.md) — dependency rules that keep this model workable
- [../contracts/probe-pipeline.md](../contracts/probe-pipeline.md) — writer obligations
- [../contracts/store-readers.md](../contracts/store-readers.md) — reader obligations
