# ADR-0004: One JSONL file as the sole persistence

## Status

Accepted

## Context

netprobe produces six metric streams (icmp, dns, tcp, tls, http, traceroute) plus an anomaly event stream and session boundaries. Consumers range from `jq` one-liners and `tail -f` dashboards to future replay/analysis tooling. The data must remain inspectable on a plain host with no database or collector installed, and the session must be reconstructable end-to-end (config → raw probes → events → summary) from artifacts alone.

## Decision

Persist everything to a **single newline-delimited JSON file** (`--log`, default `./netprobe-<sanitized-target>-<timestamp>.jsonl`), written by one logger task. Each line is a self-contained serde-tagged record (`"type"` discriminant: `icmp`, `dns`, `tcp`, `tls`, `http`, `traceroute`, `event`, `session_start`, `session_end`); `session_start` embeds the effective config, `session_end` the session summary. Events flush immediately; other records flush at ≤ 5 s or on close.

## Consequences

Positive:

- Zero-dependency consumption: `grep`, `jq`, `awk`, `tail -f`, any log shipper — no exporter needed.
- Trivially appendable/streamable and safely truncatable per line; partially written last line (ungraceful kill) corrupts at most one record.
- Session self-description (`session_start.config`) makes files comparable across versions and hosts.
- Quiet mode needs no TUI store at all to remain fully useful.

Negative:

- No indexing/aggregation — analysis tools must scan; large files at 1 Hz ICMP (~86k lines/day) grow to tens of MB/day.
- No rotation: long sessions rely on the user's log management; the file is truncated on restart with the same `--log` path.
- One schema serves two audiences (machines and humans); field naming is frozen by the external contract.

## Alternatives Considered

- **SQLite** — rejected: heavier dependency, kills `tail`/`jq` ergonomics; aggregation is out of scope for v1.
- **Per-layer files** (`icmp.jsonl`, `events.jsonl`, …) — rejected: cross-layer correlation (e.g. did `http_error` follow a `route_change`?) requires timestamp alignment anyway; one timeline is simpler and loss-burst analysis depends on interleaving.
- **Prometheus endpoint first** — rejected as the persistence layer (pull model loses history across restarts); plausible as a future exporter, not a replacement.

## Related Specs

- [../contracts/jsonl-log-format.md](../contracts/jsonl-log-format.md) — the normative schema
- [../domains/logging.md](../domains/logging.md) — writer mechanics and flush policy
