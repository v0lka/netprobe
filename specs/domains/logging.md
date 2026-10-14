# Logging

## Purpose

Single-writer JSONL persistence: every probe result, anomaly event, and session boundary is serialized by `serde` (`src/models.rs`) and appended to one file by the logger task (`src/logger.rs`) through an mpsc channel. Quiet and TUI modes log identically; the file is the only durable artifact of a session.

## Key Files

- `src/logger.rs` — `Logger` (channel setup + writer loop)
- `src/models.rs` — `LogRecord` enum and all record structs/status enums (serde schemas)
- `src/app.rs` — creates the logger, sends `session_start`/`session_end`

## Core Types

```rust
// src/models.rs — one enum, internally tagged via serde
// (the discriminant is a field inside the record object, not a wrapper)
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LogRecord {
    Icmp(IcmpRecord), Dns(DnsRecord), Tcp(TcpRecord), Tls(TlsRecord),
    Http(HttpRecord), Traceroute(TracerouteRecord), Event(EventRecord),
    SessionStart(SessionStartRecord), SessionEnd(SessionEndRecord),
}

// src/logger.rs
pub struct Logger { writer: BufWriter<tokio::fs::File> }
impl Logger {
    pub const CHANNEL_BUFFER_SIZE: usize = 1024;
    pub const FLUSH_INTERVAL_SECS: u64 = 5;
    pub async fn new(path: &Path) -> Result<(Self, mpsc::Sender<LogRecord>, mpsc::Receiver<LogRecord>)>;
    pub async fn run(self, rx: mpsc::Receiver<LogRecord>, cancel: CancellationToken) -> Result<()>;
}
```

`Logger::new` creates/truncates the file and owns the mpsc channel (returns writer, sender, and receiver for `app.rs` to wire up). `run` is the writer loop: receive → `serde_json::to_string` → `write_all` + `\n`.

## Flow

```
probe loop ──▶ log_tx.send(LogRecord) ──▶ mpsc channel (buffer 1024)
                                              │
              app.rs: session_start/session_end ┘
                                              ▼
        Logger::run: rx.recv() ─▶ serde_json::to_string ─▶ BufWriter<File>::write_all + '\n'
                                              │ flush points:
                                              ├─▶ Event record received → immediate flush()
                                              ├─▶ 5 s tick → flush if dirty
                                              ├─▶ cancel fired (once) → flush, keep draining
                                              └─▶ channel closed → final flush, exit
```

Readers are external tailers only — nothing in-process reads the file back.

## Behavior

### Flush policy

| Trigger | Action |
| ------- | ------ |
| `LogRecord::Event` received | immediate `flush()` — anomalies are durable ASAP |
| Every 5 s tick (`FLUSH_INTERVAL_SECS`) | flush if anything was written since last flush |
| Cancellation token fires | one flush; loop keeps draining until channel closes |
| Channel closed (all senders dropped) | final flush, writer loop exits |
| Write/serialize error | `run` returns `Err` — logged by the spawner; records are not re-queued |

### Session records

- `session_start` is sent by `app.rs` before probe tasks spawn — first data record in every file.
- `session_end` is sent after all probe tasks joined, with the summary (MOS, grade, uptime, counters) computed from a store read lock — last data record in a graceful session.

### Status enums (snake_case on the wire)

- `IcmpStatus`: `ok | timeout | error`
- `DnsStatus`: `ok | nxdomain | servfail | timeout`
- `TcpStatus`: `ok | refused | timeout | reset`
- `TlsStatus`: `ok | error`
- `HttpStatus`: `ok | error`
- `TracerouteStatus`: `ok | error` (one `traceroute` record per attempt — see [probing/traceroute.md](probing/traceroute.md))
- `Severity`: `info | warning | critical`

`Option` fields have their JSON keys **omitted entirely** when absent (`#[serde(skip_serializing_if = "Option::is_none")]` — e.g. `rtt_ms` on timeout, TLS fields on handshake failure). A consumer must not assume these keys are present; absence means "no value".

### Tracing (diagnostics) vs JSONL (data)

The `tracing` subsystem is separate from JSONL logging:

- Quiet mode: `tracing_subscriber::fmt().with_writer(std::io::stderr)` — diagnostics go to stderr, keeping stdout clean.
- TUI mode: `TuiTracingLayer` (`src/tui_tracing.rs`) captures tracing **events** (no span callbacks) into a `TracingLogReceiver`; a consumer task forwards them to `store.push_log_event` → logs deque → TUI logs panel. Tracing output never enters the JSONL file.

## Invariants

1. The logger task is the only writer of the log file; all producers go through the mpsc channel.
2. `session_start` precedes all probe records; `session_end` follows all probe records in a graceful shutdown.
3. Every `event` record is flushed to disk before the next channel item is processed.
4. Record schemas live only in `models.rs` — probe loops never hand-build JSON.
5. A failed log-file creation is fatal to startup (`app.rs` context: "Failed to create logger"); runtime write failures do not stop the session.

## Configuration

- Log path: `--log <PATH>`; default `./netprobe-<sanitized-target>-<unix-timestamp>.jsonl` (built in `main.rs::into_config`, which replaces target characters outside `A-Za-z0-9._-` with `_`).
- Channel buffer: 1024 records (`CHANNEL_BUFFER_SIZE`); a full channel makes senders await (natural backpressure) — probes block on send, not drop.
- Flush interval: 5 s (compile-time constant).

## Extension Points

- **New record type**: add struct + `LogRecord` variant in `models.rs` (tag inherits `snake_case`); send it from the owning probe loop; update `contracts/jsonl-log-format.md`.
- **Alternate sink** (e.g. Prometheus, second file): add a sibling task consuming `log_tx` via a cloned `Sender` — do not write inside probe loops.

## Related Specs

- [../contracts/jsonl-log-format.md](../contracts/jsonl-log-format.md) — full on-disk schema tables
- [metrics-store.md](metrics-store.md) — in-memory counterpart of the same data
- [../architecture/concurrency.md](../architecture/concurrency.md) — logger task lifecycle and shutdown ordering
