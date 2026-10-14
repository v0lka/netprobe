# TCP / TLS / HTTP Pipeline

## Role

Measures connection-establishment quality in three sequential phases per tick — TCP connect time, TLS handshake time (+ certificate details), and HTTP TTFB/status — using low-level sockets so each phase is timed independently.

## Key Files

- `src/probe/tcp.rs` — `tcp_connect` (socket2 non-blocking connect), `tcp_tls_http_probe_loop` (pipeline owner)
- `src/probe/tls.rs` — `tls_handshake` (tokio-rustls), `TlsInfo`, certificate parsing (x509-parser)
- `src/probe/http.rs` — `http_probe` (raw HTTP/1.1 GET with TTFB), `parse_status_line`

## Behavior

### Stage 1 — TCP connect (`tcp_connect`)

1. `socket2::Socket::new(Domain::IPV4|IPV6, Type::STREAM)` → `set_nonblocking(true)`.
2. `connect(addr)`:
   - Immediate success → convert to `tokio::net::TcpStream`, measure elapsed.
   - `EINPROGRESS` (or `WSAEWOULDBLOCK` on Windows) → convert to tokio stream, await `stream.writable()` under `timeout(timeout_tcp_ms)`; a refused/reset peer still makes the socket writable, so the real outcome is observed via `SO_ERROR` (`stream.take_error()`) — only an empty `SO_ERROR` counts as connected.
   - Immediate refusal/reset → mapped error.
3. Failure classification: `SO_ERROR` kind (`ConnectionRefused` → `Refused`, `ConnectionReset` → `Reset`) or, for immediate connect errors, lowercased error-string matching (`refused` → `Refused`, `reset` → `Reset`); the elapsed outer timeout → `Timeout`.

Timing starts before socket creation and ends when the stream becomes writable — this is the reported `connect_ms`.

### Stage 2 — TLS handshake (`tls_handshake`, skipped when `--no-tls`)

1. Build `ClientConfig` with `ring` crypto provider and `webpki_roots` (Mozilla roots); wrapped in `TlsConnector`.
2. `connector.connect(ServerName::try_from(hostname), tcp_stream)` under `timeout(timeout_tcp_ms)` — note: the TLS stage uses `timeout_tcp_ms`, not a dedicated TLS timeout.
3. From the established connection (`conn = stream.get_ref().1`): protocol version (`TLSv1_x` formatting), negotiated cipher suite, `peer_certificates()` leaf parsed by `x509-parser` → subject, issuer, SAN list (DNS names + IP addresses), `not_after` → `cert_expiry` and `cert_days_remaining`.

`TlsInfo { handshake_ms, version, cipher, cert_subject, cert_issuer, cert_san, cert_expiry, cert_days_remaining }` — stored via `set_latest_tls` and pushed to history via `push_tls_handshake`.

`hostname` is the original CLI target string (SNI) — even when probing a switched IP, the handshake keeps the hostname.

### Stage 3 — HTTP probe (`http_probe`, skipped when `--no-http`)

1. Write minimal request: `GET <http_path> HTTP/1.1\r\nHost: <host>\r\nConnection: close\r\n\r\n` over the established (TLS or plain) stream, under `timeout(timeout_http_ms)`. IPv6 literal hosts are bracketed per RFC 7230 §5.4 (`Host: [2001:db8::1]`).
2. `TTFB` = time to first byte (`read_exact` of 1 byte).
3. Read until `\r\n` (status line complete); the whole phase runs under a single overall deadline (`timeout_http_ms` — the same timeout as the request/TTFB) plus a hard 8 KiB buffer cap (`MAX_STATUS_LINE_BUFFER`). Only a terminated status line is parsed: deadline expiry before `\r\n` fails the attempt as a timeout, and a connection closed mid-status-line fails it as a parse error — a truncated buffer is never parsed, so no bogus status code can be fabricated. `total_ms` = elapsed at that point.
4. `parse_status_line` → `u16` status code: the second whitespace-separated token of the first line, parsed as `u16`; the protocol token is not validated (HTTP/1.0, HTTP/1.1, and any `<token> <code>` status line are accepted).

### Loop orchestration (`tcp_tls_http_probe_loop`)

Per tick (interval `interval_tcp_sec`), and retargeting on `ip_rx.changed()`:

```
tcp_connect ──ok──▶ tcp record + store ──▶ tls_handshake ──ok──▶ tls record + store
     │                                          │                     │
     │ fail                                     │ fail                ▼
     ▼                                     tls error record     http_probe (unless --no-http)
  tcp error record  (+ tcp_refused                │                     │
   event when refused;                     (store: latest error)   │ ok: http record + store
   store: latest error)                                     │      (+ http_error event when
                                                            │       code >= 400)
                                                            └──▶ http error record
                                                                  (+ http_error event)
```

Cancellation is re-checked between stages; a cancel mid-pipeline breaks out without sending partial-stage records for stages not yet completed.

Cert-expiry checking runs on every successful handshake: `detector.on_cert_expiry(cert_days_remaining)` may emit a `cert_expiry_warning` event (each tick while the condition holds).

## Error Handling

- Every stage failure produces its own record with `status: Error` (fields `None`) and updates the store's latest-error slot; the loop continues next tick.
- TCP `Refused` additionally emits a `tcp_refused` event; HTTP status ≥ 400 or a failed request emits `http_error`.
- Stage failures abort only the remaining stages of that tick's pipeline (no TLS/HTTP after failed TCP; no HTTP after failed TLS).

## Invariants

1. The pipeline always progresses TCP → TLS → HTTP within a tick; stages never run concurrently or out of order.
2. A successful TCP connect is logged even if TLS/HTTP are disabled or fail.
3. `connect_ms` includes socket creation; `handshake_ms` covers only TLS; `ttfb_ms`/`total_ms` cover only the HTTP request on the already-established stream.
4. SNI/Host always use the original hostname; the connection target IP follows the active-IP watch.
5. With `--no-tls`, HTTP runs over the plain TCP stream (same socket, no TLS record emitted).

## Related Specs

- [README.md](README.md) — loop pattern, configuration table
- [../../contracts/jsonl-log-format.md](../../contracts/jsonl-log-format.md) — `tcp`, `tls`, `http` record schemas
- [../anomaly-detection.md](../anomaly-detection.md) — `tcp_refused`, `http_error`, `cert_expiry_warning` triggers
- [../../decisions/0001-low-level-tls-timing.md](../../decisions/0001-low-level-tls-timing.md) — why socket2+rustls instead of an HTTP client crate
