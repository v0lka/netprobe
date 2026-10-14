# ADR-0001: Low-level TLS/HTTP probing instead of an HTTP client crate

## Status

Accepted

## Context

The L7 layer must report four independent timings per tick: TCP connect, TLS handshake, HTTP TTFB, and total HTTP time, plus certificate details (subject, issuer, SAN, expiry). Off-the-shelf HTTP clients (e.g. `reqwest`) perform TCP+TLS+request as one opaque step: they expose total time and (with `tls_info`) the certificate, but not the split between connect and handshake, and not TTFB. The original design doc (`.qoder/specs/netprobe-spec.md`) explicitly evaluated this trade-off.

## Decision

Build the L7 pipeline manually: `socket2` non-blocking TCP connect → `tokio-rustls` handshake over that stream (`ring` provider, webpki roots) → hand-written minimal `GET path HTTP/1.1` request on the established stream. Certificates come from `rustls` peer certificates, parsed with `x509-parser`. Implemented in `src/probe/tcp.rs` (pipeline + connect), `src/probe/tls.rs` (handshake + cert parsing), `src/probe/http.rs` (raw GET + status-line parse).

## Consequences

Positive:

- Every phase is individually timed and logged (`tcp`, `tls`, `http` records) — the core value of the tool.
- Certificate inspection (SAN, days remaining) enables the `cert_expiry_warning` detector.
- No tower/hyper dependency stack; smaller attack surface for a diagnostic tool.
- TLS stage can be disabled (`--no-tls`) while keeping HTTP over plain TCP with the same code path.

Negative:

- Hand-rolled HTTP/1.1: only the status line is parsed; redirects, chunked bodies, and TLS-session resumption nuances are ignored by design.
- `rustls` config must be rebuilt per handshake (no session reuse) — acceptable at the 10 s default cadence.
- The TLS stage reuses `timeout_tcp_ms` (no dedicated TLS timeout knob yet).

## Alternatives Considered

- **`reqwest` + `tls_info(true)`** — rejected: single fused timing for connect+TLS; handshake time unrecoverable; heavier dependency tree.
- **`hyper` with connector hooks** — rejected: still couples the HTTP state machine to the timings, significantly more complex than a 30-line raw GET for a healthcheck.
- **Shelling out to `openssl s_client` / `curl -w`** — rejected: parsing stability across platforms, subprocess overhead, and no IPv6-parity guarantees.

## Related Specs

- [../domains/probing/tcp-tls-http.md](../domains/probing/tcp-tls-http.md) — the implementation
- [../contracts/jsonl-log-format.md](../contracts/jsonl-log-format.md) — `tcp`/`tls`/`http` record schemas
