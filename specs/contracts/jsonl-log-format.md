# Contract: JSONL Log Format (on-disk)

## Boundary Rule

This is the **external** interface between netprobe and log consumers (scripts, analyzers, replay tooling). The schema is defined solely by the serde structs in `src/models.rs`; nothing else may shape the file. One JSON object per line, UTF-8, newline-delimited; every record carries `"ts"` (RFC 3339, `DateTime<Utc>`) and `"target"`.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | -------- | ----------- | ------- |
| `LogRecord` (serde internally-tagged `"type"`, snake_case) | `models.rs` | `logger.rs` writes; external tools read | the entire schema |
| `Logger` flush guarantees | `logger.rs` | external tailing tools | durability expectations |

## Initialization

The file is created/truncated at startup (`Logger::new`); the first line is always `session_start`. Default location: `./netprobe-<target>-<unix-secs>.jsonl`, overridable via `--log`.

## Record Schemas

Discriminant values (`"type"`): `icmp`, `dns`, `tcp`, `tls`, `http`, `traceroute`, `event`, `session_start`, `session_end`.

**icmp**
| Field | Type | Notes |
| ----- | ---- | ----- |
| `seq` | u16 | probe sequence |
| `rtt_ms` | f64 \| null | `null` on timeout/error |
| `ttl` | u8 \| null | IPv4 replies only |
| `status` | `ok` \| `timeout` \| `error` | |

**dns**
| `resolve_ms` f64 · `ips` [string] · `ttl_secs` u32 \| null · `server` string | `status`: `ok` \| `nxdomain` \| `servfail` \| `timeout` — `ips` empty on failure |

**tcp**
| `port` u16 · `connect_ms` f64 \| null | `status`: `ok` \| `refused` \| `timeout` \| `reset` |

**tls**
| `port` u16 · `handshake_ms` f64 \| null · `version` string \| null (e.g. `TLSv1.3`) · `cipher` string \| null · `cert_subject` string \| null · `cert_issuer` string \| null · `cert_san` [string] \| null · `cert_expiry` RFC 3339 \| null · `cert_days_remaining` i64 \| null | `status`: `ok` \| `error` — all metric fields `null` on error |

**http**
| `port` u16 · `path` string · `ttfb_ms` f64 \| null · `total_ms` f64 \| null · `status_code` u16 \| null | `status`: `ok` \| `error` (`error` also for status ≥ 400) |

**traceroute**
| `hops` [{ `hop` u8 · `ip` string \| null · `rtt_ms` f64 \| null · `host` string \| null }] · `hop_count` u8 | `status`: `ok` \| `error` — exactly one record per trace attempt; error attempts carry `status: error` with empty `hops` (see [../domains/probing/traceroute.md](../domains/probing/traceroute.md)) |

**event**
| `event` string (see [../domains/anomaly-detection.md](../domains/anomaly-detection.md) for the catalog) · `severity` `info` \| `warning` \| `critical` · `value` f64 \| null · `threshold` f64 \| null · `sigma` f64 \| null · `message` string | emitted for: `rtt_spike`, `jitter_spike`, `loss_burst`, `dns_change`, `cert_expiry_warning`, `http_error`, `tcp_refused` |

**session_start**
| `resolved_target` string \| null · `traceroute_available` bool · `config` { `port` u16 · `interval_icmp_ms` u64 · `interval_dns_sec` u64 · `interval_tcp_sec` u64 · `interval_trace_sec` u64 · `history_size` usize · `icmp_strategy` string (`unprivileged` \| `raw` \| `subprocess`) } | exactly the first record |

**session_end**
| `duration_sec` u64 · `summary` { `icmp_sent` u64 · `icmp_received` u64 · `loss_pct` f64 · `rtt_avg_ms` f64 · `rtt_p95_ms` f64 · `uptime_pct` f64 · `mos` f64 (1.0–4.5) · `grade` `"A"`…`"F"` (char) · `events_total` u64 } | last record of a graceful session |

## Data Flow Across Boundary

Producer → file only. Consumers never influence the process. Ordering within a line of sight: probes interleave by wall-clock; `event` records are flushed immediately, others at ≤ 5 s granularity (see [../domains/logging.md](../domains/logging.md)). Files under ungraceful termination (kill -9) end without `session_end`.

## Error Propagation

Serialization errors abort the logger task (records after the failure are lost, file retains prior lines); startup file-creation errors abort the whole run with exit 1.

## Breaking Change Checklist

- **Adding an optional field**: additive — safe; still update this file and `docs/USER_GUIDE.md` (log format section).
- **Adding a record type / status value**: consumers doing exhaustive matching will break — call it out in release notes; update `models.rs`, this contract, and the anomaly catalog if applicable.
- **Renaming/removing a field or changing semantics**: breaking — prefer a new field + deprecation window; bump the project version and document migration.
- **Changing `session_start`/`session_end` shape**: breaking for session-parsing tools — coordinate with `app.rs` record builders and `contracts/cli-to-app.md`.
- **Changing flush/durability guarantees**: update `domains/logging.md` before changing `Logger` constants.
