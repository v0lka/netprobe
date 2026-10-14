# DNS Prober

## Role

Periodically resolves the target domain with hickory-resolver, measures resolution time, tracks the resolved IP set, and detects address-set changes between consecutive successful resolutions.

## Key Files

- `src/probe/dns.rs` — `DnsProber`, `DnsResult`, `DnsChangeInfo`, `dns_probe_loop`, `process_dns_result`

## Behavior

### Resolver setup

`DnsProber::new(target, dns_server, timeout)` builds a `Resolver<TokioConnectionProvider>`:

- With `--dns-server <IP>`: `NameServerConfigGroup::from_ips_clear(&[server], 53, true)`, `ResolverConfig::from_parts` — plain UDP DNS to that server only.
- Without: the system resolver configuration via `hickory_resolver::system_conf::read_system_conf()` (e.g. `/etc/resolv.conf` on Unix, the registry on Windows) — note `ResolverConfig::default()` is Google Public DNS in hickory 0.25, not the system config.
- Both: `ResolverOpts { timeout, attempts: 2 }`.

### Resolution

`DnsProber::resolve() -> DnsResult` wraps `resolver.lookup_ip(target)` in `tokio::time::timeout(timeout_dns_ms * (DNS_ATTEMPTS + 1))` — the resolver's `timeout` is per attempt and `attempts` counts retries, so the whole lookup gets `(attempts + 1) × timeout` before the outer cap fires:

| Outcome | Status | Fields |
| ------- | ------ | ------ |
| Lookup success | `Ok` | `resolve_ms` (wall time incl. timeout wrapper), `ips` (all A/AAAA answers), `ttl_secs` (TTL of the first record), `server` (first nameserver as `"<ip>:53"` from config, or the literal `"system"` fallback), `change_info` (see below) |
| Resolver error, `is_nx_domain()` | `Nxdomain` | empty `ips`, `server` |
| Resolver error with response code `ServFail` (typed check: `ResolveErrorKind::Proto(ProtoErrorKind::NoRecordsFound { response_code: ServFail, .. })` — not a `Debug`-string match) | `Servfail` | empty `ips` |
| Other resolver error (transport refused/unreachable, malformed reply, …) | `Timeout` | empty `ips` |
| Outer timeout elapsed | `Timeout` | empty `ips` |

### Change detection

`change_info` is produced only when the previous successful resolution had a non-empty IP set and the set differs (`HashSet<IpAddr>` comparison, order-insensitive):

```rust
pub struct DnsChangeInfo { pub old_ips: HashSet<IpAddr>, pub new_ips: HashSet<IpAddr> }
```

The first resolution never triggers a change; `previous_ips` updates only on successful resolutions.

### Probe loop

`dns_probe_loop` resolves once immediately (unless cancelled), then every `interval_dns_sec`. `process_dns_result` per resolution:

1. Write lock: on success `store.push_dns_resolve(ms)` and `store.set_latest_dns(Some(DnsData{…}), None)`; on failure `set_latest_dns(None, Some("DNS <status>"))`.
2. Send `LogRecord::Dns(DnsRecord)` — every resolution is logged, success or failure.
3. On `change_info`: generate `detector.on_dns_change(old, new)` → `store.push_event` + `LogRecord::Event` (`dns_change`).

Note: the DNS prober resolves the original target hostname throughout the session. It does not follow the active-IP watch (`ip_rx`) — IP switching affects ICMP/TCP/traceroute targets, not the resolution cadence.

## Error Handling

- Resolution failures map into the `DnsStatus` taxonomy above; the loop continues on the next tick.
- `resolve_ms` is recorded even for failed lookups, but only successful resolutions enter the resolve-time history (`push_dns_resolve`).

## Invariants

1. Every DNS attempt produces exactly one `dns` JSONL record.
2. `dns_change` events fire only from the second successful resolution onward, and only when the IP set (not the order) changed.
3. Only successful resolutions update `previous_ips`, so a transient failure between two different successful sets still yields a single change event covering both.
4. The resolver is built once per session; `--dns-server` replaces the entire system config.

## Related Specs

- [README.md](README.md) — loop pattern, configuration table
- [../anomaly-detection.md](../anomaly-detection.md) — `on_dns_change` event shape
- [../../contracts/jsonl-log-format.md](../../contracts/jsonl-log-format.md) — `dns` record schema
- [../../contracts/cli-to-app.md](../../contracts/cli-to-app.md) — `--dns-server` and startup resolution (separate resolver in `app.rs`)
