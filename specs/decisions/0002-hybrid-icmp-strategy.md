# ADR-0002: Hybrid ICMP strategy with subprocess fallback

## Status

Accepted

## Context

ICMP echo requires socket privileges that vary by OS, kernel version, and sysctl state. A monitoring tool that hard-requires root excludes the most common use case (unprivileged user on a normal Linux box); a tool that silently degrades to nothing is useless. Linux ≥ 3.0 supports unprivileged ICMP via `SOCK_DGRAM` + `IPPROTO_ICMP` when `net.ipv4.ping_group_range` permits; macOS allows DGRAM ICMP for wheel users; `SOCK_RAW` needs `CAP_NET_RAW`/root. As a last resort, the system `ping` binary is setuid/authorized almost everywhere.

## Decision

`IcmpProber::new` probes capabilities once at startup, in fixed order, and pins the strategy for the process lifetime:

1. `surge-ping` client with `SOCK_DGRAM` (`Type::DGRAM`) → `IcmpStrategy::Unprivileged`
2. `surge-ping` client with `SOCK_RAW` (`Type::RAW`) → `IcmpStrategy::Raw`
3. system `ping` subprocess (`ping -c 1 -W` Unix / `ping -n 1 -w` Windows, output parsed by regex) → `IcmpStrategy::Subprocess`

The chosen strategy is reported in `session_start.config.icmp_strategy`; the startup `info!` line about the strategy surfaces transiently in the TUI logs panel (via `TuiTracingLayer`), and no dashboard element renders it. The three strategies share one `IcmpResult` shape, so the probe loop and anomaly detection are strategy-agnostic.

## Consequences

Positive:

- Works out of the box for unprivileged users on modern Linux; improves silently with `setcap cap_net_raw+ep`.
- Traceroute privilege checking can reuse the same signal chain (see [ADR-0005](0005-traceroute-privilege-gating.md)).
- Strategy visibility in `session_start` makes logs self-describing.

Negative:

- Subprocess mode adds ~process-spawn latency per probe, regex fragility across `ping` implementations (mitigated by tests for macOS/Linux/Windows formats), and loses precise sequence/TTL semantics.
- Strategy is fixed at startup: privilege changes mid-session are not picked up until restart.
- Dual code paths (surge vs parse) must be kept behaviorally aligned (duplicate/reorder flags, timeout mapping).

## Alternatives Considered

- **Require root/cap always** — rejected: unusable default experience for the primary audience.
- **Runtime re-negotiation on repeated failures** — rejected: strategy flapping would corrupt aggregate baselines and duplicate/reorder tracking; deterministic behavior wins.
- **Library-only (no subprocess)** — rejected: unmonitored ICMP on locked-down hosts is worse than approximate subprocess RTT.

## Related Specs

- [../domains/probing/icmp.md](../domains/probing/icmp.md) — implementation and loop behavior
