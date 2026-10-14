# Contract: CLI <-> App Orchestration

## Boundary Rule

Dependency points one way: `src/main.rs` (parsing) → `Config` (`src/config.rs`) → `app::run`. The app layer never reaches back into CLI types; everything it may know about user intent is captured in `Config`.

## Interfaces

| Interface | Crate/Module | Consumed By | Purpose |
| --------- | ------------ | ----------- | ------- |
| `clap::Parser` derive on `struct Cli` (`src/main.rs`) | clap 4 | `main` | argument definition, `--help`/`--version` |
| `Cli::into_config(self) -> Config` | `main.rs` | `main` | the only conversion point CLI → app |
| `Config` (`src/config.rs`) | plain struct + `DEFAULT_*` consts | `app::run`, probe loops, TUI | runtime configuration |
| `app::run(config, tracing_receiver) -> anyhow::Result<()>` | `app.rs` | `main` | whole application lifetime |

## Initialization

1. `main`: `Cli::parse()` → `cli.into_config()` (also builds the default log path `./netprobe-<sanitized-target>-<unix-secs>.jsonl`).
2. Tracing setup depends on `config.quiet`: quiet → `tracing_subscriber::fmt().with_writer(std::io::stderr).init()` (stderr); TUI → `TuiTracingLayer` registry + keep the `TracingLogReceiver`.
3. `main` calls `app::run(config, tracing_receiver).await`; on `Err` prints `Error: {e}` to stderr and exits with code 1.
4. `app::run` startup order: resolve target (IP passthrough without a reverse-DNS lookup, or DNS resolve preferring IPv4) → `IcmpProber::new` (strategy detection; construction is infallible — an unavailable ICMP transport falls back to the `subprocess` strategy) → traceroute prober construction (availability flag) → `MetricsStore` + logger creation (file failure is fatal) → `session_start` send → spawn tasks → TUI/quiet foreground.

## Data Flow Across Boundary

CLI string arguments → typed `Config` fields:

| CLI | Config field | Default |
| --- | ------------ | ------- |
| `<TARGET>` (positional) | `target: String` | required |
| `--log <PATH>` | `log_path: PathBuf` | `./netprobe-<sanitized-target>-<ts>.jsonl` |
| `--port <PORT>` | `port: u16` | 443 |
| `--http-path <PATH>` | `http_path: String` | `/` |
| `--no-http` / `--no-tls` | `no_http` / `no_tls: bool` | false |
| `--interval-icmp <MS>` | `interval_icmp_ms: u64` | 1000 |
| `--interval-dns <SEC>` | `interval_dns_sec: u64` | 30 |
| `--interval-tcp <SEC>` | `interval_tcp_sec: u64` | 10 |
| `--interval-trace <SEC>` | `interval_trace_sec: u64` | 60 |
| `--history <N>` | `history: usize` | 3600 |
| `--timeout-icmp <MS>` | `timeout_icmp_ms: u64` | 2000 |
| `--timeout-tcp <MS>` | `timeout_tcp_ms: u64` | 5000 |
| `--timeout-dns <MS>` | `timeout_dns_ms: u64` | 5000 |
| `--timeout-http <MS>` | `timeout_http_ms: u64` | 10000 |
| `--timeout-trace <MS>` | `timeout_trace_ms: u64` | 30000 |
| `--dns-server <IP>` | `dns_server: Option<IpAddr>` | system resolver |
| `-q, --quiet` | `quiet: bool` | false |

Defaults are owned by `Config::DEFAULT_*` constants (clap `default_value_t`/`default_value` references them) — `main.rs` carries no literal default values, except the computed `--log` path default, which is built in `main.rs::into_config` (`./netprobe-<sanitized-target>-<unix-secs>.jsonl`; there is intentionally no `DEFAULT_*` constant for it).

Validation also lives at the boundary, in the clap value parsers (`main.rs`): `--port` and every `--interval-*`/`--timeout-*` must be ≥ 1 (`tokio::time::interval(Duration::ZERO)` would panic), `--history` must be 1–1000000 (≥ 1 keeps aggregates/sparklines meaningful; the cap bounds the ring-buffer allocation), and `--http-path` must be an absolute path starting with `/` (it becomes the HTTP request-target). Violations are rejected by clap with a usage error (exit code 2) before `app::run` starts.

## Error Propagation

- **Fatal (anyhow with context, exit 1)**: unparseable args (clap exits 2 by itself), an unreadable system DNS configuration (`read_system_conf()` inside `create_resolver` — the error message suggests passing `--dns-server` to override), DNS resolution failure of the target at startup, log-file creation failure. (ICMP prober construction is infallible — it falls back to the `subprocess` strategy — so it cannot abort. `DnsProber::new` shares this system-config dependency and surfaces it as `ProbeError::Other`, but `app.rs` constructs the prober at startup with `.context("Failed to create DNS prober")?`, so this failure aborts startup too — in practice it is shadowed by `create_resolver` failing the same way one step earlier.)
- **Non-fatal (never cross this boundary as errors)**: individual probe failures — they are recorded as statuses/events; traceroute privilege issues; tracing consumer issues.

## Breaking Change Checklist

- **Adding a CLI option**: define it in `Cli` with `default_value_t = Config::DEFAULT_*` (or `Option`), add the field to `Config` + `Default` impl, map it in `into_config`, then update `contracts/cli-to-app.md`, the consuming domain's Configuration section, and `docs/USER_GUIDE.md`.
- **Renaming/removing an option**: grep docs and specs for the flag name; bump `session_start.config` schema only if the removed value was recorded there.
- **Changing a default**: update the `Config::DEFAULT_*` constant (single source), then `docs/USER_GUIDE.md`; `session_start` records effective values, so old logs stay interpretable.
- **Changing startup order**: `session_start` semantics (`resolved_target`, `icmp_strategy`, `traceroute_available`) are part of the JSONL contract — coordinate with `contracts/jsonl-log-format.md`.
