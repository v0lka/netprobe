use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use tracing_subscriber::prelude::*;

mod anomaly;
mod app;
mod config;
mod logger;
mod models;
mod probe;
mod store;
mod tui;
mod tui_tracing;
mod util;

use config::Config;
use tui_tracing::TuiTracingLayer;

/// Network quality monitoring tool with TUI dashboard
#[derive(Parser, Debug)]
#[command(name = "netprobe")]
#[command(about = "Deep network connection quality monitoring with TUI dashboard")]
#[command(version)]
#[command(after_help = "\
ELEVATED PRIVILEGES:
  Traceroute functionality on Linux/macOS requires raw socket access.
  Without elevated privileges, netprobe will run but traceroute will be disabled.

  Linux:   sudo setcap cap_net_raw+ep ./netprobe   (one-time setup, then run without sudo)
           or run with: sudo ./netprobe <target>

  macOS:   sudo ./netprobe <target>

  Windows: Traceroute works without elevated privileges (uses tracert.exe)

EXAMPLES:
  netprobe example.com              Monitor example.com with default settings
  netprobe 1.1.1.1 --no-http        Monitor IP without HTTP probing
  netprobe example.com -q --log out.jsonl   Quiet mode with logging")]
struct Cli {
    /// Target host (domain or IP address)
    target: String,

    /// Path to JSONL log file
    #[arg(long, value_name = "PATH")]
    log: Option<PathBuf>,

    /// TCP/HTTP port
    #[arg(long, value_name = "PORT", default_value_t = Config::DEFAULT_PORT)]
    port: u16,

    /// HTTP path for healthcheck
    #[arg(long, value_name = "PATH", default_value = Config::DEFAULT_HTTP_PATH)]
    http_path: String,

    /// Disable HTTP(S) probing
    #[arg(long)]
    no_http: bool,

    /// Disable TLS (use plain HTTP)
    #[arg(long)]
    no_tls: bool,

    /// ICMP ping interval in milliseconds
    #[arg(long, value_name = "MS", default_value_t = Config::DEFAULT_INTERVAL_ICMP_MS)]
    interval_icmp: u64,

    /// DNS resolve interval in seconds
    #[arg(long, value_name = "SEC", default_value_t = Config::DEFAULT_INTERVAL_DNS_SEC)]
    interval_dns: u64,

    /// TCP/HTTP probe interval in seconds
    #[arg(long, value_name = "SEC", default_value_t = Config::DEFAULT_INTERVAL_TCP_SEC)]
    interval_tcp: u64,

    /// Traceroute interval in seconds
    #[arg(long, value_name = "SEC", default_value_t = Config::DEFAULT_INTERVAL_TRACE_SEC)]
    interval_trace: u64,

    /// Ring buffer history size in samples
    #[arg(long, value_name = "N", default_value_t = Config::DEFAULT_HISTORY)]
    history: usize,

    /// ICMP probe timeout in milliseconds
    #[arg(long, value_name = "MS", default_value_t = Config::DEFAULT_TIMEOUT_ICMP_MS)]
    timeout_icmp: u64,

    /// TCP connect timeout in milliseconds
    #[arg(long, value_name = "MS", default_value_t = Config::DEFAULT_TIMEOUT_TCP_MS)]
    timeout_tcp: u64,

    /// DNS resolution timeout in milliseconds
    #[arg(long, value_name = "MS", default_value_t = Config::DEFAULT_TIMEOUT_DNS_MS)]
    timeout_dns: u64,

    /// HTTP response timeout in milliseconds
    #[arg(long, value_name = "MS", default_value_t = Config::DEFAULT_TIMEOUT_HTTP_MS)]
    timeout_http: u64,

    /// Traceroute timeout in milliseconds
    #[arg(long, value_name = "MS", default_value_t = Config::DEFAULT_TIMEOUT_TRACE_MS)]
    timeout_trace: u64,

    /// Explicit DNS server
    #[arg(long, value_name = "IP")]
    dns_server: Option<IpAddr>,

    /// Quiet mode (no TUI, only logging)
    #[arg(short, long)]
    quiet: bool,
}

impl Cli {
    /// Convert CLI arguments to Config
    fn into_config(self) -> Config {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let log_path = self.log.unwrap_or_else(|| {
            PathBuf::from(format!("./netprobe-{}-{}.jsonl", self.target, timestamp))
        });

        Config {
            target: self.target,
            log_path,
            port: self.port,
            http_path: self.http_path,
            no_http: self.no_http,
            no_tls: self.no_tls,
            interval_icmp_ms: self.interval_icmp,
            interval_dns_sec: self.interval_dns,
            interval_tcp_sec: self.interval_tcp,
            interval_trace_sec: self.interval_trace,
            history: self.history,
            timeout_icmp_ms: self.timeout_icmp,
            timeout_tcp_ms: self.timeout_tcp,
            timeout_dns_ms: self.timeout_dns,
            timeout_http_ms: self.timeout_http,
            timeout_trace_ms: self.timeout_trace,
            dns_server: self.dns_server,
            quiet: self.quiet,
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let config = cli.into_config();

    // Initialize tracing based on mode
    let tracing_receiver = if config.quiet {
        // Quiet mode: use standard stderr subscriber
        tracing_subscriber::fmt::init();
        None
    } else {
        // TUI mode: use custom layer that captures logs for display
        let (layer, receiver) = TuiTracingLayer::new();
        tracing_subscriber::registry().with(layer).init();
        Some(receiver)
    };

    // Run the application
    if let Err(e) = app::run(config, tracing_receiver).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
