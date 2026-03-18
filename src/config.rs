use std::net::IpAddr;
use std::path::PathBuf;

/// Configuration for netprobe, derived from CLI arguments
#[derive(Debug, Clone)]
pub struct Config {
    /// Target host (domain or IP address)
    pub target: String,
    /// Path to JSONL log file
    pub log_path: PathBuf,
    /// TCP/HTTP port
    pub port: u16,
    /// HTTP path for healthcheck
    pub http_path: String,
    /// Disable HTTP(S) probing
    pub no_http: bool,
    /// Disable TLS (use plain HTTP)
    pub no_tls: bool,
    /// ICMP ping interval in milliseconds
    pub interval_icmp_ms: u64,
    /// DNS resolve interval in seconds
    pub interval_dns_sec: u64,
    /// TCP/HTTP probe interval in seconds
    pub interval_tcp_sec: u64,
    /// Traceroute interval in seconds
    pub interval_trace_sec: u64,
    /// Ring buffer history size in samples
    pub history: usize,
    /// ICMP probe timeout in milliseconds
    pub timeout_icmp_ms: u64,
    /// TCP connect timeout in milliseconds
    pub timeout_tcp_ms: u64,
    /// DNS resolution timeout in milliseconds
    pub timeout_dns_ms: u64,
    /// HTTP response timeout in milliseconds
    pub timeout_http_ms: u64,
    /// Traceroute timeout in milliseconds
    pub timeout_trace_ms: u64,
    /// Explicit DNS server (optional)
    pub dns_server: Option<IpAddr>,
    /// Quiet mode (no TUI, only logging)
    pub quiet: bool,
}

impl Config {
    /// Default ICMP interval: 1000ms
    pub const DEFAULT_INTERVAL_ICMP_MS: u64 = 1000;
    /// Default DNS interval: 30 seconds
    pub const DEFAULT_INTERVAL_DNS_SEC: u64 = 30;
    /// Default TCP interval: 10 seconds
    pub const DEFAULT_INTERVAL_TCP_SEC: u64 = 10;
    /// Default traceroute interval: 60 seconds
    pub const DEFAULT_INTERVAL_TRACE_SEC: u64 = 60;
    /// Default history size: 3600 samples
    pub const DEFAULT_HISTORY: usize = 3600;
    /// Default ICMP timeout: 2000ms
    pub const DEFAULT_TIMEOUT_ICMP_MS: u64 = 2000;
    /// Default TCP timeout: 5000ms
    pub const DEFAULT_TIMEOUT_TCP_MS: u64 = 5000;
    /// Default DNS timeout: 5000ms
    pub const DEFAULT_TIMEOUT_DNS_MS: u64 = 5000;
    /// Default HTTP timeout: 10000ms
    pub const DEFAULT_TIMEOUT_HTTP_MS: u64 = 10000;
    /// Default traceroute timeout: 30000ms (30 seconds)
    pub const DEFAULT_TIMEOUT_TRACE_MS: u64 = 30000;
    /// Default port: 443
    pub const DEFAULT_PORT: u16 = 443;
    /// Default HTTP path: /
    pub const DEFAULT_HTTP_PATH: &str = "/";
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target: String::new(),
            log_path: PathBuf::from("netprobe-default.jsonl"),
            port: Self::DEFAULT_PORT,
            http_path: Self::DEFAULT_HTTP_PATH.to_string(),
            no_http: false,
            no_tls: false,
            interval_icmp_ms: Self::DEFAULT_INTERVAL_ICMP_MS,
            interval_dns_sec: Self::DEFAULT_INTERVAL_DNS_SEC,
            interval_tcp_sec: Self::DEFAULT_INTERVAL_TCP_SEC,
            interval_trace_sec: Self::DEFAULT_INTERVAL_TRACE_SEC,
            history: Self::DEFAULT_HISTORY,
            timeout_icmp_ms: Self::DEFAULT_TIMEOUT_ICMP_MS,
            timeout_tcp_ms: Self::DEFAULT_TIMEOUT_TCP_MS,
            timeout_dns_ms: Self::DEFAULT_TIMEOUT_DNS_MS,
            timeout_http_ms: Self::DEFAULT_TIMEOUT_HTTP_MS,
            timeout_trace_ms: Self::DEFAULT_TIMEOUT_TRACE_MS,
            dns_server: None,
            quiet: false,
        }
    }
}
