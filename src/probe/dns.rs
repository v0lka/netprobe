//! DNS resolution prober

use crate::anomaly::AnomalyDetector;
use crate::models::{DnsRecord, DnsStatus, LogRecord};
use crate::probe::ProbeError;
use crate::store::{DnsData, SharedStore};
use anyhow::Result;
pub use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{Instant, interval};
use tokio_util::sync::CancellationToken;

/// DNS retry count for the resolver (`attempts` are retries after a timeout,
/// so a lookup can legitimately run up to `DNS_ATTEMPTS + 1` per-request
/// timeouts before giving up).
const DNS_ATTEMPTS: usize = 2;

/// Information about DNS IP changes
#[derive(Debug, Clone)]
pub struct DnsChangeInfo {
    pub old_ips: HashSet<IpAddr>,
    pub new_ips: HashSet<IpAddr>,
}

/// Detect a change in the resolved IP set
///
/// Returns `None` for the first resolution (nothing to compare against) and
/// whenever the resolved set is unchanged; otherwise describes the old and
/// new sets.
fn detect_dns_change(
    previous_ips: &HashSet<IpAddr>,
    current_ips: &HashSet<IpAddr>,
) -> Option<DnsChangeInfo> {
    if !previous_ips.is_empty() && previous_ips != current_ips {
        Some(DnsChangeInfo {
            old_ips: previous_ips.clone(),
            new_ips: current_ips.clone(),
        })
    } else {
        None
    }
}

/// Result of a DNS resolution
#[derive(Debug, Clone)]
pub struct DnsResult {
    pub resolve_ms: f64,
    pub ips: Vec<IpAddr>,
    pub ttl_secs: Option<u32>,
    pub server: String,
    pub status: DnsStatus,
    pub change_info: Option<DnsChangeInfo>,
}

/// Classify a resolver error as SERVFAIL by its typed response code.
///
/// hickory surfaces a SERVFAIL response as a `Dns` error carrying
/// `DnsError::ResponseCode`; matching on the discriminant (rather than the
/// error's `Debug` string) keeps the classification stable across hickory
/// releases.
fn is_servfail(e: &NetError) -> bool {
    matches!(
        e,
        NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail))
    )
}

/// DNS Prober
pub struct DnsProber {
    target: String,
    resolver: TokioResolver,
    server: String,
    previous_ips: HashSet<IpAddr>,
    timeout: Duration,
}

impl DnsProber {
    /// Create a new DNS prober
    pub fn new(
        target: &str,
        dns_server: Option<IpAddr>,
        timeout: Duration,
    ) -> Result<Self, ProbeError> {
        // Build resolver config
        let (config, opts) = if let Some(server) = dns_server {
            // Use explicit DNS server
            let name_servers = vec![NameServerConfig::udp_and_tcp(server)];
            let config = ResolverConfig::from_parts(None, vec![], name_servers);
            let mut opts = ResolverOpts::default();
            opts.timeout = timeout;
            opts.attempts = DNS_ATTEMPTS;
            (config, opts)
        } else {
            // Use the system resolver configuration (e.g. /etc/resolv.conf on
            // Unix, the registry on Windows). `ResolverConfig::default()` is
            // Google Public DNS in hickory 0.25/0.26, not the system config.
            let (config, mut opts) =
                hickory_resolver::system_conf::read_system_conf().map_err(|e| {
                    ProbeError::Other(format!("Failed to read system DNS configuration: {}", e))
                })?;
            opts.timeout = timeout;
            opts.attempts = DNS_ATTEMPTS;
            (config, opts)
        };

        // Remember the first nameserver for reporting: `Resolver::config()`
        // no longer exists in hickory 0.26, so capture it up front. Keep the
        // historical `"<ip>:<port>"` format (port from the first connection).
        let server = config
            .name_servers()
            .first()
            .map(|ns| match ns.connections.first() {
                Some(conn) => format!("{}:{}", ns.ip, conn.port),
                None => ns.ip.to_string(),
            })
            .unwrap_or_else(|| "system".to_string());

        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| ProbeError::Other(format!("Failed to build DNS resolver: {}", e)))?;

        Ok(Self {
            target: target.to_string(),
            resolver,
            server,
            previous_ips: HashSet::new(),
            timeout,
        })
    }

    /// Perform a DNS resolution
    pub async fn resolve(&mut self) -> DnsResult {
        let start = Instant::now();

        // Perform the lookup with an overall cap sized to admit the retries:
        // the resolver's `timeout` is per attempt and `attempts` counts
        // retries, so the whole lookup can legitimately take up to
        // (attempts + 1) × timeout before it must give up.
        let lookup_result = tokio::time::timeout(
            self.timeout * (DNS_ATTEMPTS as u32 + 1),
            self.resolver.lookup_ip(&self.target),
        )
        .await;

        let elapsed = start.elapsed();
        let resolve_ms = elapsed.as_secs_f64() * 1000.0;

        match lookup_result {
            Ok(Ok(lookup)) => {
                // Extract IP addresses
                let ips: Vec<IpAddr> = lookup.iter().collect();
                let current_ips: HashSet<IpAddr> = ips.iter().cloned().collect();

                // Get TTL from the response records
                let ttl_secs = lookup.as_lookup().answers().iter().map(|r| r.ttl).next();

                // Get the server used (from resolver config)
                let server = self.server.clone();

                // Detect changes
                let change_info = detect_dns_change(&self.previous_ips, &current_ips);

                // Update previous IPs
                self.previous_ips = current_ips;

                DnsResult {
                    resolve_ms,
                    ips,
                    ttl_secs,
                    server,
                    status: DnsStatus::Ok,
                    change_info,
                }
            }
            Ok(Err(e)) => {
                // DNS error (NXDOMAIN, SERVFAIL, transport failures, ...)
                let status = if e.is_nx_domain() {
                    DnsStatus::Nxdomain
                } else if is_servfail(&e) {
                    DnsStatus::Servfail
                } else {
                    DnsStatus::Timeout
                };

                DnsResult {
                    resolve_ms,
                    ips: vec![],
                    ttl_secs: None,
                    server: self.server.clone(),
                    status,
                    change_info: None,
                }
            }
            Err(_) => {
                // Timeout
                DnsResult {
                    resolve_ms,
                    ips: vec![],
                    ttl_secs: None,
                    server: self.server.clone(),
                    status: DnsStatus::Timeout,
                    change_info: None,
                }
            }
        }
    }
}

/// Main DNS probe loop
pub async fn dns_probe_loop(
    mut prober: DnsProber,
    store: SharedStore,
    log_tx: mpsc::Sender<LogRecord>,
    interval_sec: u64,
    target: String,
    cancel: CancellationToken,
) -> Result<()> {
    let mut ticker = interval(Duration::from_secs(interval_sec));
    let detector = AnomalyDetector::new();

    // Note: `tokio::time::interval`'s first tick completes immediately, so the
    // loop below performs exactly one resolution right away, then ticks —
    // no separate pre-loop resolve is needed (that used to emit two
    // back-to-back records at startup).

    loop {
        // Wait for next tick or cancellation (biased to prioritize cancellation)
        tokio::select! {
            biased;

            _ = cancel.cancelled() => {
                tracing::info!("DNS probe loop cancelled");
                break;
            }
            _ = ticker.tick() => {}
        }

        // Check cancellation before probe
        if cancel.is_cancelled() {
            tracing::info!("DNS probe loop cancelled");
            break;
        }

        let result = prober.resolve().await;
        process_dns_result(&result, &store, &log_tx, &target, &detector).await;
    }

    Ok(())
}

/// Process a DNS result - update store and send log record
async fn process_dns_result(
    result: &DnsResult,
    store: &SharedStore,
    log_tx: &mpsc::Sender<LogRecord>,
    target: &str,
    detector: &AnomalyDetector,
) {
    // Update store
    {
        let mut store = store.write().await;

        // Push resolve time if successful
        let is_ok = matches!(result.status, DnsStatus::Ok);
        if is_ok {
            store.push_dns_resolve(result.resolve_ms);
        }

        // Set latest DNS result
        let data = if is_ok {
            Some(DnsData {
                resolve_ms: result.resolve_ms,
                ips: result.ips.clone(),
                ttl_secs: result.ttl_secs,
                server: result.server.clone(),
            })
        } else {
            None
        };

        let error = if !is_ok {
            Some(format!("DNS {:?}", result.status))
        } else {
            None
        };

        store.set_latest_dns(data, error);
    }

    // Create and send DNS record
    let record = DnsRecord {
        ts: chrono::Utc::now(),
        target: target.to_string(),
        resolve_ms: result.resolve_ms,
        ips: result.ips.iter().map(|ip| ip.to_string()).collect(),
        ttl_secs: result.ttl_secs,
        server: result.server.clone(),
        status: result.status.clone(),
    };

    let _ = log_tx.send(LogRecord::Dns(record)).await;

    // Handle DNS change detection with AnomalyDetector
    if let Some(ref change_info) = result.change_info {
        tracing::info!(
            "DNS change detected: old_ips={:?}, new_ips={:?}",
            change_info.old_ips,
            change_info.new_ips
        );

        // Generate and send DNS change event
        let anomaly = detector.on_dns_change(&change_info.old_ips, &change_info.new_ips);

        {
            let mut store = store.write().await;
            store.push_event(
                anomaly.event_type.clone(),
                anomaly.severity.clone(),
                anomaly.message.clone(),
            );
        }

        let event_record = detector.to_event_record(&anomaly, target);
        let _ = log_tx.send(LogRecord::Event(event_record)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_change_detection() {
        // Drive the same predicate the prober uses (detect_dns_change)
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "1.0.0.1".parse().unwrap();
        let ip3: IpAddr = "8.8.8.8".parse().unwrap();

        // First resolution - no previous IPs, so no change
        let previous_ips: HashSet<IpAddr> = HashSet::new();
        let current_ips_1: HashSet<IpAddr> = [ip1, ip2].iter().cloned().collect();

        assert!(
            detect_dns_change(&previous_ips, &current_ips_1).is_none(),
            "First resolution should not trigger change"
        );

        // Second resolution - different IPs, should trigger change
        let current_ips_2: HashSet<IpAddr> = [ip1, ip3].iter().cloned().collect();

        let change = detect_dns_change(&current_ips_1, &current_ips_2)
            .expect("Second resolution should trigger change");
        assert!(
            change.old_ips.contains(&ip2),
            "Old IPs should contain 1.0.0.1"
        );
        assert!(
            !change.new_ips.contains(&ip2),
            "New IPs should not contain 1.0.0.1"
        );
        assert!(
            change.new_ips.contains(&ip3),
            "New IPs should contain 8.8.8.8"
        );

        // Third resolution - same IPs, no change
        assert!(
            detect_dns_change(&current_ips_2, &current_ips_2).is_none(),
            "Third resolution should not trigger change (same IPs)"
        );
    }

    #[test]
    fn test_dns_result_structure() {
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "1.0.0.1".parse().unwrap();

        let result = DnsResult {
            resolve_ms: 4.2,
            ips: vec![ip1, ip2],
            ttl_secs: Some(286),
            server: "192.168.1.1".to_string(),
            status: DnsStatus::Ok,
            change_info: None,
        };

        assert_eq!(result.resolve_ms, 4.2);
        assert_eq!(result.ips.len(), 2);
        assert_eq!(result.ttl_secs, Some(286));
        assert_eq!(result.server, "192.168.1.1");
        assert!(matches!(result.status, DnsStatus::Ok));
    }
}
