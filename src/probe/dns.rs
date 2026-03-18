//! DNS resolution prober

use crate::anomaly::AnomalyDetector;
use crate::models::{DnsRecord, DnsStatus, LogRecord};
use crate::probe::ProbeError;
use crate::store::{DnsData, SharedStore};
use anyhow::Result;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{Instant, interval};
use tokio_util::sync::CancellationToken;

/// Type alias for TokioResolver (hickory-resolver 0.25+)
pub type TokioResolver = Resolver<TokioConnectionProvider>;

/// Information about DNS IP changes
#[derive(Debug, Clone)]
pub struct DnsChangeInfo {
    pub old_ips: HashSet<IpAddr>,
    pub new_ips: HashSet<IpAddr>,
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

/// DNS Prober
pub struct DnsProber {
    target: String,
    resolver: TokioResolver,
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
            let name_servers = NameServerConfigGroup::from_ips_clear(&[server], 53, true);
            let config = ResolverConfig::from_parts(None, vec![], name_servers);
            let mut opts = ResolverOpts::default();
            opts.timeout = timeout;
            opts.attempts = 2;
            (config, opts)
        } else {
            // Use system configuration with custom options
            let mut opts = ResolverOpts::default();
            opts.timeout = timeout;
            opts.attempts = 2;
            (ResolverConfig::default(), opts)
        };

        let resolver =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
                .with_options(opts)
                .build();

        Ok(Self {
            target: target.to_string(),
            resolver,
            previous_ips: HashSet::new(),
            timeout,
        })
    }

    /// Perform a DNS resolution
    pub async fn resolve(&mut self) -> DnsResult {
        let start = Instant::now();

        // Perform the lookup with timeout
        let lookup_result =
            tokio::time::timeout(self.timeout, self.resolver.lookup_ip(&self.target)).await;

        let elapsed = start.elapsed();
        let resolve_ms = elapsed.as_secs_f64() * 1000.0;

        match lookup_result {
            Ok(Ok(lookup)) => {
                // Extract IP addresses
                let ips: Vec<IpAddr> = lookup.iter().collect();
                let current_ips: HashSet<IpAddr> = ips.iter().cloned().collect();

                // Get TTL from the response records
                let ttl_secs = lookup.as_lookup().records().iter().map(|r| r.ttl()).next();

                // Get the server used (from resolver config)
                let server = self.get_dns_server_string();

                // Detect changes
                let change_info =
                    if !self.previous_ips.is_empty() && self.previous_ips != current_ips {
                        Some(DnsChangeInfo {
                            old_ips: self.previous_ips.clone(),
                            new_ips: current_ips.clone(),
                        })
                    } else {
                        None
                    };

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
                // DNS error (NXDOMAIN, SERVFAIL, etc.)
                let status = if e.is_nx_domain() {
                    DnsStatus::Nxdomain
                } else {
                    // Check for SERVFAIL by examining the error kind
                    let error_str = format!("{:?}", e);
                    if error_str.contains("SERVFAIL") {
                        DnsStatus::Servfail
                    } else {
                        DnsStatus::Timeout
                    }
                };

                DnsResult {
                    resolve_ms,
                    ips: vec![],
                    ttl_secs: None,
                    server: self.get_dns_server_string(),
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
                    server: self.get_dns_server_string(),
                    status: DnsStatus::Timeout,
                    change_info: None,
                }
            }
        }
    }

    /// Get DNS server as string for logging
    fn get_dns_server_string(&self) -> String {
        // Try to get the first nameserver from config
        self.resolver
            .config()
            .name_servers()
            .first()
            .map(|ns| ns.socket_addr.to_string())
            .unwrap_or_else(|| "system".to_string())
    }

    /// Get a reference to the resolver (for testing)
    #[allow(dead_code)]
    fn resolver(&self) -> &TokioResolver {
        &self.resolver
    }

    /// Get the target
    #[allow(dead_code)]
    pub fn target(&self) -> &str {
        &self.target
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

    // Perform initial DNS resolution immediately (check cancellation first)
    if !cancel.is_cancelled() {
        let initial_result = prober.resolve().await;
        process_dns_result(&initial_result, &store, &log_tx, &target, &detector).await;
    }

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
        // Simulate two consecutive DNS resolutions with different IPs
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "1.0.0.1".parse().unwrap();
        let ip3: IpAddr = "8.8.8.8".parse().unwrap();

        // First resolution - no previous IPs, so no change
        let mut previous_ips: HashSet<IpAddr> = HashSet::new();
        let current_ips_1: HashSet<IpAddr> = [ip1, ip2].iter().cloned().collect();

        let change_info_1 = if !previous_ips.is_empty() && previous_ips != current_ips_1 {
            Some(DnsChangeInfo {
                old_ips: previous_ips.clone(),
                new_ips: current_ips_1.clone(),
            })
        } else {
            None
        };

        assert!(
            change_info_1.is_none(),
            "First resolution should not trigger change"
        );

        // Update previous IPs
        previous_ips = current_ips_1;

        // Second resolution - different IPs, should trigger change
        let current_ips_2: HashSet<IpAddr> = [ip1, ip3].iter().cloned().collect();

        let change_info_2 = if !previous_ips.is_empty() && previous_ips != current_ips_2 {
            Some(DnsChangeInfo {
                old_ips: previous_ips.clone(),
                new_ips: current_ips_2.clone(),
            })
        } else {
            None
        };

        assert!(
            change_info_2.is_some(),
            "Second resolution should trigger change"
        );
        let change = change_info_2.unwrap();
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
        previous_ips = current_ips_2;
        let current_ips_3: HashSet<IpAddr> = [ip1, ip3].iter().cloned().collect();

        let change_info_3 = if !previous_ips.is_empty() && previous_ips != current_ips_3 {
            Some(DnsChangeInfo {
                old_ips: previous_ips.clone(),
                new_ips: current_ips_3.clone(),
            })
        } else {
            None
        };

        assert!(
            change_info_3.is_none(),
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
