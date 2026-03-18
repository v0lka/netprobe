//! ICMP ping prober

use crate::anomaly::AnomalyDetector;
use crate::models::{IcmpRecord, IcmpStatus, LogRecord};
use crate::probe::{IcmpStrategy, ProbeError};
use crate::store::SharedStore;
use anyhow::Result;
use regex::Regex;
use socket2::Type;
use std::net::IpAddr;
use std::time::Duration;
use surge_ping::{Client, Config as PingConfig, ICMP, PingIdentifier, PingSequence};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::{Instant, interval};
use tokio_util::sync::CancellationToken;

/// Result of a single ICMP probe with duplicate/reorder detection
#[derive(Debug, Clone)]
pub struct IcmpResult {
    pub rtt: Option<Duration>,
    pub ttl: Option<u8>,
    pub seq: u16,
    pub status: IcmpStatus,
    pub duplicate: bool,
    pub reordered: bool,
}

/// ICMP Prober with hybrid strategy
pub struct IcmpProber {
    target: IpAddr,
    timeout: Duration,
    strategy: IcmpStrategy,
    client: Option<Client>,
    seen_seqs: std::collections::HashSet<u16>,
    last_seq: u16,
}

impl IcmpProber {
    /// Create a new ICMP prober with automatic strategy selection
    pub async fn new(target: IpAddr, timeout: Duration) -> Result<(Self, IcmpStrategy)> {
        // Try unprivileged socket first (SOCK_DGRAM)
        let config = PingConfig::builder()
            .kind(ICMP::V4)
            .sock_type_hint(Type::DGRAM)
            .build();

        match Client::new(&config) {
            Ok(client) => Ok((
                Self {
                    target,
                    timeout,
                    strategy: IcmpStrategy::Unprivileged,
                    client: Some(client),
                    seen_seqs: std::collections::HashSet::new(),
                    last_seq: 0,
                },
                IcmpStrategy::Unprivileged,
            )),
            Err(_) => {
                // Try raw socket (SOCK_RAW)
                let config = PingConfig::builder()
                    .kind(ICMP::V4)
                    .sock_type_hint(Type::RAW)
                    .build();

                match Client::new(&config) {
                    Ok(client) => Ok((
                        Self {
                            target,
                            timeout,
                            strategy: IcmpStrategy::Raw,
                            client: Some(client),
                            seen_seqs: std::collections::HashSet::new(),
                            last_seq: 0,
                        },
                        IcmpStrategy::Raw,
                    )),
                    Err(_) => {
                        // Fall back to subprocess
                        Ok((
                            Self {
                                target,
                                timeout,
                                strategy: IcmpStrategy::Subprocess,
                                client: None,
                                seen_seqs: std::collections::HashSet::new(),
                                last_seq: 0,
                            },
                            IcmpStrategy::Subprocess,
                        ))
                    }
                }
            }
        }
    }

    /// Perform a single ping
    pub async fn ping(&mut self, seq: u16) -> Result<IcmpResult, ProbeError> {
        match self.strategy {
            IcmpStrategy::Unprivileged | IcmpStrategy::Raw => self.ping_surge(seq).await,
            IcmpStrategy::Subprocess => self.ping_subprocess(seq).await,
        }
    }

    /// Ping using surge-ping library
    async fn ping_surge(&mut self, seq: u16) -> Result<IcmpResult, ProbeError> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| ProbeError::SocketError("No client available".to_string()))?;

        let payload = vec![0; 56];
        let _start = Instant::now();

        // Create a Pinger for this specific target
        let mut pinger = client.pinger(self.target, PingIdentifier(0)).await;

        let ping_future = pinger.ping(PingSequence(seq), &payload);

        match tokio::time::timeout(self.timeout, ping_future).await {
            Ok(Ok((packet, rtt))) => {
                // Extract TTL from the packet
                let ttl = match &packet {
                    surge_ping::IcmpPacket::V4(p) => p.get_ttl(),
                    surge_ping::IcmpPacket::V6(_) => None, // IPv6 doesn't have TTL in the same way
                };

                // Check for duplicates and reordering
                let is_duplicate = !self.seen_seqs.insert(seq);
                let is_reordered = seq < self.last_seq;

                if seq > self.last_seq {
                    self.last_seq = seq;
                }

                Ok(IcmpResult {
                    rtt: Some(rtt),
                    ttl,
                    seq,
                    status: IcmpStatus::Ok,
                    duplicate: is_duplicate,
                    reordered: is_reordered,
                })
            }
            Ok(Err(_)) => Ok(IcmpResult {
                rtt: None,
                ttl: None,
                seq,
                status: IcmpStatus::Timeout,
                duplicate: false,
                reordered: false,
            }),
            Err(_) => Ok(IcmpResult {
                rtt: None,
                ttl: None,
                seq,
                status: IcmpStatus::Timeout,
                duplicate: false,
                reordered: false,
            }),
        }
    }

    /// Ping using subprocess fallback
    async fn ping_subprocess(&mut self, seq: u16) -> Result<IcmpResult, ProbeError> {
        let target_str = self.target.to_string();
        let timeout_sec = self.timeout.as_secs().max(1);

        #[cfg(target_os = "windows")]
        let output = Command::new("ping")
            .args([
                "-n",
                "1",
                "-w",
                &(timeout_sec * 1000).to_string(),
                &target_str,
            ])
            .output()
            .await
            .map_err(|e| ProbeError::Other(format!("Failed to execute ping: {}", e)))?;

        #[cfg(not(target_os = "windows"))]
        let output = Command::new("ping")
            .args(["-c", "1", "-W", &timeout_sec.to_string(), &target_str])
            .output()
            .await
            .map_err(|e| ProbeError::Other(format!("Failed to execute ping: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Check for timeout indicators
        if stdout.contains("Request timed out")
            || stdout.contains("100% packet loss")
            || stdout.contains("0 received")
            || stdout.contains("Destination Host Unreachable")
        {
            return Ok(IcmpResult {
                rtt: None,
                ttl: None,
                seq,
                status: IcmpStatus::Timeout,
                duplicate: false,
                reordered: false,
            });
        }

        // Parse RTT and TTL from output
        let (rtt, ttl) = parse_ping_output(&stdout)?;

        // Check for duplicates and reordering
        let is_duplicate = !self.seen_seqs.insert(seq);
        let is_reordered = seq < self.last_seq;

        if seq > self.last_seq {
            self.last_seq = seq;
        }

        Ok(IcmpResult {
            rtt,
            ttl,
            seq,
            status: IcmpStatus::Ok,
            duplicate: is_duplicate,
            reordered: is_reordered,
        })
    }

    /// Get the current strategy
    #[allow(dead_code)]
    pub fn strategy(&self) -> IcmpStrategy {
        self.strategy
    }

    /// Update the target IP address
    pub fn update_target(&mut self, target: IpAddr) {
        self.target = target;
        // Reset sequence tracking when target changes
        self.seen_seqs.clear();
        self.last_seq = 0;
    }
}

/// Parse ping command output to extract RTT and TTL
fn parse_ping_output(output: &str) -> Result<(Option<Duration>, Option<u8>), ProbeError> {
    // macOS format: "64 bytes from 1.1.1.1: icmp_seq=0 ttl=56 time=14.2 ms"
    // Linux format: "64 bytes from 1.1.1.1: icmp_seq=1 ttl=56 time=14.2 ms"
    // Windows format: "Reply from 1.1.1.1: bytes=32 time=14ms TTL=56"

    // Try macOS/Linux format first
    let macos_regex = Regex::new(r"ttl[=:](\d+).*time[=:]([\d.]+)\s*ms").unwrap();
    let windows_regex = Regex::new(r"time[=:]([\d.]+)ms.*TTL[=:](\d+)").unwrap();

    if let Some(caps) = macos_regex.captures(output) {
        let ttl = caps.get(1).and_then(|m| m.as_str().parse::<u8>().ok());
        let rtt_ms = caps.get(2).and_then(|m| m.as_str().parse::<f64>().ok());
        let rtt = rtt_ms.map(|ms| Duration::from_secs_f64(ms / 1000.0));
        return Ok((rtt, ttl));
    }

    // Try Windows format
    if let Some(caps) = windows_regex.captures(output) {
        let rtt_ms = caps.get(1).and_then(|m| m.as_str().parse::<f64>().ok());
        let ttl = caps.get(2).and_then(|m| m.as_str().parse::<u8>().ok());
        let rtt = rtt_ms.map(|ms| Duration::from_secs_f64(ms / 1000.0));
        return Ok((rtt, ttl));
    }

    Err(ProbeError::ParseError(
        "Could not parse ping output".to_string(),
    ))
}

/// Main ICMP probe loop
pub async fn icmp_probe_loop(
    mut prober: IcmpProber,
    store: SharedStore,
    log_tx: mpsc::Sender<LogRecord>,
    interval_ms: u64,
    target: String,
    cancel: CancellationToken,
    mut ip_rx: tokio::sync::watch::Receiver<std::net::IpAddr>,
) -> Result<()> {
    let mut ticker = interval(Duration::from_millis(interval_ms));
    let mut seq: u16 = 0;
    let mut detector = AnomalyDetector::new();

    loop {
        // Wait for next tick, cancellation, or IP change (biased to prioritize cancellation)
        tokio::select! {
            biased;

            _ = cancel.cancelled() => {
                tracing::info!("ICMP probe loop cancelled");
                break;
            }
            _ = ip_rx.changed() => {
                let new_ip = *ip_rx.borrow();
                tracing::info!("ICMP probe updating target to: {}", new_ip);
                prober.update_target(new_ip);
                // Reset sequence tracking on IP change
                seq = 0;
            }
            _ = ticker.tick() => {}
        }

        // Check cancellation before probe
        if cancel.is_cancelled() {
            tracing::info!("ICMP probe loop cancelled");
            break;
        }

        // Increment sent counter
        {
            let mut store = store.write().await;
            store.inc_icmp_sent();
        }

        // Perform ping
        match prober.ping(seq).await {
            Ok(result) => {
                let mut store = store.write().await;

                // Handle duplicate detection
                if result.duplicate {
                    store.inc_icmp_duplicate();
                }

                // Handle reordering detection
                if result.reordered {
                    store.inc_icmp_reordered();
                }

                // Process result with anomaly detector
                let anomalies = if let Some(rtt) = result.rtt {
                    let rtt_ms = rtt.as_secs_f64() * 1000.0;
                    store.push_icmp_rtt(rtt_ms);
                    detector.on_icmp_ok(rtt_ms)
                } else {
                    // Timeout - check for loss burst
                    if let Some(anomaly) = detector.on_icmp_loss() {
                        vec![anomaly]
                    } else {
                        vec![]
                    }
                };

                // Send anomaly events to store and logger
                for anomaly in &anomalies {
                    store.push_event(
                        anomaly.event_type.clone(),
                        anomaly.severity.clone(),
                        anomaly.message.clone(),
                    );
                    let event_record = detector.to_event_record(anomaly, &target);
                    let _ = log_tx.send(LogRecord::Event(event_record)).await;
                }

                // Create and send record
                let record = IcmpRecord {
                    ts: chrono::Utc::now(),
                    target: target.clone(),
                    seq: result.seq,
                    rtt_ms: result.rtt.map(|d| d.as_secs_f64() * 1000.0),
                    ttl: result.ttl,
                    status: result.status,
                };

                let _ = log_tx.send(LogRecord::Icmp(record)).await;
            }
            Err(e) => {
                // Check for loss burst on error
                if let Some(anomaly) = detector.on_icmp_loss() {
                    let mut store = store.write().await;
                    store.push_event(
                        anomaly.event_type.clone(),
                        anomaly.severity.clone(),
                        anomaly.message.clone(),
                    );
                    let event_record = detector.to_event_record(&anomaly, &target);
                    let _ = log_tx.send(LogRecord::Event(event_record)).await;
                }

                // Send error record
                let record = IcmpRecord {
                    ts: chrono::Utc::now(),
                    target: target.clone(),
                    seq,
                    rtt_ms: None,
                    ttl: None,
                    status: IcmpStatus::Error,
                };

                let _ = log_tx.send(LogRecord::Icmp(record)).await;

                tracing::warn!("ICMP probe error: {}", e);
            }
        }

        seq = seq.wrapping_add(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ping_output_macos() {
        let output = "64 bytes from 1.1.1.1: icmp_seq=0 ttl=56 time=14.234 ms";
        let (rtt, ttl) = parse_ping_output(output).unwrap();

        assert!(rtt.is_some());
        assert!((rtt.unwrap().as_secs_f64() * 1000.0 - 14.234).abs() < 0.001);
        assert_eq!(ttl, Some(56));
    }

    #[test]
    fn test_parse_ping_output_linux() {
        let output = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=64 time=0.526 ms";
        let (rtt, ttl) = parse_ping_output(output).unwrap();

        assert!(rtt.is_some());
        assert!((rtt.unwrap().as_secs_f64() * 1000.0 - 0.526).abs() < 0.001);
        assert_eq!(ttl, Some(64));
    }

    #[test]
    fn test_parse_ping_output_windows() {
        let output = "Reply from 1.1.1.1: bytes=32 time=14ms TTL=56";
        let (rtt, ttl) = parse_ping_output(output).unwrap();

        assert!(rtt.is_some());
        assert!((rtt.unwrap().as_secs_f64() * 1000.0 - 14.0).abs() < 0.001);
        assert_eq!(ttl, Some(56));
    }

    #[test]
    fn test_parse_ping_output_windows_decimal() {
        let output = "Reply from 8.8.8.8: bytes=32 time=23.456ms TTL=117";
        let (rtt, ttl) = parse_ping_output(output).unwrap();

        assert!(rtt.is_some());
        assert!((rtt.unwrap().as_secs_f64() * 1000.0 - 23.456).abs() < 0.001);
        assert_eq!(ttl, Some(117));
    }

    #[test]
    fn test_parse_ping_output_multiline() {
        let output = r#"PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=56 time=14.234 ms

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 14.234/14.234/14.234/0.000 ms"#;

        let (rtt, ttl) = parse_ping_output(output).unwrap();

        assert!(rtt.is_some());
        assert!((rtt.unwrap().as_secs_f64() * 1000.0 - 14.234).abs() < 0.001);
        assert_eq!(ttl, Some(56));
    }
}
