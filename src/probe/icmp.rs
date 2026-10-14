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
use tokio::time::interval;
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
    ///
    /// Construction is infallible: when neither the unprivileged (SOCK_DGRAM)
    /// nor the raw-socket (SOCK_RAW) client can be created, the prober falls
    /// back to spawning the platform `ping` subprocess.
    pub async fn new(target: IpAddr, timeout: Duration) -> (Self, IcmpStrategy) {
        // Select the ICMP family from the target address: a V6 target with a
        // V4 client only surfaces as SocketError/timeout instead of a
        // working ping.
        let kind = if target.is_ipv6() { ICMP::V6 } else { ICMP::V4 };

        // Try unprivileged socket first (SOCK_DGRAM)
        let config = PingConfig::builder()
            .kind(kind)
            .sock_type_hint(Type::DGRAM)
            .build();

        if let Ok(client) = Client::new(&config) {
            return (
                Self {
                    target,
                    timeout,
                    strategy: IcmpStrategy::Unprivileged,
                    client: Some(client),
                    seen_seqs: std::collections::HashSet::new(),
                    last_seq: 0,
                },
                IcmpStrategy::Unprivileged,
            );
        }

        // Try raw socket (SOCK_RAW)
        let config = PingConfig::builder()
            .kind(kind)
            .sock_type_hint(Type::RAW)
            .build();

        if let Ok(client) = Client::new(&config) {
            return (
                Self {
                    target,
                    timeout,
                    strategy: IcmpStrategy::Raw,
                    client: Some(client),
                    seen_seqs: std::collections::HashSet::new(),
                    last_seq: 0,
                },
                IcmpStrategy::Raw,
            );
        }

        // Fall back to subprocess
        (
            Self {
                target,
                timeout,
                strategy: IcmpStrategy::Subprocess,
                client: None,
                seen_seqs: std::collections::HashSet::new(),
                last_seq: 0,
            },
            IcmpStrategy::Subprocess,
        )
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

                // Check for duplicates and reordering using the sequence
                // number *echoed by the reply*, not our locally generated
                // probe index: every probe passes a fresh, strictly
                // increasing index, so tracking our own indices can never
                // observe a duplicate or reorder.
                let reply_seq = packet.get_sequence().into_u16();
                let is_duplicate = !self.seen_seqs.insert(reply_seq);
                let is_reordered = reply_seq < self.last_seq;

                if reply_seq > self.last_seq {
                    self.last_seq = reply_seq;
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
            Ok(Err(e)) => {
                // An ICMP error that is not a lost packet (e.g. destination
                // unreachable, time exceeded, malformed reply) is an Error,
                // not a Timeout: only the elapsed outer timeout below is a
                // Timeout.
                tracing::debug!("ICMP probe error: {}", e);
                Ok(IcmpResult {
                    rtt: None,
                    ttl: None,
                    seq,
                    status: IcmpStatus::Error,
                    duplicate: false,
                    reordered: false,
                })
            }
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
        let mut command = {
            let mut c = Command::new("ping");
            c.args([
                "-n",
                "1",
                "-w",
                &(timeout_sec * 1000).to_string(),
                &target_str,
            ]);
            c
        };

        #[cfg(not(target_os = "windows"))]
        let mut command = {
            // `ping -W` takes seconds on Linux iputils but *milliseconds* on
            // macOS/BSD ("Time in MilliSeconds to wait for a reply for each
            // packet sent").
            let wait_time = if cfg!(target_os = "macos") {
                (timeout_sec * 1000).to_string()
            } else {
                timeout_sec.to_string()
            };
            // macOS `ping` rejects IPv6 literals (and has no -6 flag); its
            // `ping6` counterpart is the IPv6 fallback. Linux iputils and
            // Windows `ping` select the family from the target themselves.
            // (`args` returns a handle borrowing the command, so the command
            // is bound first and the arguments attached as a statement.)
            if cfg!(target_os = "macos") && self.target.is_ipv6() {
                let mut c = Command::new("ping6");
                c.args(["-c", "1", &target_str]);
                c
            } else {
                let mut c = Command::new("ping");
                c.args(["-c", "1", "-W", &wait_time, &target_str]);
                c
            }
        };

        // Kill the child when this future is dropped mid-wait: the outer
        // `tokio::time::timeout` below abandons `command.output()` at the
        // deadline, and without `kill_on_drop` an unresponsive target would
        // leave an orphaned `ping`/`ping6` process running past the probe.
        command.kill_on_drop(true);

        // Bound the subprocess wait ourselves as a platform-agnostic backstop:
        // macOS `ping6` takes no wait flag we can rely on, and a wedged `ping`
        // must not stall the loop's cadence beyond `timeout_icmp_ms` (the
        // per-platform wait flags above already bound the normal paths).
        let output = match tokio::time::timeout(self.timeout, command.output()).await {
            Ok(result) => {
                result.map_err(|e| ProbeError::Other(format!("Failed to execute ping: {}", e)))?
            }
            // Killed at the deadline without answering: a lost probe
            Err(_) => {
                return Ok(IcmpResult {
                    rtt: None,
                    ttl: None,
                    seq,
                    status: IcmpStatus::Timeout,
                    duplicate: false,
                    reordered: false,
                });
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Check for timeout indicators across platforms:
        // - Windows: "Request timed out."
        // - macOS/BSD: "Request timeout for icmp_seq N", "100.0% packet loss",
        //   "0 packets received"
        // - Linux iputils: "Request timeout for icmp_seq N", "100% packet
        //   loss", "0 received"
        if stdout.contains("Request timed out")
            || stdout.contains("Request timeout")
            || stdout.contains("100% packet loss")
            || stdout.contains("100.0% packet loss")
            || stdout.contains("0 received")
            || stdout.contains("0 packets received")
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

        // One-shot `ping -c 1` cannot observe duplicates or reordering: each
        // attempt runs an independent process whose reply echoes that run's
        // own constant counter (`icmp_seq=0` on macOS/BSD and `ping6`,
        // `icmp_seq=1` on Linux iputils; Windows omits it entirely), so the
        // echoed value carries no session-unique information. Both flags stay
        // `false` on this path; duplicate/reorder detection is only
        // meaningful on the in-process surge path.
        Ok(IcmpResult {
            rtt,
            ttl,
            seq,
            status: IcmpStatus::Ok,
            duplicate: false,
            reordered: false,
        })
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
    // Windows also prints `time<1ms` for sub-millisecond replies (`<` form)
    let windows_regex = Regex::new(r"time[=:<]([\d.]+)ms.*TTL[=:](\d+)").unwrap();

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
#[allow(clippy::too_many_arguments)]
pub async fn icmp_probe_loop(
    mut prober: IcmpProber,
    store: SharedStore,
    log_tx: mpsc::Sender<LogRecord>,
    interval_ms: u64,
    target: String,
    cancel: CancellationToken,
    mut ip_rx: tokio::sync::watch::Receiver<std::net::IpAddr>,
    reset_notify: std::sync::Arc<tokio::sync::Notify>,
) -> Result<()> {
    let mut ticker = interval(Duration::from_millis(interval_ms));
    let mut seq: u16 = 0;
    let mut detector = AnomalyDetector::new();

    loop {
        // Wait for next tick, cancellation, IP change, or statistics reset
        // (biased to prioritize cancellation)
        tokio::select! {
            biased;

            _ = cancel.cancelled() => {
                tracing::info!("ICMP probe loop cancelled");
                break;
            }
            res = ip_rx.changed() => {
                // Closed channel: run_tui (the only sender) is gone — treat
                // it as shutdown rather than an IP change, so the loop does
                // not run one more probe on the TUI error-exit path
                if res.is_err() {
                    break;
                }
                let new_ip = *ip_rx.borrow();
                tracing::info!("ICMP probe updating target to: {}", new_ip);
                prober.update_target(new_ip);
                // Reset sequence tracking on IP change
                seq = 0;
                // Start a fresh anomaly-detection baseline: the previous
                // target's RTT/jitter samples must not score the new
                // endpoint's first samples
                detector = AnomalyDetector::new();
            }
            _ = reset_notify.notified() => {
                tracing::info!("ICMP anomaly detector reset (statistics reset)");
                // The store's statistics were reset (r hotkey); the detector
                // must re-warm against the fresh baseline instead of scoring
                // new samples against pre-reset windows
                detector = AnomalyDetector::new();
                continue;
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
                // Update the store in one short critical section: the write
                // guard must never be held across the channel sends below
                // (a full `log_tx` would otherwise stall the TUI's read lock
                // while the sender awaits backpressure)
                let anomalies = {
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

                    for anomaly in &anomalies {
                        store.push_event(
                            anomaly.event_type.clone(),
                            anomaly.severity.clone(),
                            anomaly.message.clone(),
                        );
                    }
                    anomalies
                };

                // The write guard is dropped above: the sends below never
                // hold it
                for anomaly in &anomalies {
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
                    {
                        let mut store = store.write().await;
                        store.push_event(
                            anomaly.event_type.clone(),
                            anomaly.severity.clone(),
                            anomaly.message.clone(),
                        );
                    }
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
    fn test_parse_ping_output_windows_sub_millisecond() {
        // Windows prints `time<1ms` for fast replies; this must parse as a
        // successful reply, not an error.
        let output = "Reply from 192.168.1.1: bytes=32 time<1ms TTL=64";
        let (rtt, ttl) = parse_ping_output(output).unwrap();

        assert!(rtt.is_some());
        assert!((rtt.unwrap().as_secs_f64() * 1000.0 - 1.0).abs() < 0.001);
        assert_eq!(ttl, Some(64));
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
