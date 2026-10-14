//! Traceroute prober

use crate::anomaly::{AnomalyDetector, AnomalyEvent, WindowedWelford};
use crate::models::{LogRecord, TracerouteRecord, TracerouteStatus};
use crate::probe::ProbeError;
use crate::store::HopData;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
#[cfg(windows)]
use tracing::error;
use tracing::{debug, info, warn};

/// Information about a route change
#[derive(Debug, Clone)]
pub struct RouteChangeInfo {
    pub description: String,
}

/// Information about a per-hop RTT anomaly
#[derive(Debug, Clone)]
pub struct HopRttAnomalyInfo {
    pub hop: u8,
    pub ip: Option<IpAddr>,
    pub rtt_ms: f64,
    pub mean: f64,
    pub stddev: f64,
    pub sigma: f64,
}

/// Result of a traceroute probe
#[derive(Debug, Clone)]
pub struct TracerouteResult {
    pub hops: Vec<HopData>,
    pub hop_count: u8,
    pub status: TracerouteStatus,
    pub error: Option<String>,
    pub route_change: Option<RouteChangeInfo>,
    pub hop_rtt_anomalies: Vec<HopRttAnomalyInfo>,
}

/// Traceroute prober
pub struct TracerouteProber {
    target: IpAddr,
    timeout: Duration,
    previous_hops: Vec<Option<IpAddr>>,
    /// Per-hop RTT baselines keyed by hop *IP* (not TTL): when the path
    /// changes and a TTL now resolves to a different router, the new router
    /// starts a fresh window instead of blending into the old baseline.
    hop_rtt_stats: HashMap<Option<IpAddr>, WindowedWelford>,
    /// Worker thread of the most recent timed-out trace (Unix). Kept so at
    /// most one timed-out trace can be alive at a time.
    #[cfg(not(windows))]
    trace_worker: Option<std::thread::JoinHandle<()>>,
}

impl TracerouteProber {
    /// Create a new traceroute prober
    ///
    /// On Unix this performs privilege discovery up front: without raw-socket
    /// privileges (root or `cap_net_raw`) traceroute is unavailable and the
    /// constructor fails with [`ProbeError::PermissionDenied`]. Windows
    /// `tracert.exe` needs no privileges, so construction always succeeds
    /// there. The per-trace check in `trace_unix` remains as a safety net for
    /// privileges dropped mid-session.
    pub fn new(target: IpAddr, timeout_ms: u64) -> Result<Self, ProbeError> {
        #[cfg(not(windows))]
        {
            use trippy_privilege::Privilege;

            let privilege = Privilege::discover()
                .map_err(|e| ProbeError::Other(format!("Failed to discover privileges: {}", e)))?;
            if !privilege.has_privileges() {
                return Err(ProbeError::PermissionDenied);
            }
        }

        Ok(Self {
            target,
            timeout: Duration::from_millis(timeout_ms),
            previous_hops: Vec::new(),
            hop_rtt_stats: HashMap::new(),
            #[cfg(not(windows))]
            trace_worker: None,
        })
    }

    /// Update the target IP address
    ///
    /// Hop RTT statistics and the previous-route history describe the path to
    /// the old target and are reset on retarget.
    pub fn update_target(&mut self, target: IpAddr) {
        self.target = target;
        self.previous_hops.clear();
        self.hop_rtt_stats.clear();
    }

    /// Perform a traceroute
    pub fn trace(&mut self) -> TracerouteResult {
        debug!("Starting traceroute to {}", self.target);

        #[cfg(windows)]
        {
            self.trace_windows()
        }

        #[cfg(not(windows))]
        {
            self.trace_unix()
        }
    }

    /// Windows-specific traceroute using tracert.exe
    #[cfg(windows)]
    fn trace_windows(&mut self) -> TracerouteResult {
        use regex::Regex;
        use std::process::Command;

        let target_str = self.target.to_string();

        // tracert has no overall timeout flag; bound the trace by deriving the
        // per-hop wait (`-w`) from --timeout-trace across the 30-hop maximum
        // (previously a hardcoded 1000 ms left the flag as a no-op here).
        let max_hops: u32 = 30;
        let total_ms = u32::try_from(self.timeout.as_millis()).unwrap_or(u32::MAX);
        let per_hop_wait_ms = (total_ms / max_hops).max(100);
        debug!("Running tracert -h 30 -w {per_hop_wait_ms} {}", target_str);

        // Run tracert in a blocking task to avoid blocking the async runtime
        let output = tokio::task::block_in_place(|| {
            Command::new("tracert")
                .args([
                    "-h",
                    &max_hops.to_string(),
                    "-w",
                    &per_hop_wait_ms.to_string(),
                    &target_str,
                ])
                .output()
        });

        let mut hop_data_vec: Vec<HopData> = Vec::new();
        let mut current_hops: Vec<Option<IpAddr>> = Vec::new();
        let mut hop_rtt_anomalies: Vec<HopRttAnomalyInfo> = Vec::new();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                if !stderr.is_empty() {
                    error!("tracert stderr: {}", stderr);
                }

                // Parse tracert output
                let ip_regex = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
                // Capture an optional `<`/`>` prefix so "<1 ms" is honored as
                // a sub-millisecond hop instead of being read as 1 ms
                let rtt_regex = Regex::new(r"([<>])?\s*(\d+)\s*ms").unwrap();

                for line in stdout.lines() {
                    // Parse lines like:
                    // "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
                    // "  2     *        *        *     Request timed out."
                    if let Some(first_char) = line.chars().next()
                        && (first_char.is_whitespace() || first_char.is_numeric())
                    {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2
                            && let Ok(hop_num) = parts[0].parse::<u8>()
                        {
                            // Find IP address
                            let ip = ip_regex.find(line).and_then(|m| m.as_str().parse().ok());

                            // Find RTT values; a `<` prefix reports a
                            // sub-millisecond reply, so record it below the
                            // 1 ms boundary (midpoint) rather than at it
                            let rtt_values: Vec<f64> = rtt_regex
                                .captures_iter(line)
                                .filter_map(|caps| {
                                    let n: f64 = caps.get(2)?.as_str().parse().ok()?;
                                    Some(if caps.get(1).is_some() { n / 2.0 } else { n })
                                })
                                .collect();

                            let avg_rtt = if !rtt_values.is_empty() {
                                Some(rtt_values.iter().sum::<f64>() / rtt_values.len() as f64)
                            } else {
                                None
                            };

                            // Update stats for anomaly detection (keyed by hop
                            // IP so a route change starts a fresh baseline)
                            if let Some(rtt) = avg_rtt {
                                let hop_stats = self
                                    .hop_rtt_stats
                                    .entry(ip)
                                    .or_insert_with(WindowedWelford::hop);

                                if hop_stats.is_warm() {
                                    let mean = hop_stats.mean();
                                    let stddev = hop_stats.stddev();
                                    if stddev > 0.0 {
                                        let sigma = (rtt - mean) / stddev;
                                        if sigma.abs() > 2.0 {
                                            hop_rtt_anomalies.push(HopRttAnomalyInfo {
                                                hop: hop_num,
                                                ip,
                                                rtt_ms: rtt,
                                                mean,
                                                stddev,
                                                sigma,
                                            });
                                        }
                                    }
                                }
                                hop_stats.push(rtt);
                            }

                            let hop_data = HopData {
                                hop: hop_num,
                                rtt_ms: avg_rtt,
                                ip,
                                host: ip.map(|ip| ip.to_string()),
                            };

                            hop_data_vec.push(hop_data);
                            current_hops.push(ip);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to run tracert: {}", e);
                return TracerouteResult {
                    hops: Vec::new(),
                    hop_count: 0,
                    status: TracerouteStatus::Error,
                    error: Some(format!("Failed to run tracert: {}", e)),
                    route_change: None,
                    hop_rtt_anomalies: Vec::new(),
                };
            }
        }

        let route_change = self.detect_route_change(&current_hops);
        self.previous_hops = current_hops;

        TracerouteResult {
            hop_count: hop_data_vec.len() as u8,
            status: TracerouteStatus::Ok,
            error: None,
            route_change,
            hop_rtt_anomalies,
            hops: hop_data_vec,
        }
    }

    /// Unix-specific traceroute using trippy_core
    #[cfg(not(windows))]
    fn trace_unix(&mut self) -> TracerouteResult {
        use trippy_core::{Builder, PrivilegeMode, Protocol};
        use trippy_privilege::Privilege;

        // Check privileges
        let privilege = match Privilege::discover() {
            Ok(p) => p,
            Err(e) => {
                return TracerouteResult {
                    hops: Vec::new(),
                    hop_count: 0,
                    status: TracerouteStatus::Error,
                    error: Some(format!("Failed to discover privileges: {}", e)),
                    route_change: None,
                    hop_rtt_anomalies: Vec::new(),
                };
            }
        };

        if !privilege.has_privileges() {
            return TracerouteResult {
                hops: Vec::new(),
                hop_count: 0,
                status: TracerouteStatus::Error,
                error: Some("Insufficient privileges. Run with sudo.".to_string()),
                route_change: None,
                hop_rtt_anomalies: Vec::new(),
            };
        }

        let builder = Builder::new(self.target)
            .protocol(Protocol::Icmp)
            .privilege_mode(PrivilegeMode::Privileged)
            .max_rounds(Some(10))
            .first_ttl(1)
            .max_ttl(30)
            .max_inflight(24);

        let tracer = match builder.build() {
            Ok(t) => t,
            Err(e) => {
                return TracerouteResult {
                    hops: Vec::new(),
                    hop_count: 0,
                    status: TracerouteStatus::Error,
                    error: Some(format!("Failed to build tracer: {}", e)),
                    route_change: None,
                    hop_rtt_anomalies: Vec::new(),
                };
            }
        };

        // Run the tracer and collect state with timeout
        match self.run_with_timeout(tracer) {
            Ok(state) => self.process_state(state),
            Err(e) => TracerouteResult {
                hops: Vec::new(),
                hop_count: 0,
                status: TracerouteStatus::Error,
                error: Some(format!("Traceroute failed: {}", e)),
                route_change: None,
                hop_rtt_anomalies: Vec::new(),
            },
        }
    }

    /// Run tracer with a timeout (Unix only)
    #[cfg(not(windows))]
    fn run_with_timeout(
        &mut self,
        tracer: trippy_core::Tracer,
    ) -> Result<trippy_core::State, String> {
        let (tx, rx) = std::sync::mpsc::channel();
        let timeout = self.timeout;

        // Bound leaked workers: trippy's blocking `run()` cannot be cancelled,
        // so a trace that exceeds the timeout keeps its OS thread alive until
        // it finishes. Refuse to start a new trace while a previous timed-out
        // one is still running instead of leaking one thread per tick.
        if let Some(handle) = self.trace_worker.as_ref()
            && !handle.is_finished()
        {
            return Err(
                "Previous traceroute still running (previous round timed out); skipping this round"
                    .to_string(),
            );
        }

        let handle = std::thread::spawn(move || {
            let result = tracer.run();
            let state = match result {
                Ok(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    Ok(tracer.snapshot())
                }
                Err(e) => Err(format!("Traceroute run failed: {}", e)),
            };
            let _ = tx.send(state);
        });
        self.trace_worker = Some(handle);

        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Err(format!("Traceroute timed out after {:?}", timeout))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err("Traceroute thread disconnected".to_string())
            }
        }
    }

    /// Process the traceroute state (Unix only)
    #[cfg(not(windows))]
    fn process_state(&mut self, state: trippy_core::State) -> TracerouteResult {
        let hops = state.hops();
        let mut hop_data_vec: Vec<HopData> = Vec::new();
        let mut current_hops: Vec<Option<IpAddr>> = Vec::new();
        let mut hop_rtt_anomalies: Vec<HopRttAnomalyInfo> = Vec::new();

        for hop in hops {
            let ttl = hop.ttl();
            let rtt_ms = hop.last_ms();
            let ip: Option<IpAddr> = hop.addrs().next().copied();
            let host: Option<String> = None;

            if let Some(rtt) = rtt_ms {
                // Key the baseline by hop IP: if the path changes and this TTL
                // now resolves to a different router, the new router gets a
                // fresh window instead of inheriting the old router's samples
                let hop_stats = self
                    .hop_rtt_stats
                    .entry(ip)
                    .or_insert_with(WindowedWelford::hop);

                if hop_stats.is_warm() {
                    let mean = hop_stats.mean();
                    let stddev = hop_stats.stddev();
                    if stddev > 0.0 {
                        let sigma = (rtt - mean) / stddev;
                        if sigma.abs() > 2.0 {
                            hop_rtt_anomalies.push(HopRttAnomalyInfo {
                                hop: ttl,
                                ip,
                                rtt_ms: rtt,
                                mean,
                                stddev,
                                sigma,
                            });
                        }
                    }
                }
                hop_stats.push(rtt);
            }

            let hop_data = HopData {
                hop: ttl,
                rtt_ms,
                ip,
                host,
            };

            hop_data_vec.push(hop_data);
            current_hops.push(ip);
        }

        let route_change = self.detect_route_change(&current_hops);
        self.previous_hops = current_hops;

        // Capture the count first, then move the vector (it is not used again)
        let hop_count = hop_data_vec.len() as u8;
        TracerouteResult {
            hops: hop_data_vec,
            hop_count,
            status: TracerouteStatus::Ok,
            error: None,
            route_change,
            hop_rtt_anomalies,
        }
    }

    /// Detect if the route has changed
    ///
    /// A hop that did not answer a trace (`None`) is "unknown", not a changed
    /// address: routers routinely rate-limit or filter Time-Exceeded, so
    /// non-answers must never be reported as topology changes. The comparison
    /// is therefore position-wise and considers only hops where *both* the
    /// previous and the current trace have an answered IP; a pure hop-count
    /// difference (hops appearing or going silent) is not a change either.
    /// The event fires only when an answered hop's IP differs from the
    /// previous run's IP at the same position.
    fn detect_route_change(&self, current_hops: &[Option<IpAddr>]) -> Option<RouteChangeInfo> {
        if self.previous_hops.is_empty() {
            return None;
        }

        let changed_hops: Vec<String> = current_hops
            .iter()
            .zip(self.previous_hops.iter())
            .enumerate()
            .filter_map(|(i, (current, previous))| match (current, previous) {
                (Some(current_ip), Some(previous_ip)) if current_ip != previous_ip => {
                    Some(format!("hop {}: {}", i + 1, current_ip))
                }
                _ => None,
            })
            .collect();

        if changed_hops.is_empty() {
            return None;
        }

        Some(RouteChangeInfo {
            description: format!("Route changed at {}", changed_hops.join(", ")),
        })
    }
}

/// Traceroute probe loop
///
/// Traces on a fixed cadence or immediately when forced via `notify` (the TUI
/// `t` hotkey), retargets when the active IP changes (`ip_rx`), publishes the
/// latest result to the store, and writes one `TracerouteRecord` per attempt
/// plus one `Event` record per anomaly (route change, per-hop RTT anomaly) to
/// the JSONL log. Send failures are ignored — a dead logger must not stop
/// probing.
#[allow(clippy::too_many_arguments)]
pub async fn traceroute_probe_loop(
    mut prober: TracerouteProber,
    store: crate::store::SharedStore,
    log_tx: tokio::sync::mpsc::Sender<crate::models::LogRecord>,
    target: String,
    interval_secs: u64,
    cancel: CancellationToken,
    notify: std::sync::Arc<tokio::sync::Notify>,
    mut ip_rx: tokio::sync::watch::Receiver<IpAddr>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    let detector = AnomalyDetector::new();

    loop {
        tokio::select! {
            biased;

            _ = cancel.cancelled() => {
                debug!("Traceroute probe loop cancelled");
                break;
            }
            res = ip_rx.changed() => {
                // Closed channel: run_tui (the only sender) is gone — treat
                // it as shutdown rather than an IP change, so the loop does
                // not run one more blocking trace on the TUI error-exit path
                if res.is_err() {
                    break;
                }
                let new_ip = *ip_rx.borrow();
                info!("Traceroute probe updating target to: {}", new_ip);
                prober.update_target(new_ip);
            }
            _ = notify.notified() => {
                debug!("Traceroute forced via notify");
            }
            _ = interval.tick() => {}
        }

        // Check cancellation before probing
        if cancel.is_cancelled() {
            debug!("Traceroute probe loop cancelled");
            break;
        }

        // trace() blocks the calling thread for up to --timeout-trace (Unix:
        // waiting on the trace thread; Windows: the tracert process), so run
        // it off the async worker like the Windows path's internal
        // block_in_place.
        let result = tokio::task::block_in_place(|| prober.trace());

        // Update store with traceroute results
        //
        // The store slot keeps the data-XOR-error invariant like every other
        // layer: a failed trace stores only the error, so `data.is_some()`
        // reliably means "the last trace succeeded".
        {
            let mut store_guard = store.write().await;
            let trace_data = if result.error.is_some() {
                None
            } else {
                Some(crate::store::TracerouteData {
                    hops: result.hops.clone(),
                })
            };
            store_guard.set_latest_traceroute(trace_data, result.error.clone());
        }

        // Anomaly events go to the store's event deque, and the attempt's
        // records (anomaly events first, then the traceroute record) go to
        // the JSONL log.
        let (records, anomalies) = trace_attempt_records(&detector, &result, &target);
        if !anomalies.is_empty() {
            let mut store_guard = store.write().await;
            for anomaly in &anomalies {
                store_guard.push_event(
                    anomaly.event_type.clone(),
                    anomaly.severity.clone(),
                    anomaly.message.clone(),
                );
            }
        }
        for record in records {
            let _ = log_tx.send(record).await;
        }
    }
}

/// Build the JSONL records and store events for one trace attempt
///
/// Pure mapping step behind the ADR-0006 contract (`specs/decisions/`):
/// one `Event` record per anomaly (route change first, then per-hop RTT
/// anomalies), then exactly one `Traceroute` record per attempt — failed
/// attempts included — so the log always carries the attempt's shape. The
/// companion [`AnomalyEvent`]s must reach the store's event deque in the
/// same order.
fn trace_attempt_records(
    detector: &AnomalyDetector,
    result: &TracerouteResult,
    target: &str,
) -> (Vec<LogRecord>, Vec<AnomalyEvent>) {
    let mut records = Vec::new();
    let mut anomalies = Vec::new();

    // Publish route change as an anomaly event (store + JSONL)
    if let Some(ref route_change) = result.route_change {
        warn!("Route change detected: {}", route_change.description);
        let anomaly = detector.on_route_change(&route_change.description);
        anomalies.push(anomaly.clone());
        records.push(LogRecord::Event(detector.to_event_record(&anomaly, target)));
    }

    // Publish per-hop RTT anomalies as events (store + JSONL)
    for hop_rtt_anomaly in &result.hop_rtt_anomalies {
        debug!(
            "Hop {} ({}) RTT anomaly: {:.1}ms (mean: {:.1}ms, sigma: {:.1})",
            hop_rtt_anomaly.hop,
            hop_rtt_anomaly
                .ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "*".to_string()),
            hop_rtt_anomaly.rtt_ms,
            hop_rtt_anomaly.mean,
            hop_rtt_anomaly.sigma
        );
        let anomaly = detector.on_hop_rtt_anomaly(
            hop_rtt_anomaly.hop,
            hop_rtt_anomaly.ip,
            hop_rtt_anomaly.rtt_ms,
            hop_rtt_anomaly.mean,
            hop_rtt_anomaly.sigma,
            hop_rtt_anomaly.stddev,
        );
        anomalies.push(anomaly.clone());
        records.push(LogRecord::Event(detector.to_event_record(&anomaly, target)));
    }

    // One TracerouteRecord per attempt (including error attempts)
    let hops: Vec<crate::models::HopRecord> = result
        .hops
        .iter()
        .map(|h| crate::models::HopRecord {
            hop: h.hop,
            ip: h.ip.map(|ip| ip.to_string()),
            rtt_ms: h.rtt_ms,
            host: h.host.clone(),
        })
        .collect();
    records.push(LogRecord::Traceroute(TracerouteRecord {
        ts: chrono::Utc::now(),
        target: target.to_string(),
        hops,
        hop_count: result.hop_count,
        status: result.status.clone(),
    }));

    (records, anomalies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;
    use std::net::Ipv4Addr;

    fn hop_addr(last_octet: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)))
    }

    fn prober_with_previous(hops: Vec<Option<IpAddr>>) -> TracerouteProber {
        TracerouteProber {
            target: IpAddr::V4(Ipv4Addr::LOCALHOST),
            timeout: Duration::from_secs(1),
            previous_hops: hops,
            hop_rtt_stats: HashMap::new(),
            #[cfg(not(windows))]
            trace_worker: None,
        }
    }

    #[test]
    fn test_detect_route_change_first_run() {
        let prober = prober_with_previous(Vec::new());
        let current = [hop_addr(1), hop_addr(2)];
        assert!(prober.detect_route_change(&current).is_none());
    }

    #[test]
    fn test_detect_route_change_identical_route() {
        let route = [hop_addr(1), hop_addr(2), hop_addr(3)];
        let prober = prober_with_previous(route.to_vec());
        assert!(prober.detect_route_change(&route).is_none());
    }

    #[test]
    fn test_detect_route_change_pure_hop_count_change_no_event() {
        // A hop-count difference alone is not a topology change: a hop
        // appearing or going silent leaves every position where both runs
        // have an answered IP unchanged
        let prober = prober_with_previous(vec![hop_addr(1), hop_addr(2)]);
        let longer = [hop_addr(1), hop_addr(2), hop_addr(3)];
        assert!(prober.detect_route_change(&longer).is_none());

        let shorter = [hop_addr(1)];
        assert!(prober.detect_route_change(&shorter).is_none());
    }

    #[test]
    fn test_detect_route_change_ip_swapped() {
        let prober = prober_with_previous(vec![hop_addr(1), hop_addr(2), hop_addr(3)]);
        let current = [hop_addr(1), hop_addr(9), hop_addr(3)];

        let change = prober
            .detect_route_change(&current)
            .expect("change expected");
        assert!(change.description.contains("hop 2"));
        assert!(change.description.contains("10.0.0.9"));
    }

    #[test]
    fn test_detect_route_change_non_answered_hop_no_event() {
        // A hop that stops answering is "unknown", not a changed address
        let prober = prober_with_previous(vec![hop_addr(1), hop_addr(2)]);
        let current = [hop_addr(1), None];
        assert!(prober.detect_route_change(&current).is_none());

        // The mirror case: a previously silent hop answering is not a change
        let prober = prober_with_previous(vec![hop_addr(1), None]);
        let current = [hop_addr(1), hop_addr(2)];
        assert!(prober.detect_route_change(&current).is_none());
    }

    #[test]
    fn test_update_target_resets_route_history() {
        let mut prober = prober_with_previous(vec![hop_addr(1), hop_addr(2)]);
        // Seed a non-empty per-hop baseline; update_target documents that it
        // is cleared along with the route history
        prober
            .hop_rtt_stats
            .insert(hop_addr(1), WindowedWelford::hop());
        prober.update_target(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));

        assert_eq!(prober.target, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        // Both documented resets happened: route history and hop stats
        assert!(prober.previous_hops.is_empty());
        assert!(prober.hop_rtt_stats.is_empty());
        // The next run is treated as a first run
        let current = [hop_addr(5), hop_addr(6)];
        assert!(prober.detect_route_change(&current).is_none());
    }

    /// A two-hop result with the given anomalies attached
    fn result_with(
        route_change: Option<RouteChangeInfo>,
        hop_anomalies: Vec<HopRttAnomalyInfo>,
        error: Option<String>,
    ) -> TracerouteResult {
        TracerouteResult {
            hops: vec![
                HopData {
                    hop: 1,
                    rtt_ms: Some(1.5),
                    ip: hop_addr(1),
                    host: None,
                },
                HopData {
                    hop: 2,
                    rtt_ms: Some(2.5),
                    ip: hop_addr(2),
                    host: Some("gw.example".to_string()),
                },
            ],
            hop_count: 2,
            status: if error.is_some() {
                TracerouteStatus::Error
            } else {
                TracerouteStatus::Ok
            },
            error,
            route_change,
            hop_rtt_anomalies: hop_anomalies,
        }
    }

    fn as_event(record: &LogRecord) -> &crate::models::EventRecord {
        match record {
            LogRecord::Event(event) => event,
            other => panic!("expected an event record, got {other:?}"),
        }
    }

    #[test]
    fn test_trace_attempt_records_clean_attempt() {
        let detector = AnomalyDetector::new();
        let result = result_with(None, Vec::new(), None);
        let (records, anomalies) = trace_attempt_records(&detector, &result, "127.0.0.1");

        // No anomalies: the attempt yields exactly one Traceroute record
        assert!(anomalies.is_empty());
        assert_eq!(records.len(), 1);
        let LogRecord::Traceroute(record) = &records[0] else {
            panic!("expected a traceroute record, got {:?}", records[0]);
        };
        assert_eq!(record.target, "127.0.0.1");
        assert_eq!(record.hop_count, 2);
        assert!(matches!(record.status, TracerouteStatus::Ok));
        assert_eq!(record.hops.len(), 2);
        assert_eq!(record.hops[0].hop, 1);
        assert_eq!(record.hops[0].ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(record.hops[0].rtt_ms, Some(1.5));
        assert_eq!(record.hops[1].host.as_deref(), Some("gw.example"));
    }

    #[test]
    fn test_trace_attempt_records_error_attempt_still_recorded() {
        let detector = AnomalyDetector::new();
        let result = result_with(None, Vec::new(), Some("trace failed".to_string()));
        let (records, anomalies) = trace_attempt_records(&detector, &result, "127.0.0.1");

        // Failed attempts still produce exactly one Traceroute record
        assert!(anomalies.is_empty());
        assert_eq!(records.len(), 1);
        let LogRecord::Traceroute(record) = &records[0] else {
            panic!("expected a traceroute record, got {:?}", records[0]);
        };
        assert!(matches!(record.status, TracerouteStatus::Error));
    }

    #[test]
    fn test_trace_attempt_records_events_precede_traceroute() {
        let detector = AnomalyDetector::new();
        let route_change = RouteChangeInfo {
            description: "Route changed at hop 2: 10.0.0.2".to_string(),
        };
        let hop_anomaly = HopRttAnomalyInfo {
            hop: 1,
            ip: hop_addr(1),
            rtt_ms: 50.0,
            mean: 1.0,
            stddev: 0.5,
            sigma: 98.0,
        };
        let result = result_with(Some(route_change), vec![hop_anomaly], None);
        let (records, anomalies) = trace_attempt_records(&detector, &result, "example.test");

        // Route-change event, hop-RTT event, then the traceroute record
        assert_eq!(records.len(), 3);
        assert!(matches!(records[0], LogRecord::Event(_)));
        assert!(matches!(records[1], LogRecord::Event(_)));
        assert!(matches!(records[2], LogRecord::Traceroute(_)));

        // The same anomalies (route change first) go to the store
        assert_eq!(anomalies.len(), 2);
        assert_eq!(anomalies[0].event_type, "route_change");
        assert_eq!(anomalies[0].severity, Severity::Warning);
        assert_eq!(anomalies[1].event_type, "hop_rtt_anomaly");
        assert_eq!(anomalies[1].severity, Severity::Warning);

        // The Event records mirror the store anomalies, in order
        let first = as_event(&records[0]);
        assert_eq!(first.event, anomalies[0].event_type);
        assert_eq!(first.severity, anomalies[0].severity);
        assert_eq!(first.message, anomalies[0].message);
        assert_eq!(first.target, "example.test");
        let second = as_event(&records[1]);
        assert_eq!(second.event, anomalies[1].event_type);
        assert_eq!(second.severity, anomalies[1].severity);
        assert_eq!(second.message, anomalies[1].message);
    }
}
