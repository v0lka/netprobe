//! Traceroute prober

use crate::anomaly::WindowedWelford;
use crate::models::{TracerouteRecord, TracerouteStatus};
use crate::probe::ProbeError;
use crate::store::HopData;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

/// Information about a route change
#[derive(Debug, Clone)]
pub struct RouteChangeInfo {
    pub description: String,
    #[allow(dead_code)]
    pub old_hops: Vec<Option<IpAddr>>,
    #[allow(dead_code)]
    pub new_hops: Vec<Option<IpAddr>>,
}

/// Information about a per-hop RTT anomaly
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HopRttAnomalyInfo {
    pub hop: u8,
    pub ip: Option<IpAddr>,
    pub rtt_ms: f64,
    pub mean: f64,
    pub sigma: f64,
}

/// Result of a traceroute probe
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
    #[allow(dead_code)]
    timeout: Duration,
    previous_hops: Vec<Option<IpAddr>>,
    hop_rtt_stats: HashMap<usize, WindowedWelford>,
}

impl TracerouteProber {
    /// Create a new traceroute prober
    pub fn new(target: IpAddr, timeout_ms: u64) -> Result<Self, ProbeError> {
        Ok(Self {
            target,
            timeout: Duration::from_millis(timeout_ms),
            previous_hops: Vec::new(),
            hop_rtt_stats: HashMap::new(),
        })
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
        debug!("Running tracert -h 30 -w 1000 {}", target_str);

        // Run tracert in a blocking task to avoid blocking the async runtime
        let output = tokio::task::block_in_place(|| {
            Command::new("tracert")
                .args(["-h", "30", "-w", "1000", &target_str])
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
                let rtt_regex = Regex::new(r"(\d+)\s*ms").unwrap();

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

                            // Find RTT values
                            let rtt_values: Vec<u32> = rtt_regex
                                .find_iter(line)
                                .filter_map(|m| m.as_str().replace("ms", "").trim().parse().ok())
                                .collect();

                            let avg_rtt = if !rtt_values.is_empty() {
                                Some(
                                    rtt_values.iter().sum::<u32>() as f64 / rtt_values.len() as f64,
                                )
                            } else {
                                None
                            };

                            // Update stats for anomaly detection
                            if let Some(rtt) = avg_rtt {
                                let hop_stats = self
                                    .hop_rtt_stats
                                    .entry(hop_num as usize)
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
    fn run_with_timeout(&self, tracer: trippy_core::Tracer) -> Result<trippy_core::State, String> {
        let (tx, rx) = std::sync::mpsc::channel();
        let timeout = self.timeout;

        std::thread::spawn(move || {
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
                let hop_stats = self
                    .hop_rtt_stats
                    .entry(ttl as usize)
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

        TracerouteResult {
            hops: hop_data_vec.clone(),
            hop_count: hop_data_vec.len() as u8,
            status: TracerouteStatus::Ok,
            error: None,
            route_change,
            hop_rtt_anomalies,
        }
    }

    /// Detect if the route has changed
    fn detect_route_change(&self, current_hops: &[Option<IpAddr>]) -> Option<RouteChangeInfo> {
        if self.previous_hops.is_empty() {
            return None;
        }

        if self.previous_hops == current_hops {
            return None;
        }

        let old_len = self.previous_hops.len();
        let new_len = current_hops.len();

        let description = if old_len != new_len {
            format!("Route hop count changed from {} to {}", old_len, new_len)
        } else {
            let changed_hops: Vec<String> = current_hops
                .iter()
                .zip(self.previous_hops.iter())
                .enumerate()
                .filter(|(_, (new, old))| new != old)
                .map(|(i, (new, _))| format!("hop {}: {:?}", i + 1, new))
                .collect();

            if changed_hops.is_empty() {
                "Route changed (unknown difference)".to_string()
            } else {
                format!("Route changed at {}", changed_hops.join(", "))
            }
        };

        Some(RouteChangeInfo {
            description,
            old_hops: self.previous_hops.clone(),
            new_hops: current_hops.to_vec(),
        })
    }
}

/// Legacy traceroute probe loop for backward compatibility
#[allow(clippy::too_many_arguments)]
pub async fn traceroute_probe_loop(
    mut prober: TracerouteProber,
    store: crate::store::SharedStore,
    _log_tx: tokio::sync::mpsc::Sender<crate::models::LogRecord>,
    _target: String,
    interval_secs: u64,
    cancel: CancellationToken,
    _notify: std::sync::Arc<tokio::sync::Notify>,
    _ip_rx: tokio::sync::watch::Receiver<IpAddr>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let result = prober.trace();

                // Update store with traceroute results
                {
                    let mut store_guard = store.write().await;
                    let trace_data = crate::store::TracerouteData {
                        hops: result.hops.clone(),
                        hop_count: result.hop_count,
                    };
                    store_guard.set_latest_traceroute(
                        Some(trace_data),
                        result.error.clone(),
                    );
                }

                if let Some(ref route_change) = result.route_change {
                    warn!("Route change detected: {}", route_change.description);
                }
            }
            _ = cancel.cancelled() => {
                debug!("Traceroute probe loop cancelled");
                break;
            }
        }
    }
}

/// Spawn a traceroute task
#[allow(dead_code)]
pub fn spawn_traceroute_task(
    target: IpAddr,
    timeout_ms: u64,
    interval_secs: u64,
    tx: mpsc::Sender<TracerouteRecord>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut prober = match TracerouteProber::new(target, timeout_ms) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to create traceroute prober: {}", e);
                return;
            }
        };

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let result = prober.trace();

                    // Convert HopData to HopRecord
                    let hops: Vec<crate::models::HopRecord> = result.hops.iter().map(|h| {
                        crate::models::HopRecord {
                            hop: h.hop,
                            ip: h.ip.map(|ip| ip.to_string()),
                            rtt_ms: h.rtt_ms,
                            host: h.host.clone(),
                        }
                    }).collect();

                    let record = TracerouteRecord {
                        ts: chrono::Utc::now(),
                        target: target.to_string(),
                        hop_count: result.hop_count,
                        status: result.status.clone(),
                        hops,
                    };

                    if let Err(e) = tx.send(record).await {
                        error!("Failed to send traceroute record: {}", e);
                        break;
                    }

                    if let Some(ref route_change) = result.route_change {
                        warn!("Route change detected: {}", route_change.description);
                    }
                }
                _ = cancel.cancelled() => {
                    debug!("Traceroute task cancelled");
                    break;
                }
            }
        }
    })
}
