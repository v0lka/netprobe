//! Application orchestration
//!
//! This module coordinates all components of netprobe:
//! - Initial DNS resolution of target
//! - ICMP strategy detection
//! - Privilege checking for traceroute
//! - Spawning all probe tasks
//! - Running TUI or quiet mode
//! - Graceful shutdown with session_end recording

use crate::config::Config;
use crate::logger::Logger;
use crate::models::{
    LogRecord, SessionConfig, SessionEndRecord, SessionStartRecord, SessionSummary,
};
use crate::probe::dns::{DnsProber, dns_probe_loop};
use crate::probe::icmp::{IcmpProber, icmp_probe_loop};
use crate::probe::tcp::tcp_tls_http_probe_loop;
use crate::probe::traceroute::{TracerouteProber, traceroute_probe_loop};
use crate::store::{MetricsStore, SharedStore};
use crate::tui::run_tui;
use crate::tui_tracing::TracingLogReceiver;
use crate::util::{compute_mos, mos_to_grade};
use anyhow::{Context, Result};
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Type alias for TokioResolver
pub type TokioResolver = Resolver<TokioConnectionProvider>;

/// Run the netprobe application
///
/// This is the main entry point that orchestrates all components:
/// 1. Resolves the target (if it's a domain name)
/// 2. Determines ICMP strategy
/// 3. Checks privileges for traceroute
/// 4. Creates shared state and logger
/// 5. Spawns all probe tasks
/// 6. Runs TUI or quiet mode
/// 7. Handles graceful shutdown
pub async fn run(config: Config, tracing_receiver: Option<TracingLogReceiver>) -> Result<()> {
    info!("Starting netprobe for target: {}", config.target);

    // Step 1: Initial DNS resolution (if target is a domain)
    let (target_ip, resolved_target, all_ips) = resolve_target(&config).await?;
    info!(
        "Resolved target: {} -> {:?} ({} IPs)",
        config.target,
        target_ip,
        all_ips.len()
    );

    // Step 2: Determine ICMP strategy
    let icmp_timeout = Duration::from_millis(config.timeout_icmp_ms);
    let (icmp_prober, icmp_strategy) = IcmpProber::new(target_ip, icmp_timeout)
        .await
        .context("Failed to initialize ICMP prober")?;
    info!("ICMP strategy: {}", icmp_strategy);

    // Step 3: Check privileges for traceroute
    let traceroute_available = TracerouteProber::new(target_ip, config.timeout_trace_ms).is_ok();
    if traceroute_available {
        info!("Traceroute: available");
    } else {
        warn!("Traceroute: unavailable (insufficient privileges)");
    }

    // Step 4: Create shared state
    let store: SharedStore = Arc::new(tokio::sync::RwLock::new(MetricsStore::new(
        config.history,
        config.target.clone(),
    )));

    // Set resolved target and IP in store
    {
        let mut store_guard = store.write().await;
        store_guard.set_resolved_target(resolved_target.clone());
        store_guard.set_resolved_ip(Some(target_ip.to_string()));
        store_guard.set_resolved_ips(all_ips);
        store_guard.set_traceroute_available(traceroute_available);
    }

    // Step 5: Create logger and channel
    let (logger, _log_tx) = Logger::new(&config.log_path)
        .await
        .context("Failed to create logger")?;

    // Create a channel for the logger task
    let (log_sender, log_receiver) = mpsc::channel::<LogRecord>(Logger::CHANNEL_BUFFER_SIZE);

    // Step 6: Write session_start record
    let session_start = SessionStartRecord {
        ts: chrono::Utc::now(),
        target: config.target.clone(),
        resolved_target: resolved_target.clone(),
        traceroute_available,
        config: SessionConfig {
            port: config.port,
            interval_icmp_ms: config.interval_icmp_ms,
            interval_dns_sec: config.interval_dns_sec,
            interval_tcp_sec: config.interval_tcp_sec,
            interval_trace_sec: config.interval_trace_sec,
            history_size: config.history,
            icmp_strategy: icmp_strategy.to_string(),
        },
    };

    let log_sender_clone = log_sender.clone();
    log_sender_clone
        .send(LogRecord::SessionStart(session_start))
        .await
        .context("Failed to send session_start record")?;

    // Step 7: Create cancellation token, traceroute notify, and IP change channel
    let cancel = CancellationToken::new();
    let trace_notify = Arc::new(Notify::new());
    let (ip_change_tx, ip_change_rx) = watch::channel(target_ip);

    // Step 8: Spawn logger task
    let cancel_clone = cancel.clone();
    let logger_handle = tokio::spawn(async move {
        if let Err(e) = logger.run(log_receiver, cancel_clone).await {
            error!("Logger error: {}", e);
        }
    });

    // Step 8b: Spawn tracing log consumer task (TUI mode only)
    let tracing_handle = if let Some(mut receiver) = tracing_receiver {
        let tracing_store = store.clone();
        let tracing_cancel = cancel.clone();
        Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(entry) = receiver.recv() => {
                        let mut store_guard = tracing_store.write().await;
                        store_guard.push_log_event(entry.level, &entry.target, entry.message);
                    }
                    _ = tracing_cancel.cancelled() => {
                        break;
                    }
                }
            }
        }))
    } else {
        None
    };

    // Step 9: Spawn probe tasks
    let mut handles = vec![];

    // ICMP probe task
    let icmp_cancel = cancel.clone();
    let icmp_store = store.clone();
    let icmp_log_tx = log_sender.clone();
    let icmp_target = config.target.clone();
    let icmp_interval = config.interval_icmp_ms;
    let icmp_ip_rx = ip_change_rx.clone();

    let icmp_handle = tokio::spawn(async move {
        if let Err(e) = icmp_probe_loop(
            icmp_prober,
            icmp_store,
            icmp_log_tx,
            icmp_interval,
            icmp_target,
            icmp_cancel,
            icmp_ip_rx,
        )
        .await
        {
            error!("ICMP probe loop error: {}", e);
        }
    });
    handles.push(icmp_handle);

    // DNS probe task
    let dns_cancel = cancel.clone();
    let dns_store = store.clone();
    let dns_log_tx = log_sender.clone();
    let dns_target = config.target.clone();
    let dns_interval = config.interval_dns_sec;
    let dns_timeout = Duration::from_millis(config.timeout_dns_ms);
    let dns_server = config.dns_server;

    let dns_prober = DnsProber::new(&config.target, dns_server, dns_timeout)
        .context("Failed to create DNS prober")?;

    let dns_handle = tokio::spawn(async move {
        if let Err(e) = dns_probe_loop(
            dns_prober,
            dns_store,
            dns_log_tx,
            dns_interval,
            dns_target,
            dns_cancel,
        )
        .await
        {
            error!("DNS probe loop error: {}", e);
        }
    });
    handles.push(dns_handle);

    // TCP/TLS/HTTP probe task
    let tcp_cancel = cancel.clone();
    let tcp_store = store.clone();
    let tcp_log_tx = log_sender.clone();
    let tcp_config = Arc::new(config.clone());
    let tcp_hostname = config.target.clone();
    let tcp_ip_rx = ip_change_rx.clone();

    let tcp_handle = tokio::spawn(async move {
        if let Err(e) = tcp_tls_http_probe_loop(
            target_ip,
            tcp_hostname,
            tcp_store,
            tcp_log_tx,
            tcp_config,
            tcp_cancel,
            tcp_ip_rx,
        )
        .await
        {
            error!("TCP/TLS/HTTP probe loop error: {}", e);
        }
    });
    handles.push(tcp_handle);

    // Traceroute probe task (if available)
    if traceroute_available {
        let trace_cancel = cancel.clone();
        let trace_store = store.clone();
        let trace_log_tx = log_sender.clone();
        let trace_target = config.target.clone();
        let trace_interval = config.interval_trace_sec;
        let trace_notify_clone = trace_notify.clone();
        let trace_ip_rx = ip_change_rx.clone();

        let trace_prober = TracerouteProber::new(target_ip, config.timeout_trace_ms)
            .context("Failed to create traceroute prober")?;

        let trace_handle = tokio::spawn(async move {
            traceroute_probe_loop(
                trace_prober,
                trace_store,
                trace_log_tx,
                trace_target,
                trace_interval,
                trace_cancel,
                trace_notify_clone,
                trace_ip_rx,
            )
            .await;
        });
        handles.push(trace_handle);
    }

    // Step 10: Run TUI or quiet mode
    let session_result = if config.quiet {
        // Quiet mode: just wait for Ctrl+C
        info!("Running in quiet mode (no TUI)");
        run_quiet_mode(cancel.clone()).await
    } else {
        // TUI mode
        info!("Starting TUI");
        let tui_cancel = cancel.clone();
        run_tui(
            store.clone(),
            config.clone(),
            tui_cancel,
            trace_notify,
            ip_change_tx,
        )
        .await
    };

    if let Err(e) = &session_result {
        error!("Session error: {}", e);
    }

    // Step 11: Graceful shutdown
    info!("Initiating graceful shutdown...");
    cancel.cancel();

    // Wait for all probe tasks to complete with timeout
    let task_names = ["ICMP", "DNS", "TCP", "Traceroute"];
    for (i, handle) in handles.into_iter().enumerate() {
        let task_name = task_names.get(i).unwrap_or(&"Unknown");
        tracing::debug!("Waiting for {} task to complete...", task_name);
        match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
            Ok(_) => tracing::debug!("{} task completed", task_name),
            Err(_) => warn!(
                "{} task did not complete within timeout, continuing...",
                task_name
            ),
        }
    }

    // Step 12: Write session_end record
    tracing::debug!("Writing session_end record...");
    let session_end = create_session_end_record(&store, &config).await;
    let _ = log_sender.send(LogRecord::SessionEnd(session_end)).await;

    // Drop sender to close logger channel
    tracing::debug!("Closing log channel...");
    drop(log_sender);

    // Wait for logger to finish with timeout
    tracing::debug!("Waiting for logger to finish...");
    match tokio::time::timeout(std::time::Duration::from_secs(5), logger_handle).await {
        Ok(_) => tracing::debug!("Logger completed"),
        Err(_) => warn!("Logger did not complete within timeout"),
    }

    // Wait for tracing consumer to finish (if running)
    if let Some(handle) = tracing_handle {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    info!("netprobe shutdown complete");

    session_result
}

/// Resolve the target to an IP address
///
/// If the target is already an IP address, returns it directly.
/// If the target is a domain name, performs DNS resolution.
/// Prefers IPv4 over IPv6 for dual-stack domains.
/// Returns: (active_ip, resolved_target, all_ips)
async fn resolve_target(config: &Config) -> Result<(IpAddr, Option<String>, Vec<IpAddr>)> {
    // First, try to parse as IP address
    if let Ok(ip) = IpAddr::from_str(&config.target) {
        // Try reverse DNS lookup for IP addresses
        let resolver = create_resolver(
            config.dns_server,
            Duration::from_millis(config.timeout_dns_ms),
        )
        .context("Failed to create DNS resolver for reverse lookup")?;

        let reverse_result = resolver.reverse_lookup(ip).await;
        let hostname = reverse_result
            .ok()
            .and_then(|lookup| lookup.iter().next().map(|name| name.to_string()));

        return Ok((ip, hostname, vec![ip]));
    }

    // It's a domain name, resolve it
    let resolver = create_resolver(
        config.dns_server,
        Duration::from_millis(config.timeout_dns_ms),
    )
    .context("Failed to create DNS resolver")?;

    let lookup = resolver
        .lookup_ip(&config.target)
        .await
        .context("Failed to resolve target domain")?;

    // Collect all IPs and prefer IPv4
    let ips: Vec<IpAddr> = lookup.iter().collect();

    if ips.is_empty() {
        anyhow::bail!("DNS resolution returned no addresses");
    }

    // Prefer IPv4, fallback to first available
    let ip = ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .copied()
        .unwrap_or(ips[0]);

    Ok((ip, Some(config.target.clone()), ips))
}

/// Create a DNS resolver
fn create_resolver(dns_server: Option<IpAddr>, timeout: Duration) -> Result<TokioResolver> {
    let (config, opts) = if let Some(server) = dns_server {
        let name_servers = NameServerConfigGroup::from_ips_clear(&[server], 53, true);
        let config = ResolverConfig::from_parts(None, vec![], name_servers);
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2;
        (config, opts)
    } else {
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2;
        (ResolverConfig::default(), opts)
    };

    Ok(
        TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build(),
    )
}

/// Run in quiet mode (no TUI, just wait for Ctrl+C)
async fn run_quiet_mode(cancel: CancellationToken) -> Result<()> {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down...");
            cancel.cancel();
        }
        _ = cancel.cancelled() => {
            // Cancellation was triggered elsewhere
        }
    }
    Ok(())
}

/// Create session_end record from current store state
async fn create_session_end_record(store: &SharedStore, config: &Config) -> SessionEndRecord {
    let store_guard = store.read().await;
    let session_start = store_guard.session_start();
    let duration = chrono::Utc::now() - session_start;
    let duration_sec = duration.num_seconds().max(0) as u64;

    let aggregates = store_guard.icmp_aggregates();
    let events = store_guard.events();

    // Calculate MOS and grade
    let mos = compute_mos(aggregates.avg_rtt, aggregates.jitter, aggregates.loss_pct);
    let grade = mos_to_grade(mos);

    // Calculate uptime percentage
    let uptime_pct = if aggregates.sent > 0 {
        (aggregates.received as f64 / aggregates.sent as f64) * 100.0
    } else {
        100.0
    };

    SessionEndRecord {
        ts: chrono::Utc::now(),
        target: config.target.clone(),
        duration_sec,
        summary: SessionSummary {
            icmp_sent: aggregates.sent,
            icmp_received: aggregates.received,
            loss_pct: aggregates.loss_pct,
            rtt_avg_ms: aggregates.avg_rtt,
            rtt_p95_ms: aggregates.p95_rtt,
            uptime_pct,
            mos,
            grade,
            events_total: events.len() as u64,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session_end_record_structure() {
        // This test verifies the structure matches the spec
        let summary = SessionSummary {
            icmp_sent: 100,
            icmp_received: 95,
            loss_pct: 5.0,
            rtt_avg_ms: 20.5,
            rtt_p95_ms: 45.2,
            uptime_pct: 95.0,
            mos: 3.8,
            grade: 'B',
            events_total: 3,
        };

        let record = SessionEndRecord {
            ts: chrono::Utc::now(),
            target: "1.1.1.1".to_string(),
            duration_sec: 3600,
            summary,
        };

        assert_eq!(record.duration_sec, 3600);
        assert_eq!(record.summary.icmp_sent, 100);
        assert_eq!(record.summary.icmp_received, 95);
        assert_eq!(record.summary.grade, 'B');
    }
}
