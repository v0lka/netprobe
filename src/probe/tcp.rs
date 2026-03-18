//! TCP connect prober

use crate::anomaly::AnomalyDetector;
use crate::config::Config;
use crate::models::{
    HttpRecord, HttpStatus, LogRecord, TcpRecord, TcpStatus as ModelsTcpStatus, TlsRecord,
    TlsStatus,
};
use crate::probe::ProbeError;
use crate::probe::http::http_probe;
use crate::probe::tls::tls_handshake;
use crate::store::{HttpData, SharedStore, TcpData, TlsData};
use socket2::{Domain, Socket, Type};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Instant, interval};
use tokio_util::sync::CancellationToken;

// EINPROGRESS error code - operation in progress
#[cfg(target_os = "macos")]
const EINPROGRESS: i32 = 36;
#[cfg(target_os = "linux")]
const EINPROGRESS: i32 = 115;
#[cfg(windows)]
const EINPROGRESS: i32 = 10036;

// WSAEWOULDBLOCK error code for Windows - operation would block
#[cfg(windows)]
const WSAEWOULDBLOCK: i32 = 10035;

/// Check if the error indicates a non-blocking connect is in progress
/// On Unix: only EINPROGRESS (36)
/// On Windows: EINPROGRESS (10036) or WSAEWOULDBLOCK (10035)
fn is_connect_in_progress(e: &std::io::Error) -> bool {
    match e.raw_os_error() {
        Some(EINPROGRESS) => true,
        #[cfg(windows)]
        Some(WSAEWOULDBLOCK) => true,
        _ => false,
    }
}

/// Result of a TCP connection attempt
#[derive(Debug, Clone)]
pub struct TcpResult {
    pub connect_ms: f64,
    #[allow(dead_code)]
    pub status: LocalTcpStatus,
}

/// Local TCP connection status (mapped to models::TcpStatus for logging)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTcpStatus {
    Connected,
    Refused,
    Timeout,
    Reset,
}

/// Perform a TCP connection with precise timing
/// Uses socket2 for non-blocking socket creation and accurate timing
pub async fn tcp_connect(
    target: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<(TcpStream, TcpResult), ProbeError> {
    let start = Instant::now();

    // Create a non-blocking socket using socket2
    let domain = if target.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, None)
        .map_err(|e| ProbeError::SocketError(format!("Failed to create socket: {}", e)))?;

    // Set non-blocking mode
    socket
        .set_nonblocking(true)
        .map_err(|e| ProbeError::SocketError(format!("Failed to set non-blocking: {}", e)))?;

    // Parse the socket address
    let addr = std::net::SocketAddr::new(target, port);

    // Try to connect (this will likely return "in progress" since we're non-blocking)
    match socket.connect(&addr.into()) {
        Ok(()) => {
            // Connection succeeded immediately
            let elapsed = start.elapsed();
            let connect_ms = elapsed.as_secs_f64() * 1000.0;

            // Convert to tokio TcpStream
            let std_stream = std::net::TcpStream::from(socket);
            let tokio_stream = TcpStream::from_std(std_stream).map_err(|e| {
                ProbeError::SocketError(format!("Failed to convert to tokio stream: {}", e))
            })?;

            Ok((
                tokio_stream,
                TcpResult {
                    connect_ms,
                    status: LocalTcpStatus::Connected,
                },
            ))
        }
        Err(e) if is_connect_in_progress(&e) => {
            // Connection in progress - this is expected for non-blocking sockets
            // Wait for the connection to complete with timeout
            let std_stream = std::net::TcpStream::from(socket);

            match tokio::time::timeout(timeout, async {
                // Try to wait for the socket to become writable (connected)
                let stream = TcpStream::from_std(std_stream).map_err(|e| {
                    ProbeError::SocketError(format!("Failed to convert to tokio stream: {}", e))
                })?;

                // Wait for the stream to be writable (indicates connected)
                stream.writable().await.map_err(|e| {
                    ProbeError::SocketError(format!("Failed to wait for writable: {}", e))
                })?;

                Ok::<_, ProbeError>(stream)
            })
            .await
            {
                Ok(Ok(stream)) => {
                    let elapsed = start.elapsed();
                    let connect_ms = elapsed.as_secs_f64() * 1000.0;

                    Ok((
                        stream,
                        TcpResult {
                            connect_ms,
                            status: LocalTcpStatus::Connected,
                        },
                    ))
                }
                Ok(Err(e)) => {
                    // Connection failed - determine the error type
                    let error_str = e.to_string().to_lowercase();
                    let status = if error_str.contains("refused")
                        || error_str.contains("connection refused")
                    {
                        LocalTcpStatus::Refused
                    } else if error_str.contains("reset") || error_str.contains("connection reset")
                    {
                        LocalTcpStatus::Reset
                    } else {
                        LocalTcpStatus::Timeout
                    };

                    Err(match status {
                        LocalTcpStatus::Refused => {
                            ProbeError::Other("Connection refused".to_string())
                        }
                        LocalTcpStatus::Reset => ProbeError::Other("Connection reset".to_string()),
                        _ => ProbeError::Timeout,
                    })
                }
                Err(_) => Err(ProbeError::Timeout),
            }
        }
        Err(e) => {
            // Immediate connection failure
            let error_str = e.to_string().to_lowercase();
            let probe_error = if error_str.contains("refused") {
                ProbeError::Other("Connection refused".to_string())
            } else if error_str.contains("reset") {
                ProbeError::Other("Connection reset".to_string())
            } else {
                ProbeError::SocketError(format!("Connection failed: {}", e))
            };
            Err(probe_error)
        }
    }
}

/// Main TCP/TLS/HTTP probe loop
/// Performs sequential probes: TCP connect -> TLS handshake (if enabled) -> HTTP GET (if enabled)
pub async fn tcp_tls_http_probe_loop(
    target: IpAddr,
    hostname: String,
    store: SharedStore,
    log_tx: mpsc::Sender<LogRecord>,
    config: Arc<Config>,
    cancel: CancellationToken,
    mut ip_rx: tokio::sync::watch::Receiver<IpAddr>,
) -> anyhow::Result<()> {
    let mut ticker = interval(Duration::from_secs(config.interval_tcp_sec));
    let detector = AnomalyDetector::new();
    let mut current_target = target;

    loop {
        // Wait for next tick, cancellation, or IP change (biased to prioritize cancellation)
        tokio::select! {
            biased;

            _ = cancel.cancelled() => {
                tracing::info!("TCP/TLS/HTTP probe loop cancelled");
                break;
            }
            _ = ip_rx.changed() => {
                let new_ip = *ip_rx.borrow();
                tracing::info!("TCP/TLS/HTTP probe updating target to: {}", new_ip);
                current_target = new_ip;
            }
            _ = ticker.tick() => {}
        }

        // Check cancellation before starting probe cycle
        if cancel.is_cancelled() {
            tracing::info!("TCP/TLS/HTTP probe loop cancelled");
            break;
        }

        // Step 1: TCP Connect
        let tcp_timeout = Duration::from_millis(config.timeout_tcp_ms);
        let tcp_result = tcp_connect(current_target, config.port, tcp_timeout).await;

        // Check cancellation after TCP
        if cancel.is_cancelled() {
            break;
        }

        match tcp_result {
            Ok((stream, tcp_data)) => {
                // TCP succeeded - record it
                let connect_ms = tcp_data.connect_ms;

                // Update store with TCP result
                {
                    let mut store = store.write().await;
                    store.push_tcp_connect(connect_ms);
                    store.set_latest_tcp(Some(TcpData { connect_ms }), None);
                }

                // Send TCP record
                let tcp_record = TcpRecord {
                    ts: chrono::Utc::now(),
                    target: config.target.clone(),
                    port: config.port,
                    connect_ms: Some(connect_ms),
                    status: ModelsTcpStatus::Ok,
                };
                let _ = log_tx.send(LogRecord::Tcp(tcp_record)).await;

                // Check cancellation before TLS
                if cancel.is_cancelled() {
                    break;
                }

                // Step 2: TLS Handshake (if not disabled)
                if !config.no_tls {
                    let tls_timeout = Duration::from_millis(config.timeout_tcp_ms);
                    match tls_handshake(stream, &hostname, tls_timeout).await {
                        Ok((mut stream, tls_info)) => {
                            // Check for certificate expiry warning
                            if let Some(anomaly) =
                                detector.on_cert_expiry(tls_info.cert_days_remaining)
                            {
                                let mut store = store.write().await;
                                store.push_event(
                                    anomaly.event_type.clone(),
                                    anomaly.severity.clone(),
                                    anomaly.message.clone(),
                                );
                                let event_record =
                                    detector.to_event_record(&anomaly, &config.target);
                                let _ = log_tx.send(LogRecord::Event(event_record)).await;
                            }

                            // Update store with TLS result
                            {
                                let mut store = store.write().await;
                                store.push_tls_handshake(tls_info.handshake_ms);
                                store.set_latest_tls(
                                    Some(TlsData {
                                        handshake_ms: tls_info.handshake_ms,
                                        version: tls_info.version.clone(),
                                        cipher: tls_info.cipher.clone(),
                                        cert_subject: tls_info.cert_subject.clone(),
                                        cert_issuer: tls_info.cert_issuer.clone(),
                                        cert_san: tls_info.cert_san.clone(),
                                        cert_expiry: tls_info.cert_expiry,
                                        cert_days_remaining: tls_info.cert_days_remaining,
                                    }),
                                    None,
                                );
                            }

                            // Send TLS record
                            let tls_record = TlsRecord {
                                ts: chrono::Utc::now(),
                                target: config.target.clone(),
                                port: config.port,
                                handshake_ms: Some(tls_info.handshake_ms),
                                version: Some(tls_info.version),
                                cipher: Some(tls_info.cipher),
                                cert_subject: Some(tls_info.cert_subject),
                                cert_issuer: Some(tls_info.cert_issuer),
                                cert_san: Some(tls_info.cert_san),
                                cert_expiry: Some(tls_info.cert_expiry),
                                cert_days_remaining: Some(tls_info.cert_days_remaining),
                                status: TlsStatus::Ok,
                            };
                            let _ = log_tx.send(LogRecord::Tls(tls_record)).await;

                            // Check cancellation before HTTP
                            if cancel.is_cancelled() {
                                break;
                            }

                            // Step 3: HTTP GET (if not disabled)
                            if !config.no_http {
                                let http_timeout = Duration::from_millis(config.timeout_http_ms);
                                match http_probe(
                                    &mut stream,
                                    &hostname,
                                    &config.http_path,
                                    http_timeout,
                                )
                                .await
                                {
                                    Ok(http_result) => {
                                        // Check for HTTP error (status >= 400)
                                        if http_result.status_code >= 400 {
                                            let anomaly = detector.on_http_error(
                                                Some(http_result.status_code),
                                                &format!("HTTP {}", http_result.status_code),
                                            );
                                            let mut store = store.write().await;
                                            store.push_event(
                                                anomaly.event_type.clone(),
                                                anomaly.severity.clone(),
                                                anomaly.message.clone(),
                                            );
                                            let event_record =
                                                detector.to_event_record(&anomaly, &config.target);
                                            let _ =
                                                log_tx.send(LogRecord::Event(event_record)).await;
                                        }

                                        // Update store with HTTP result
                                        {
                                            let mut store = store.write().await;
                                            store.push_ttfb(http_result.ttfb_ms);
                                            store.set_latest_http(
                                                Some(HttpData {
                                                    ttfb_ms: http_result.ttfb_ms,
                                                    total_ms: http_result.total_ms,
                                                    status_code: http_result.status_code,
                                                }),
                                                None,
                                            );
                                        }

                                        // Send HTTP record
                                        let http_record = HttpRecord {
                                            ts: chrono::Utc::now(),
                                            target: config.target.clone(),
                                            port: config.port,
                                            path: config.http_path.clone(),
                                            ttfb_ms: Some(http_result.ttfb_ms),
                                            total_ms: Some(http_result.total_ms),
                                            status_code: Some(http_result.status_code),
                                            status: if http_result.status_code >= 400 {
                                                HttpStatus::Error
                                            } else {
                                                HttpStatus::Ok
                                            },
                                        };
                                        let _ = log_tx.send(LogRecord::Http(http_record)).await;
                                    }
                                    Err(e) => {
                                        // HTTP probe failed
                                        let error_msg = e.to_string();
                                        {
                                            let mut store = store.write().await;
                                            store.set_latest_http(None, Some(error_msg.clone()));
                                        }

                                        // Generate HTTP error event
                                        let anomaly = detector.on_http_error(None, &error_msg);
                                        {
                                            let mut store = store.write().await;
                                            store.push_event(
                                                anomaly.event_type.clone(),
                                                anomaly.severity.clone(),
                                                anomaly.message.clone(),
                                            );
                                        }
                                        let event_record =
                                            detector.to_event_record(&anomaly, &config.target);
                                        let _ = log_tx.send(LogRecord::Event(event_record)).await;

                                        let http_record = HttpRecord {
                                            ts: chrono::Utc::now(),
                                            target: config.target.clone(),
                                            port: config.port,
                                            path: config.http_path.clone(),
                                            ttfb_ms: None,
                                            total_ms: None,
                                            status_code: None,
                                            status: HttpStatus::Error,
                                        };
                                        let _ = log_tx.send(LogRecord::Http(http_record)).await;
                                        tracing::warn!("HTTP probe error: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // TLS handshake failed
                            let error_msg = e.to_string();
                            {
                                let mut store = store.write().await;
                                store.set_latest_tls(None, Some(error_msg.clone()));
                            }

                            let tls_record = TlsRecord {
                                ts: chrono::Utc::now(),
                                target: config.target.clone(),
                                port: config.port,
                                handshake_ms: None,
                                version: None,
                                cipher: None,
                                cert_subject: None,
                                cert_issuer: None,
                                cert_san: None,
                                cert_expiry: None,
                                cert_days_remaining: None,
                                status: TlsStatus::Error,
                            };
                            let _ = log_tx.send(LogRecord::Tls(tls_record)).await;
                            tracing::warn!("TLS handshake error: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                // TCP connect failed
                let error_str = e.to_string();
                let status = if error_str.contains("refused") {
                    // Generate TCP refused event
                    let anomaly = detector.on_tcp_refused(&error_str);
                    {
                        let mut store = store.write().await;
                        store.push_event(
                            anomaly.event_type.clone(),
                            anomaly.severity.clone(),
                            anomaly.message.clone(),
                        );
                    }
                    let event_record = detector.to_event_record(&anomaly, &config.target);
                    let _ = log_tx.send(LogRecord::Event(event_record)).await;

                    ModelsTcpStatus::Refused
                } else if error_str.contains("reset") {
                    ModelsTcpStatus::Reset
                } else {
                    ModelsTcpStatus::Timeout
                };

                {
                    let mut store = store.write().await;
                    store.set_latest_tcp(None, Some(error_str.clone()));
                }

                let tcp_record = TcpRecord {
                    ts: chrono::Utc::now(),
                    target: config.target.clone(),
                    port: config.port,
                    connect_ms: None,
                    status,
                };
                let _ = log_tx.send(LogRecord::Tcp(tcp_record)).await;
                tracing::warn!("TCP connect error: {}", e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_connect_refused() {
        // Connect to a port that's likely not open
        // Using 127.0.0.1:9 (discard service) which should be refused on most systems
        // or timeout if no service is running
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let result = tcp_connect(target, 9, Duration::from_millis(500)).await;

        // The result could be either an error (refused) or success (if service running)
        // We just verify the function doesn't panic
        match result {
            Ok((_, tcp_result)) => {
                // If it succeeded, verify we got a valid result
                assert!(tcp_result.connect_ms >= 0.0);
                assert_eq!(tcp_result.status, LocalTcpStatus::Connected);
            }
            Err(_) => {
                // Connection failed as expected (refused or timeout)
            }
        }
    }

    #[test]
    fn test_tcp_status_enum() {
        assert_eq!(LocalTcpStatus::Connected, LocalTcpStatus::Connected);
        assert_ne!(LocalTcpStatus::Connected, LocalTcpStatus::Refused);
        assert_ne!(LocalTcpStatus::Timeout, LocalTcpStatus::Reset);
    }
}
