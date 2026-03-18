//! JSONL logger

use crate::models::LogRecord;
use anyhow::Result;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Logger that writes JSONL records to a file via mpsc channel
pub struct Logger {
    writer: BufWriter<File>,
}

impl Logger {
    /// Buffer size for the mpsc channel
    pub const CHANNEL_BUFFER_SIZE: usize = 1024;
    /// Flush interval in seconds
    pub const FLUSH_INTERVAL_SECS: u64 = 5;

    /// Create a new logger and mpsc channel
    ///
    /// Returns the Logger (which should be passed to run()) and the Sender
    pub async fn new(path: &Path) -> Result<(Self, mpsc::Sender<LogRecord>)> {
        // Create/truncate the file
        let file = File::create(path).await?;
        let writer = BufWriter::new(file);

        let logger = Self { writer };
        let (tx, _rx) = mpsc::channel(Self::CHANNEL_BUFFER_SIZE);

        Ok((logger, tx))
    }

    /// Create a new logger with an existing sender
    ///
    /// This is useful for testing when you want to create your own channel
    #[allow(dead_code)]
    pub async fn new_with_sender(
        path: &Path,
    ) -> Result<(Self, mpsc::Sender<LogRecord>, mpsc::Receiver<LogRecord>)> {
        let file = File::create(path).await?;
        let writer = BufWriter::new(file);

        let logger = Self { writer };
        let (tx, rx) = mpsc::channel(Self::CHANNEL_BUFFER_SIZE);

        Ok((logger, tx, rx))
    }

    /// Run the logger loop
    ///
    /// This should be spawned as a separate task. It will:
    /// - Receive records from the channel
    /// - Serialize them to JSON
    /// - Write to the file with newline
    /// - Flush every 5 seconds or immediately for events
    /// - Stop when cancellation token is triggered
    pub async fn run(
        mut self,
        mut rx: mpsc::Receiver<LogRecord>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let mut flush_interval =
            tokio::time::interval(tokio::time::Duration::from_secs(Self::FLUSH_INTERVAL_SECS));
        let mut needs_flush = false;
        let mut shutdown_initiated = false;

        loop {
            tokio::select! {
                // Receive records from channel
                record = rx.recv() => {
                    match record {
                        Some(record) => {
                            let is_event = matches!(record, LogRecord::Event(_));

                            // Serialize to JSON
                            let json = serde_json::to_string(&record)?;

                            // Write to file
                            self.writer.write_all(json.as_bytes()).await?;
                            self.writer.write_all(b"\n").await?;

                            // Events trigger immediate flush
                            if is_event {
                                self.writer.flush().await?;
                            } else {
                                needs_flush = true;
                            }
                        }
                        None => {
                            // Channel closed - flush and exit
                            self.writer.flush().await?;
                            break;
                        }
                    }
                }

                // Periodic flush
                _ = flush_interval.tick() => {
                    if needs_flush {
                        self.writer.flush().await?;
                        needs_flush = false;
                    }
                }

                // Cancellation - flush but continue until channel closes
                // Use guard to ensure this branch only triggers once
                _ = cancel.cancelled(), if !shutdown_initiated => {
                    shutdown_initiated = true;
                    if needs_flush {
                        self.writer.flush().await?;
                        needs_flush = false;
                    }
                }
            }
        }

        Ok(())
    }

    /// Flush the writer explicitly
    #[allow(dead_code)]
    pub async fn flush(&mut self) -> Result<()> {
        self.writer.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;
    use chrono::Utc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_logger_basic() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.jsonl");

        let (logger, tx, rx) = Logger::new_with_sender(&log_path).await.unwrap();
        let cancel = CancellationToken::new();

        // Spawn logger task
        let logger_handle = tokio::spawn(async move {
            logger.run(rx, cancel).await.unwrap();
        });

        // Send some records
        let icmp_record = IcmpRecord {
            ts: Utc::now(),
            target: "1.1.1.1".to_string(),
            seq: 1,
            rtt_ms: Some(10.5),
            ttl: Some(64),
            status: IcmpStatus::Ok,
        };
        tx.send(LogRecord::Icmp(icmp_record)).await.unwrap();

        let dns_record = DnsRecord {
            ts: Utc::now(),
            target: "example.com".to_string(),
            resolve_ms: 5.0,
            ips: vec!["1.1.1.1".to_string()],
            ttl_secs: Some(300),
            server: "8.8.8.8".to_string(),
            status: DnsStatus::Ok,
        };
        tx.send(LogRecord::Dns(dns_record)).await.unwrap();

        // Give logger time to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Drop sender to close channel
        drop(tx);

        // Wait for logger to finish with timeout
        let result = timeout(Duration::from_secs(5), logger_handle).await;
        assert!(result.is_ok(), "Logger should complete within timeout");

        // Read and verify file contents
        let content: String = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(
            lines.len(),
            2,
            "Expected 2 lines, got {}: {:?}",
            lines.len(),
            content
        );

        // Verify first line is ICMP
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["type"], "icmp");
        assert_eq!(first["target"], "1.1.1.1");

        // Verify second line is DNS
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["type"], "dns");
        assert_eq!(second["target"], "example.com");
    }

    #[tokio::test]
    async fn test_logger_event_immediate_flush() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.jsonl");

        let (logger, tx, rx) = Logger::new_with_sender(&log_path).await.unwrap();
        let cancel = CancellationToken::new();

        // Spawn logger task
        let logger_handle = tokio::spawn(async move {
            logger.run(rx, cancel).await.unwrap();
        });

        // Send an event (should flush immediately)
        let event_record = EventRecord {
            ts: Utc::now(),
            target: "1.1.1.1".to_string(),
            event: "rtt_spike".to_string(),
            severity: Severity::Warning,
            value: Some(100.0),
            threshold: Some(50.0),
            sigma: Some(3.5),
            message: "RTT spike detected".to_string(),
        };
        tx.send(LogRecord::Event(event_record)).await.unwrap();

        // Small delay to allow flush
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check file is flushed (should contain the event)
        let content: String = tokio::fs::read_to_string(&log_path).await.unwrap();
        assert!(!content.is_empty());

        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["type"], "event");
        assert_eq!(parsed["event"], "rtt_spike");

        // Clean up
        drop(tx);
        let _ = timeout(Duration::from_secs(1), logger_handle).await;
    }

    #[tokio::test]
    async fn test_logger_session_start_end() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.jsonl");

        let (logger, tx, rx) = Logger::new_with_sender(&log_path).await.unwrap();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Spawn logger task
        let logger_handle = tokio::spawn(async move {
            logger.run(rx, cancel_clone).await.unwrap();
        });

        // Send session_start
        let start_record = SessionStartRecord {
            ts: Utc::now(),
            target: "1.1.1.1".to_string(),
            resolved_target: Some("one.one.one.one".to_string()),
            traceroute_available: true,
            config: SessionConfig {
                port: 443,
                interval_icmp_ms: 1000,
                interval_dns_sec: 30,
                interval_tcp_sec: 10,
                interval_trace_sec: 60,
                history_size: 3600,
                icmp_strategy: "unprivileged".to_string(),
            },
        };
        tx.send(LogRecord::SessionStart(start_record))
            .await
            .unwrap();

        // Send session_end
        let end_record = SessionEndRecord {
            ts: Utc::now(),
            target: "1.1.1.1".to_string(),
            duration_sec: 100,
            summary: SessionSummary {
                icmp_sent: 100,
                icmp_received: 99,
                loss_pct: 1.0,
                rtt_avg_ms: 20.0,
                rtt_p95_ms: 35.0,
                uptime_pct: 99.0,
                mos: 4.2,
                grade: 'A',
                events_total: 0,
            },
        };
        tx.send(LogRecord::SessionEnd(end_record)).await.unwrap();

        // Drop sender
        drop(tx);

        // Wait for logger
        let _ = timeout(Duration::from_secs(2), logger_handle).await;

        // Verify
        let content: String = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["type"], "session_start");
        assert_eq!(first["traceroute_available"], true);

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["type"], "session_end");
        assert_eq!(second["duration_sec"], 100);
        assert!(second["summary"].is_object());
        assert_eq!(second["summary"]["grade"], "A");
    }

    #[tokio::test]
    async fn test_logger_cancellation() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.jsonl");

        let (logger, tx, rx) = Logger::new_with_sender(&log_path).await.unwrap();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Spawn logger task
        let logger_handle = tokio::spawn(async move {
            logger.run(rx, cancel_clone).await.unwrap();
        });

        // Send a record and wait for it to be processed
        let icmp_record = IcmpRecord {
            ts: Utc::now(),
            target: "1.1.1.1".to_string(),
            seq: 1,
            rtt_ms: Some(10.0),
            ttl: Some(64),
            status: IcmpStatus::Ok,
        };
        tx.send(LogRecord::Icmp(icmp_record)).await.unwrap();

        // Give time for processing
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Cancel the logger (triggers flush but doesn't exit)
        cancel.cancel();

        // Drop sender to close channel and cause logger to exit
        drop(tx);

        // Wait for logger to finish
        let result = timeout(Duration::from_secs(2), logger_handle).await;
        assert!(result.is_ok());

        // Verify file was flushed
        let content: String = tokio::fs::read_to_string(&log_path).await.unwrap();
        assert!(!content.is_empty(), "Log file should not be empty");
    }
}
