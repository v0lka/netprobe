//! Serde models for JSONL records

use chrono::{DateTime, Utc};
use serde::Serialize;

/// ICMP probe record
#[derive(Debug, Clone, Serialize)]
pub struct IcmpRecord {
    pub ts: DateTime<Utc>,
    pub target: String,
    pub seq: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,
    pub status: IcmpStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IcmpStatus {
    Ok,
    Timeout,
    Error,
}

/// DNS resolution record
#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub ts: DateTime<Utc>,
    pub target: String,
    pub resolve_ms: f64,
    pub ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u32>,
    pub server: String,
    pub status: DnsStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsStatus {
    Ok,
    Nxdomain,
    Servfail,
    Timeout,
}

/// TCP connect record
#[derive(Debug, Clone, Serialize)]
pub struct TcpRecord {
    pub ts: DateTime<Utc>,
    pub target: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<f64>,
    pub status: TcpStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpStatus {
    Ok,
    Refused,
    Timeout,
    Reset,
}

/// TLS handshake record
#[derive(Debug, Clone, Serialize)]
pub struct TlsRecord {
    pub ts: DateTime<Utc>,
    pub target: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_san: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_expiry: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_days_remaining: Option<i64>,
    pub status: TlsStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsStatus {
    Ok,
    Error,
}

/// HTTP probe record
#[derive(Debug, Clone, Serialize)]
pub struct HttpRecord {
    pub ts: DateTime<Utc>,
    pub target: String,
    pub port: u16,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttfb_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    pub status: HttpStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpStatus {
    Ok,
    Error,
}

/// Hop record for traceroute
#[derive(Debug, Clone, Serialize)]
pub struct HopRecord {
    pub hop: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// Traceroute record
#[derive(Debug, Clone, Serialize)]
pub struct TracerouteRecord {
    pub ts: DateTime<Utc>,
    pub target: String,
    pub hops: Vec<HopRecord>,
    pub hop_count: u8,
    pub status: TracerouteStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteStatus {
    Ok,
    Error,
}

/// Event record for anomalies
#[derive(Debug, Clone, Serialize)]
pub struct EventRecord {
    pub ts: DateTime<Utc>,
    pub target: String,
    pub event: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigma: Option<f64>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Session configuration embedded in session_start
#[derive(Debug, Clone, Serialize)]
pub struct SessionConfig {
    pub port: u16,
    pub interval_icmp_ms: u64,
    pub interval_dns_sec: u64,
    pub interval_tcp_sec: u64,
    pub interval_trace_sec: u64,
    pub history_size: usize,
    pub icmp_strategy: String,
}

/// Session start record
#[derive(Debug, Clone, Serialize)]
pub struct SessionStartRecord {
    pub ts: DateTime<Utc>,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_target: Option<String>,
    pub traceroute_available: bool,
    pub config: SessionConfig,
}

/// Session summary embedded in session_end
#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    pub icmp_sent: u64,
    pub icmp_received: u64,
    pub loss_pct: f64,
    pub rtt_avg_ms: f64,
    pub rtt_p95_ms: f64,
    pub uptime_pct: f64,
    pub mos: f64,
    pub grade: char,
    pub events_total: u64,
}

/// Session end record
#[derive(Debug, Clone, Serialize)]
pub struct SessionEndRecord {
    pub ts: DateTime<Utc>,
    pub target: String,
    pub duration_sec: u64,
    pub summary: SessionSummary,
}

/// Union type for all log records - used for serialization with type tag
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LogRecord {
    Icmp(IcmpRecord),
    Dns(DnsRecord),
    Tcp(TcpRecord),
    Tls(TlsRecord),
    Http(HttpRecord),
    #[allow(dead_code)]
    Traceroute(TracerouteRecord),
    Event(EventRecord),
    SessionStart(SessionStartRecord),
    SessionEnd(SessionEndRecord),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_icmp_record_serialization() {
        let record = IcmpRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 14, 23, 5).unwrap()
                + chrono::Duration::milliseconds(123),
            target: "1.1.1.1".to_string(),
            seq: 8142,
            rtt_ms: Some(14.2),
            ttl: Some(56),
            status: IcmpStatus::Ok,
        };

        // Test via LogRecord enum to get the type tag
        let log_record = LogRecord::Icmp(record);
        let json = serde_json::to_string(&log_record).unwrap();
        assert!(json.contains("\"type\":\"icmp\""));
        assert!(json.contains("\"target\":\"1.1.1.1\""));
        assert!(json.contains("\"seq\":8142"));
        assert!(json.contains("\"rtt_ms\":14.2"));
        assert!(json.contains("\"ttl\":56"));
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_icmp_timeout_serialization() {
        let record = IcmpRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 14, 23, 5).unwrap(),
            target: "1.1.1.1".to_string(),
            seq: 8143,
            rtt_ms: None,
            ttl: None,
            status: IcmpStatus::Timeout,
        };

        // Test via LogRecord enum to get the type tag
        let log_record = LogRecord::Icmp(record);
        let json = serde_json::to_string(&log_record).unwrap();
        assert!(json.contains("\"type\":\"icmp\""));
        assert!(!json.contains("rtt_ms"));
        assert!(!json.contains("ttl"));
        assert!(json.contains("\"status\":\"timeout\""));
    }

    #[test]
    fn test_dns_record_serialization() {
        let record = DnsRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 14, 23, 30).unwrap()
                + chrono::Duration::milliseconds(1),
            target: "one.one.one.one".to_string(),
            resolve_ms: 4.2,
            ips: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            ttl_secs: Some(286),
            server: "192.168.1.1".to_string(),
            status: DnsStatus::Ok,
        };

        // Test via LogRecord enum to get the type tag
        let log_record = LogRecord::Dns(record);
        let json = serde_json::to_string(&log_record).unwrap();
        assert!(json.contains("\"type\":\"dns\""));
        assert!(json.contains("\"target\":\"one.one.one.one\""));
        assert!(json.contains("\"resolve_ms\":4.2"));
        assert!(json.contains("\"1.1.1.1\""));
        assert!(json.contains("\"1.0.0.1\""));
        assert!(json.contains("\"ttl_secs\":286"));
        assert!(json.contains("\"server\":\"192.168.1.1\""));
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_tcp_record_serialization() {
        let record = TcpRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 14, 23, 35).unwrap()
                + chrono::Duration::milliseconds(50),
            target: "1.1.1.1".to_string(),
            port: 443,
            connect_ms: Some(15.1),
            status: TcpStatus::Ok,
        };

        // Test via LogRecord enum to get the type tag
        let log_record = LogRecord::Tcp(record);
        let json = serde_json::to_string(&log_record).unwrap();
        assert!(json.contains("\"type\":\"tcp\""));
        assert!(json.contains("\"port\":443"));
        assert!(json.contains("\"connect_ms\":15.1"));
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_tls_record_serialization() {
        let record = TlsRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 14, 23, 35).unwrap()
                + chrono::Duration::milliseconds(65),
            target: "1.1.1.1".to_string(),
            port: 443,
            handshake_ms: Some(42.3),
            version: Some("TLSv1.3".to_string()),
            cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
            cert_subject: Some("CN=one.one.one.one".to_string()),
            cert_issuer: Some("CN=DigiCert".to_string()),
            cert_san: Some(vec![
                "one.one.one.one".to_string(),
                "1.1.1.1".to_string(),
                "1.0.0.1".to_string(),
            ]),
            cert_expiry: Some(Utc.with_ymd_and_hms(2026, 6, 15, 0, 0, 0).unwrap()),
            cert_days_remaining: Some(89),
            status: TlsStatus::Ok,
        };

        // Test via LogRecord enum to get the type tag
        let log_record = LogRecord::Tls(record);
        let json = serde_json::to_string(&log_record).unwrap();
        assert!(json.contains("\"type\":\"tls\""));
        assert!(json.contains("\"handshake_ms\":42.3"));
        assert!(json.contains("\"version\":\"TLSv1.3\""));
        assert!(json.contains("\"cipher\":\"TLS_AES_256_GCM_SHA384\""));
        assert!(json.contains("\"cert_days_remaining\":89"));
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_http_record_serialization() {
        let record = HttpRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 14, 23, 35).unwrap()
                + chrono::Duration::milliseconds(130),
            target: "1.1.1.1".to_string(),
            port: 443,
            path: "/".to_string(),
            ttfb_ms: Some(78.4),
            total_ms: Some(82.1),
            status_code: Some(200),
            status: HttpStatus::Ok,
        };

        // Test via LogRecord enum to get the type tag
        let log_record = LogRecord::Http(record);
        let json = serde_json::to_string(&log_record).unwrap();
        assert!(json.contains("\"type\":\"http\""));
        assert!(json.contains("\"ttfb_ms\":78.4"));
        assert!(json.contains("\"total_ms\":82.1"));
        assert!(json.contains("\"status_code\":200"));
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_traceroute_record_serialization() {
        let record = TracerouteRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 14, 24, 5).unwrap()
                + chrono::Duration::milliseconds(200),
            target: "1.1.1.1".to_string(),
            hops: vec![
                HopRecord {
                    hop: 1,
                    ip: Some("192.168.1.1".to_string()),
                    rtt_ms: Some(1.2),
                    host: Some("router.local".to_string()),
                },
                HopRecord {
                    hop: 2,
                    ip: Some("10.0.0.1".to_string()),
                    rtt_ms: Some(4.1),
                    host: None,
                },
                HopRecord {
                    hop: 3,
                    ip: None,
                    rtt_ms: None,
                    host: None,
                },
                HopRecord {
                    hop: 4,
                    ip: Some("1.1.1.1".to_string()),
                    rtt_ms: Some(14.2),
                    host: Some("one.one.one.one".to_string()),
                },
            ],
            hop_count: 4,
            status: TracerouteStatus::Ok,
        };

        // Test via LogRecord enum to get the type tag
        let log_record = LogRecord::Traceroute(record);
        let json = serde_json::to_string(&log_record).unwrap();
        assert!(json.contains("\"type\":\"traceroute\""));
        assert!(json.contains("\"hop_count\":4"));
        assert!(json.contains("\"hop\":1"));
        assert!(json.contains("\"192.168.1.1\""));
        assert!(json.contains("\"status\":\"ok\""));
    }

    #[test]
    fn test_event_record_serialization() {
        let record = EventRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 14, 22, 51).unwrap(),
            target: "1.1.1.1".to_string(),
            event: "rtt_spike".to_string(),
            severity: Severity::Warning,
            value: Some(47.1),
            threshold: Some(32.4),
            sigma: Some(3.2),
            message: "RTT spike: 47.1ms (3.2σ above mean)".to_string(),
        };

        // Test via LogRecord enum to get the type tag
        let log_record = LogRecord::Event(record);
        let json = serde_json::to_string(&log_record).unwrap();
        assert!(json.contains("\"type\":\"event\""));
        assert!(json.contains("\"event\":\"rtt_spike\""));
        assert!(json.contains("\"severity\":\"warning\""));
        assert!(json.contains("\"value\":47.1"));
        assert!(json.contains("\"sigma\":3.2"));
    }

    #[test]
    fn test_session_start_record_serialization() {
        let record = SessionStartRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 14, 0, 0).unwrap(),
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

        // Test via LogRecord enum to get the type tag
        let log_record = LogRecord::SessionStart(record);
        let json = serde_json::to_string(&log_record).unwrap();
        assert!(json.contains("\"type\":\"session_start\""));
        assert!(json.contains("\"traceroute_available\":true"));
        assert!(json.contains("\"resolved_target\":\"one.one.one.one\""));
        assert!(json.contains("\"icmp_strategy\":\"unprivileged\""));
        assert!(json.contains("\"history_size\":3600"));
    }

    #[test]
    fn test_session_end_record_serialization() {
        let record = SessionEndRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 16, 15, 39).unwrap(),
            target: "1.1.1.1".to_string(),
            duration_sec: 8139,
            summary: SessionSummary {
                icmp_sent: 8139,
                icmp_received: 8115,
                loss_pct: 0.29,
                rtt_avg_ms: 18.7,
                rtt_p95_ms: 32.4,
                uptime_pct: 99.71,
                mos: 4.3,
                grade: 'A',
                events_total: 7,
            },
        };

        // Test via LogRecord enum to get the type tag
        let log_record = LogRecord::SessionEnd(record);
        let json = serde_json::to_string(&log_record).unwrap();
        assert!(json.contains("\"type\":\"session_end\""));
        assert!(json.contains("\"duration_sec\":8139"));
        assert!(json.contains("\"summary\""));
        assert!(json.contains("\"icmp_sent\":8139"));
        assert!(json.contains("\"icmp_received\":8115"));
        assert!(json.contains("\"loss_pct\":0.29"));
        assert!(json.contains("\"rtt_avg_ms\":18.7"));
        assert!(json.contains("\"rtt_p95_ms\":32.4"));
        assert!(json.contains("\"uptime_pct\":99.71"));
        assert!(json.contains("\"mos\":4.3"));
        assert!(json.contains("\"grade\":\"A\""));
        assert!(json.contains("\"events_total\":7"));
    }

    #[test]
    fn test_log_record_enum_serialization() {
        // Test that LogRecord enum serializes with correct type tag
        let icmp = IcmpRecord {
            ts: Utc::now(),
            target: "1.1.1.1".to_string(),
            seq: 1,
            rtt_ms: Some(10.0),
            ttl: Some(64),
            status: IcmpStatus::Ok,
        };

        let log_record = LogRecord::Icmp(icmp);
        let json = serde_json::to_string(&log_record).unwrap();

        // The enum should serialize with "type" field at top level
        assert!(json.contains("\"type\":\"icmp\""));
        assert!(json.contains("\"target\":\"1.1.1.1\""));
    }

    #[test]
    fn test_log_record_session_end_structure() {
        let record = SessionEndRecord {
            ts: Utc.with_ymd_and_hms(2026, 3, 18, 16, 15, 39).unwrap(),
            target: "1.1.1.1".to_string(),
            duration_sec: 8139,
            summary: SessionSummary {
                icmp_sent: 8139,
                icmp_received: 8115,
                loss_pct: 0.29,
                rtt_avg_ms: 18.7,
                rtt_p95_ms: 32.4,
                uptime_pct: 99.71,
                mos: 4.3,
                grade: 'A',
                events_total: 7,
            },
        };

        let log_record = LogRecord::SessionEnd(record);
        let json = serde_json::to_string(&log_record).unwrap();

        // Verify the structure matches spec: duration_sec at top level, summary nested
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "session_end");
        assert_eq!(parsed["duration_sec"], 8139);
        assert!(parsed["summary"].is_object());
        assert_eq!(parsed["summary"]["icmp_sent"], 8139);
        assert_eq!(parsed["summary"]["grade"], "A");
    }
}
