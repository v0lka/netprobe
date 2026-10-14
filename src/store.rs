//! Metrics store for shared state

use crate::models::*;
use crate::util::{calculate_percentile, compute_jitter};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Ring buffer with fixed capacity - wraps VecDeque
#[derive(Debug, Clone)]
pub struct RingBuffer<T> {
    buffer: VecDeque<T>,
    capacity: usize,
}

impl<T> RingBuffer<T> {
    /// Create a new ring buffer with specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Push a value into the buffer, removing oldest if at capacity
    ///
    /// `make_contiguous` re-rotates the backing storage, so once the buffer
    /// has wrapped at capacity `as_slice` still observes the complete
    /// chronological window instead of only the front run.
    pub fn push(&mut self, value: T) {
        if self.buffer.len() >= self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(value);
        self.buffer.make_contiguous();
    }

    /// Get all values as a slice in chronological order (oldest first)
    ///
    /// Every mutating method keeps the backing deque contiguous (`push`
    /// calls `make_contiguous`, `clear` empties it), so the single front
    /// slice is always the complete window — including after the buffer
    /// has wrapped at capacity.
    pub fn as_slice(&self) -> &[T] {
        self.buffer.as_slices().0
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Aggregated ICMP statistics
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IcmpAggregates {
    pub min_rtt: f64,
    pub max_rtt: f64,
    pub avg_rtt: f64,
    pub p95_rtt: f64,
    pub jitter: f64,
    pub sent: u64,
    pub received: u64,
    pub loss_pct: f64,
    pub duplicates: u64,
    pub reordered: u64,
}

/// Latest probe results with status
#[derive(Debug, Clone)]
pub struct ProbeResult<T> {
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> Default for ProbeResult<T> {
    fn default() -> Self {
        Self {
            data: None,
            error: None,
        }
    }
}

/// DNS result data
#[derive(Debug, Clone)]
pub struct DnsData {
    pub resolve_ms: f64,
    pub ips: Vec<IpAddr>,
    pub ttl_secs: Option<u32>,
    pub server: String,
}

/// TCP result data
#[derive(Debug, Clone)]
pub struct TcpData {
    pub connect_ms: f64,
}

/// TLS result data
#[derive(Debug, Clone)]
pub struct TlsData {
    pub handshake_ms: f64,
    pub version: String,
    pub cipher: String,
    pub cert_days_remaining: i64,
}

/// HTTP result data
#[derive(Debug, Clone)]
pub struct HttpData {
    pub ttfb_ms: f64,
    pub total_ms: f64,
    pub status_code: u16,
}

/// Traceroute hop data
#[derive(Debug, Clone)]
pub struct HopData {
    pub hop: u8,
    pub ip: Option<IpAddr>,
    pub rtt_ms: Option<f64>,
    pub host: Option<String>,
}

/// Traceroute result data
#[derive(Debug, Clone)]
pub struct TracerouteData {
    pub hops: Vec<HopData>,
}

/// Event entry for the events deque
#[derive(Debug, Clone)]
pub struct EventEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub severity: Severity,
    pub message: String,
}

/// Shared metrics store - wrapped in Arc<RwLock<>> for thread-safe access
#[derive(Debug)]
pub struct MetricsStore {
    // Ring buffers for time-series data
    icmp_rtt_history: RingBuffer<f64>,
    dns_resolve_history: RingBuffer<f64>,
    tcp_connect_history: RingBuffer<f64>,
    tls_handshake_history: RingBuffer<f64>,
    ttfb_history: RingBuffer<f64>,

    // ICMP aggregates
    icmp_aggregates: IcmpAggregates,

    // Latest probe results (for TUI display)
    latest_dns: ProbeResult<DnsData>,
    latest_tcp: ProbeResult<TcpData>,
    latest_tls: ProbeResult<TlsData>,
    latest_http: ProbeResult<HttpData>,
    latest_traceroute: ProbeResult<TracerouteData>,

    // Events log (bounded deque) - network anomalies only
    events: VecDeque<EventEntry>,
    max_events: usize,
    /// Total number of events ever pushed (unbounded; the deque is capped)
    events_total: u64,

    // Logs (bounded deque) - tracing/log messages
    logs: VecDeque<EventEntry>,
    max_logs: usize,

    // Session info
    session_start: chrono::DateTime<chrono::Utc>,
    traceroute_available: bool,

    // Target info
    target: String,
    resolved_target: Option<String>,
    /// All resolved IP addresses
    resolved_ips: Vec<IpAddr>,
    /// Index of currently active IP for monitoring
    active_ip_index: usize,
}

impl MetricsStore {
    /// Maximum number of events to keep
    const DEFAULT_MAX_EVENTS: usize = 200;

    /// Create a new metrics store with specified history size
    pub fn new(history_size: usize, target: String) -> Self {
        Self {
            icmp_rtt_history: RingBuffer::new(history_size),
            dns_resolve_history: RingBuffer::new(history_size),
            tcp_connect_history: RingBuffer::new(history_size),
            tls_handshake_history: RingBuffer::new(history_size),
            ttfb_history: RingBuffer::new(history_size),
            icmp_aggregates: IcmpAggregates::default(),
            latest_dns: ProbeResult::default(),
            latest_tcp: ProbeResult::default(),
            latest_tls: ProbeResult::default(),
            latest_http: ProbeResult::default(),
            latest_traceroute: ProbeResult::default(),
            events: VecDeque::with_capacity(Self::DEFAULT_MAX_EVENTS),
            max_events: Self::DEFAULT_MAX_EVENTS,
            events_total: 0,
            logs: VecDeque::with_capacity(Self::DEFAULT_MAX_EVENTS),
            max_logs: Self::DEFAULT_MAX_EVENTS,
            session_start: chrono::Utc::now(),
            traceroute_available: true,
            target,
            resolved_target: None,
            resolved_ips: Vec::new(),
            active_ip_index: 0,
        }
    }

    // ICMP methods

    /// Push a new ICMP RTT value
    pub fn push_icmp_rtt(&mut self, rtt: f64) {
        self.icmp_rtt_history.push(rtt);
        self.icmp_aggregates.received += 1;
        self.recalculate_icmp_aggregates();
    }

    /// Increment ICMP sent counter
    pub fn inc_icmp_sent(&mut self) {
        self.icmp_aggregates.sent += 1;
        self.recalculate_loss_pct();
    }

    /// Increment ICMP duplicate counter
    pub fn inc_icmp_duplicate(&mut self) {
        self.icmp_aggregates.duplicates += 1;
    }

    /// Increment ICMP reordered counter
    pub fn inc_icmp_reordered(&mut self) {
        self.icmp_aggregates.reordered += 1;
    }

    /// Get ICMP RTT history
    pub fn icmp_rtt_history(&self) -> &[f64] {
        self.icmp_rtt_history.as_slice()
    }

    /// Get ICMP aggregates
    pub fn icmp_aggregates(&self) -> &IcmpAggregates {
        &self.icmp_aggregates
    }

    // DNS methods

    /// Push a new DNS resolve time
    pub fn push_dns_resolve(&mut self, ms: f64) {
        self.dns_resolve_history.push(ms);
    }

    /// Get DNS resolve history
    pub fn dns_resolve_history(&self) -> &[f64] {
        self.dns_resolve_history.as_slice()
    }

    /// Set latest DNS result
    pub fn set_latest_dns(&mut self, data: Option<DnsData>, error: Option<String>) {
        self.latest_dns = ProbeResult { data, error };
    }

    /// Get latest DNS result
    pub fn latest_dns(&self) -> &ProbeResult<DnsData> {
        &self.latest_dns
    }

    // TCP methods

    /// Push a new TCP connect time
    pub fn push_tcp_connect(&mut self, ms: f64) {
        self.tcp_connect_history.push(ms);
    }

    /// Get TCP connect history
    pub fn tcp_connect_history(&self) -> &[f64] {
        self.tcp_connect_history.as_slice()
    }

    /// Set latest TCP result
    pub fn set_latest_tcp(&mut self, data: Option<TcpData>, error: Option<String>) {
        self.latest_tcp = ProbeResult { data, error };
    }

    /// Get latest TCP result
    pub fn latest_tcp(&self) -> &ProbeResult<TcpData> {
        &self.latest_tcp
    }

    // TLS methods

    /// Push a new TLS handshake time
    pub fn push_tls_handshake(&mut self, ms: f64) {
        self.tls_handshake_history.push(ms);
    }

    /// Get TLS handshake history
    #[allow(dead_code)]
    pub fn tls_handshake_history(&self) -> &[f64] {
        self.tls_handshake_history.as_slice()
    }

    /// Set latest TLS result
    pub fn set_latest_tls(&mut self, data: Option<TlsData>, error: Option<String>) {
        self.latest_tls = ProbeResult { data, error };
    }

    /// Get latest TLS result
    pub fn latest_tls(&self) -> &ProbeResult<TlsData> {
        &self.latest_tls
    }

    // HTTP methods

    /// Push a new TTFB value
    pub fn push_ttfb(&mut self, ms: f64) {
        self.ttfb_history.push(ms);
    }

    /// Get TTFB history
    #[allow(dead_code)]
    pub fn ttfb_history(&self) -> &[f64] {
        self.ttfb_history.as_slice()
    }

    /// Set latest HTTP result
    pub fn set_latest_http(&mut self, data: Option<HttpData>, error: Option<String>) {
        self.latest_http = ProbeResult { data, error };
    }

    /// Get latest HTTP result
    pub fn latest_http(&self) -> &ProbeResult<HttpData> {
        &self.latest_http
    }

    // Traceroute methods

    /// Set latest traceroute result
    pub fn set_latest_traceroute(&mut self, data: Option<TracerouteData>, error: Option<String>) {
        self.latest_traceroute = ProbeResult { data, error };
    }

    /// Get latest traceroute result
    pub fn latest_traceroute(&self) -> &ProbeResult<TracerouteData> {
        &self.latest_traceroute
    }

    // Event methods

    /// Push a new event
    pub fn push_event(&mut self, event_type: String, severity: Severity, message: String) {
        self.events_total += 1;
        if self.events.len() >= self.max_events {
            self.events.pop_front();
        }
        self.events.push_back(EventEntry {
            timestamp: chrono::Utc::now(),
            event_type,
            severity,
            message,
        });
    }

    /// Push a log event from tracing
    /// Used for capturing tracing output in TUI mode
    pub fn push_log_event(&mut self, level: tracing::Level, target: &str, message: String) {
        let (event_type, severity) = match level {
            tracing::Level::ERROR => ("log_error", Severity::Critical),
            tracing::Level::WARN => ("log_warn", Severity::Warning),
            tracing::Level::INFO => ("log_info", Severity::Info),
            tracing::Level::DEBUG => ("log_debug", Severity::Info),
            tracing::Level::TRACE => ("log_trace", Severity::Info),
        };

        // Sanitize message: replace ALL control characters (C0 range and
        // DEL — including ESC/ANSI escape sequences) with spaces so they
        // cannot break the TUI layout
        let sanitized_message: String = message
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();

        // Format message with shortened target
        let short_target = target.split("::").last().unwrap_or(target);
        let formatted_message = format!("[{}] {}", short_target, sanitized_message);

        if self.logs.len() >= self.max_logs {
            self.logs.pop_front();
        }
        self.logs.push_back(EventEntry {
            timestamp: chrono::Utc::now(),
            event_type: event_type.to_string(),
            severity,
            message: formatted_message,
        });
    }

    /// Get events (network anomalies)
    pub fn events(&self) -> &VecDeque<EventEntry> {
        &self.events
    }

    /// Get the total number of events ever pushed
    ///
    /// Unlike [`Self::events`] (a bounded deque that evicts FIFO), this
    /// counter never decreases, so it reflects the true session event count.
    pub fn events_total(&self) -> u64 {
        self.events_total
    }

    /// Get logs (tracing messages)
    pub fn logs(&self) -> &VecDeque<EventEntry> {
        &self.logs
    }

    // Session methods

    /// Get session start time
    pub fn session_start(&self) -> chrono::DateTime<chrono::Utc> {
        self.session_start
    }

    /// Set traceroute availability
    pub fn set_traceroute_available(&mut self, available: bool) {
        self.traceroute_available = available;
    }

    /// Check if traceroute is available
    pub fn traceroute_available(&self) -> bool {
        self.traceroute_available
    }

    /// Get target
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Set resolved target (hostname)
    pub fn set_resolved_target(&mut self, resolved: Option<String>) {
        self.resolved_target = resolved;
    }

    /// Set all resolved IP addresses, marking `active` as the one currently
    /// monitored by the probes
    ///
    /// `active` is matched by value against `ips`; when it is `None` or not
    /// present in `ips`, index 0 is selected. Keeping the active index in
    /// sync with the probed IP prevents the header from displaying a
    /// different address than the one being measured.
    pub fn set_resolved_ips_with_active(&mut self, ips: Vec<IpAddr>, active: Option<IpAddr>) {
        self.active_ip_index = active
            .and_then(|ip| ips.iter().position(|&candidate| candidate == ip))
            .unwrap_or(0);
        self.resolved_ips = ips;
    }

    /// Get the currently active IP for monitoring
    pub fn active_ip(&self) -> Option<IpAddr> {
        self.resolved_ips.get(self.active_ip_index).copied()
    }

    /// Get the active IP index (0-based)
    pub fn active_ip_index(&self) -> usize {
        self.active_ip_index
    }

    /// Get the total number of resolved IPs
    pub fn resolved_ip_count(&self) -> usize {
        self.resolved_ips.len()
    }

    /// Switch to the next IP address
    /// Returns true if switched, false if there's only one or no IPs
    ///
    /// Per-endpoint ICMP statistics (history + aggregates) are cleared on a
    /// successful switch so the panel, header MOS, and session summary reflect
    /// only the newly selected endpoint.
    pub fn next_ip(&mut self) -> bool {
        if self.resolved_ips.len() <= 1 {
            return false;
        }
        self.active_ip_index = (self.active_ip_index + 1) % self.resolved_ips.len();
        self.clear_icmp_stats();
        true
    }

    /// Switch to the previous IP address
    /// Returns true if switched, false if there's only one or no IPs
    ///
    /// Like [`Self::next_ip`], a successful switch clears the per-endpoint
    /// ICMP statistics.
    pub fn prev_ip(&mut self) -> bool {
        if self.resolved_ips.len() <= 1 {
            return false;
        }
        if self.active_ip_index == 0 {
            self.active_ip_index = self.resolved_ips.len() - 1;
        } else {
            self.active_ip_index -= 1;
        }
        self.clear_icmp_stats();
        true
    }

    /// Clear per-endpoint ICMP statistics (RTT history + aggregates)
    fn clear_icmp_stats(&mut self) {
        self.icmp_rtt_history.clear();
        self.icmp_aggregates = IcmpAggregates::default();
    }

    /// Reset statistics (for 'r' hotkey)
    pub fn reset(&mut self) {
        self.clear_icmp_stats();
        self.dns_resolve_history.clear();
        self.tcp_connect_history.clear();
        self.tls_handshake_history.clear();
        self.ttfb_history.clear();
        self.session_start = chrono::Utc::now();
        // Note: we don't clear events, the events_total counter, or latest
        // results on reset
    }

    // Private helper methods

    fn recalculate_icmp_aggregates(&mut self) {
        let values = self.icmp_rtt_history.as_slice();
        if values.is_empty() {
            return;
        }

        // Calculate min, max, avg
        let mut sum = 0.0;
        let mut min = values[0];
        let mut max = values[0];

        for &v in values {
            sum += v;
            if v < min {
                min = v;
            }
            if v > max {
                max = v;
            }
        }

        let avg = sum / values.len() as f64;

        // Lower-index quantile (rank ⌊p·(n−1)⌋, see `util::calculate_percentile`)
        // via partial selection: O(n) average per sample instead of an
        // O(n log n) full sort (and NaN-safe)
        let p95 = calculate_percentile(values, 0.95);

        // Calculate jitter (mean absolute difference between consecutive values)
        let jitter = compute_jitter(values);

        self.icmp_aggregates.min_rtt = min;
        self.icmp_aggregates.max_rtt = max;
        self.icmp_aggregates.avg_rtt = avg;
        self.icmp_aggregates.p95_rtt = p95;
        self.icmp_aggregates.jitter = jitter;

        self.recalculate_loss_pct();
    }

    fn recalculate_loss_pct(&mut self) {
        if self.icmp_aggregates.sent > 0 {
            // saturating_sub: `received` can exceed `sent` — transiently
            // while a store reset races an in-flight probe result, and for
            // as long as duplicate replies keep arriving (each duplicate
            // pushes an RTT sample); a plain u64 subtraction would panic
            // (debug) or wrap (release).
            let lost = self
                .icmp_aggregates
                .sent
                .saturating_sub(self.icmp_aggregates.received);
            self.icmp_aggregates.loss_pct =
                (lost as f64 / self.icmp_aggregates.sent as f64) * 100.0;
        }
    }
}

/// Type alias for the shared store
pub type SharedStore = Arc<RwLock<MetricsStore>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_basic() {
        let mut buf = RingBuffer::new(3);
        assert!(buf.as_slice().is_empty());

        buf.push(1.0);
        buf.push(2.0);
        assert_eq!(buf.as_slice().len(), 2);

        buf.push(3.0);
        assert_eq!(buf.as_slice().len(), 3);

        // Should overflow - oldest removed
        buf.push(4.0);
        assert_eq!(buf.as_slice().len(), 3);
        assert_eq!(buf.as_slice(), [2.0, 3.0, 4.0]);
    }

    #[test]
    fn test_ring_buffer_as_slice_after_wrap() {
        // Regression: once the deque wraps at capacity, as_slice must still
        // return the complete window in chronological order — the wrapped
        // tail holds the newest samples.
        let mut buf = RingBuffer::new(3);
        for v in 1..=7 {
            buf.push(f64::from(v));
        }
        assert_eq!(buf.as_slice(), [5.0, 6.0, 7.0]);
        assert_eq!(buf.as_slice().len(), 3);

        // The wrapped state is stable: further pushes keep the window whole
        buf.push(8.0);
        assert_eq!(buf.as_slice(), [6.0, 7.0, 8.0]);
    }

    #[test]
    fn test_ring_buffer_latest() {
        let mut buf = RingBuffer::new(5);
        assert_eq!(buf.as_slice().last(), None);

        buf.push(10.0);
        assert_eq!(buf.as_slice().last(), Some(&10.0));

        buf.push(20.0);
        assert_eq!(buf.as_slice().last(), Some(&20.0));
    }

    #[test]
    fn test_ring_buffer_clear() {
        let mut buf = RingBuffer::new(5);
        buf.push(1.0);
        buf.push(2.0);
        assert_eq!(buf.as_slice().len(), 2);

        buf.clear();
        assert!(buf.as_slice().is_empty());
    }

    #[test]
    fn test_metrics_store_icmp() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        // Simulate some ICMP probes
        for i in 0..10 {
            store.inc_icmp_sent();
            store.push_icmp_rtt(10.0 + i as f64);
        }

        let agg = store.icmp_aggregates();
        assert_eq!(agg.sent, 10);
        assert_eq!(agg.received, 10);
        assert_eq!(agg.loss_pct, 0.0);
        assert_eq!(agg.min_rtt, 10.0);
        assert_eq!(agg.max_rtt, 19.0);
    }

    #[test]
    fn test_metrics_store_packet_loss() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        // Send 10, receive 7
        for _ in 0..10 {
            store.inc_icmp_sent();
        }
        for i in 0..7 {
            store.push_icmp_rtt(10.0 + i as f64);
        }

        let agg = store.icmp_aggregates();
        assert_eq!(agg.sent, 10);
        assert_eq!(agg.received, 7);
        assert_eq!(agg.loss_pct, 30.0);
    }

    #[test]
    fn test_metrics_store_loss_pct_received_exceeds_sent() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        // Transient inconsistent state (reset racing an in-flight result):
        // `received` > `sent` must not panic or wrap loss_pct
        store.inc_icmp_sent();
        store.push_icmp_rtt(10.0);
        store.push_icmp_rtt(12.0);

        let agg = store.icmp_aggregates();
        assert_eq!(agg.sent, 1);
        assert_eq!(agg.received, 2);
        assert_eq!(agg.loss_pct, 0.0);
    }

    #[test]
    fn test_metrics_store_duplicates_and_reordered() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        store.inc_icmp_duplicate();
        store.inc_icmp_duplicate();
        store.inc_icmp_reordered();

        let agg = store.icmp_aggregates();
        assert_eq!(agg.duplicates, 2);
        assert_eq!(agg.reordered, 1);
    }

    #[test]
    fn test_metrics_store_dns() {
        let mut store = MetricsStore::new(100, "example.com".to_string());

        store.push_dns_resolve(5.0);
        store.push_dns_resolve(10.0);
        store.push_dns_resolve(15.0);

        assert_eq!(store.dns_resolve_history().len(), 3);
        assert_eq!(store.dns_resolve_history().last(), Some(&15.0));

        // Set latest DNS result
        store.set_latest_dns(
            Some(DnsData {
                resolve_ms: 5.0,
                ips: vec!["1.1.1.1".parse().unwrap()],
                ttl_secs: Some(300),
                server: "8.8.8.8".to_string(),
            }),
            None,
        );

        let latest = store.latest_dns();
        assert!(latest.data.is_some());
        assert!(latest.error.is_none());
    }

    #[test]
    fn test_metrics_store_dns_error() {
        let mut store = MetricsStore::new(100, "example.com".to_string());

        store.set_latest_dns(None, Some("DNS timeout".to_string()));

        let latest = store.latest_dns();
        assert!(latest.data.is_none());
        assert_eq!(latest.error, Some("DNS timeout".to_string()));
    }

    #[test]
    fn test_metrics_store_events() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        store.push_event(
            "rtt_spike".to_string(),
            Severity::Warning,
            "RTT spike detected".to_string(),
        );
        store.push_event(
            "loss_burst".to_string(),
            Severity::Critical,
            "Packet loss burst".to_string(),
        );

        assert_eq!(store.events().len(), 2);
    }

    #[test]
    fn test_metrics_store_events_overflow() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        // Add more events than max
        for i in 0..250 {
            store.push_event(
                format!("event_{}", i),
                Severity::Info,
                format!("Message {}", i),
            );
        }

        // Should be capped at 200
        assert_eq!(store.events().len(), 200);
        // But the total count is unbounded
        assert_eq!(store.events_total(), 250);
    }

    #[test]
    fn test_metrics_store_reset() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());
        let original_start = store.session_start();

        // Add data to every history, the aggregates, the event log, and a
        // latest_* slot, so both halves of reset()'s contract are exercised:
        // histories/aggregates are cleared, events and latest_* survive.
        store.push_icmp_rtt(10.0);
        store.push_dns_resolve(5.0);
        store.push_tcp_connect(12.0);
        store.push_tls_handshake(20.0);
        store.push_ttfb(30.0);
        store.inc_icmp_sent();
        store.push_event(
            "rtt_spike".to_string(),
            Severity::Warning,
            "RTT spike detected".to_string(),
        );
        store.set_latest_dns(
            Some(DnsData {
                resolve_ms: 5.0,
                ips: vec!["1.1.1.1".parse().unwrap()],
                ttl_secs: Some(300),
                server: "8.8.8.8".to_string(),
            }),
            None,
        );

        // Small delay so the reset timestamp is strictly newer than the
        // original one (Utc::now() can return the same value within one tick)
        std::thread::sleep(std::time::Duration::from_millis(2));

        // Reset
        store.reset();

        // All five histories and the aggregates should be cleared
        assert!(store.icmp_rtt_history().is_empty());
        assert!(store.dns_resolve_history().is_empty());
        assert!(store.tcp_connect_history().is_empty());
        assert!(store.tls_handshake_history().is_empty());
        assert!(store.ttfb_history().is_empty());
        assert_eq!(store.icmp_aggregates(), &IcmpAggregates::default());

        // Events and latest_* slots are deliberately preserved
        assert_eq!(store.events().len(), 1);
        assert!(store.latest_dns().data.is_some());

        // Session start should be updated
        assert!(store.session_start() > original_start);
    }

    #[test]
    fn test_percentile() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];

        assert_eq!(calculate_percentile(&data, 0.0), 1.0);
        assert_eq!(calculate_percentile(&data, 0.5), 5.0);
        assert_eq!(calculate_percentile(&data, 0.95), 9.0);
        assert_eq!(calculate_percentile(&data, 1.0), 10.0);
    }

    #[test]
    fn test_jitter_calculation() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        // RTT sequence: 10, 20, 10, 20 (jitter = mean of |10|, |10|, |10| = 10)
        store.inc_icmp_sent();
        store.push_icmp_rtt(10.0);
        store.inc_icmp_sent();
        store.push_icmp_rtt(20.0);
        store.inc_icmp_sent();
        store.push_icmp_rtt(10.0);
        store.inc_icmp_sent();
        store.push_icmp_rtt(20.0);

        let agg = store.icmp_aggregates();
        assert_eq!(agg.jitter, 10.0);
    }

    #[test]
    fn test_traceroute_available() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        assert!(store.traceroute_available());

        store.set_traceroute_available(false);
        assert!(!store.traceroute_available());
    }

    #[test]
    fn test_resolved_ips_and_switching() {
        use std::net::IpAddr;
        use std::str::FromStr;

        let mut store = MetricsStore::new(100, "example.com".to_string());

        // Initially empty
        assert_eq!(store.resolved_ip_count(), 0);
        assert_eq!(store.active_ip(), None);
        assert_eq!(store.active_ip_index(), 0);

        // Set multiple IPs
        let ips: Vec<IpAddr> = vec![
            IpAddr::from_str("1.1.1.1").unwrap(),
            IpAddr::from_str("1.0.0.1").unwrap(),
            IpAddr::from_str("8.8.8.8").unwrap(),
        ];
        store.set_resolved_ips_with_active(ips.clone(), None);

        assert_eq!(store.resolved_ip_count(), 3);
        assert_eq!(store.active_ip(), Some(ips[0]));
        assert_eq!(store.active_ip_index(), 0);

        // Switch to next IP
        assert!(store.next_ip());
        assert_eq!(store.active_ip(), Some(ips[1]));
        assert_eq!(store.active_ip_index(), 1);

        // Switch to next IP
        assert!(store.next_ip());
        assert_eq!(store.active_ip(), Some(ips[2]));
        assert_eq!(store.active_ip_index(), 2);

        // Wrap around to first
        assert!(store.next_ip());
        assert_eq!(store.active_ip(), Some(ips[0]));
        assert_eq!(store.active_ip_index(), 0);

        // Switch to previous (wraps to last)
        assert!(store.prev_ip());
        assert_eq!(store.active_ip(), Some(ips[2]));
        assert_eq!(store.active_ip_index(), 2);

        // Switch to previous
        assert!(store.prev_ip());
        assert_eq!(store.active_ip(), Some(ips[1]));
        assert_eq!(store.active_ip_index(), 1);

        // Setting new IPs resets index
        let new_ips: Vec<IpAddr> = vec![IpAddr::from_str("9.9.9.9").unwrap()];
        store.set_resolved_ips_with_active(new_ips.clone(), None);
        assert_eq!(store.active_ip_index(), 0);
        assert_eq!(store.active_ip(), Some(new_ips[0]));

        // With single IP, next/prev return false
        assert!(!store.next_ip());
        assert!(!store.prev_ip());
    }

    #[test]
    fn test_resolved_ips_empty() {
        let mut store = MetricsStore::new(100, "example.com".to_string());

        // Empty vec
        store.set_resolved_ips_with_active(vec![], None);
        assert_eq!(store.resolved_ip_count(), 0);
        assert_eq!(store.active_ip(), None);
        assert!(!store.next_ip());
        assert!(!store.prev_ip());
    }

    #[test]
    fn test_set_resolved_ips_with_active() {
        use std::net::IpAddr;
        use std::str::FromStr;

        let mut store = MetricsStore::new(100, "example.com".to_string());

        let v6: IpAddr = IpAddr::from_str("2606:4700:4700::1111").unwrap();
        let v4: IpAddr = IpAddr::from_str("1.1.1.1").unwrap();

        // Dual-stack answer where the probed (IPv4) address is not first:
        // the active index must land on the probed IP, not on index 0
        store.set_resolved_ips_with_active(vec![v6, v4], Some(v4));
        assert_eq!(store.active_ip_index(), 1);
        assert_eq!(store.active_ip(), Some(v4));
        assert_eq!(store.resolved_ip_count(), 2);

        // Unknown active falls back to index 0
        let other: IpAddr = IpAddr::from_str("8.8.8.8").unwrap();
        store.set_resolved_ips_with_active(vec![v6, v4], Some(other));
        assert_eq!(store.active_ip_index(), 0);

        // None active falls back to index 0 (passing None)
        store.set_resolved_ips_with_active(vec![v6, v4], None);
        assert_eq!(store.active_ip_index(), 0);
    }

    #[test]
    fn test_ip_switch_clears_icmp_stats() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        let ips: Vec<std::net::IpAddr> = vec![
            "1.1.1.1".parse().unwrap(),
            "1.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        ];
        store.set_resolved_ips_with_active(ips.clone(), None);

        // Accumulate ICMP samples on the first IP
        for _ in 0..10 {
            store.inc_icmp_sent();
            store.push_icmp_rtt(40.0);
        }
        assert_eq!(store.icmp_rtt_history().len(), 10);
        assert_eq!(store.icmp_aggregates().sent, 10);

        // A successful switch must clear the per-endpoint ICMP statistics so
        // the two endpoints are not blended
        assert!(store.next_ip());
        assert_eq!(store.active_ip(), Some(ips[1]));
        assert!(store.icmp_rtt_history().is_empty());
        assert_eq!(store.icmp_aggregates(), &IcmpAggregates::default());

        // prev_ip behaves the same
        store.inc_icmp_sent();
        store.push_icmp_rtt(50.0);
        assert!(store.prev_ip());
        assert_eq!(store.active_ip(), Some(ips[0]));
        assert!(store.icmp_rtt_history().is_empty());
        assert_eq!(store.icmp_aggregates(), &IcmpAggregates::default());

        // A failed switch (single IP) keeps the stats
        store.set_resolved_ips_with_active(vec![ips[0]], None);
        store.inc_icmp_sent();
        store.push_icmp_rtt(60.0);
        assert!(!store.next_ip());
        assert!(!store.prev_ip());
        assert_eq!(store.icmp_rtt_history().len(), 1);
    }
}
