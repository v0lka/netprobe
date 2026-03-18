//! TUI TCP/TLS/HTTP panel widget
//!
//! Displays:
//! - TCP connect time, TLS handshake time, TTFB, Total time, HTTP status code
//! - TLS version, cipher, cert days remaining (color-coded)
//! - BrailleSparkline for TCP connect time history
//! - "disabled" for --no-http/--no-tls
//! - Error display when prober fails

use crate::store::MetricsStore;
use crate::tui::sparkline::{BrailleSparkline, gradient_for_rtt};
use crate::tui::theme::Theme;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Widget},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// TCP/TLS/HTTP panel widget
#[derive(Debug)]
pub struct TcpTlsPanel<'a> {
    store: &'a MetricsStore,
    theme: &'a Theme,
    port: u16,
}

impl<'a> TcpTlsPanel<'a> {
    /// Create a new TCP/TLS/HTTP panel
    pub fn new(store: &'a MetricsStore, theme: &'a Theme, port: u16) -> Self {
        Self { store, theme, port }
    }

    /// Format a value with appropriate precision
    fn format_value(&self, value: f64, unit: &str) -> String {
        if value < 10.0 {
            format!("{:.2}{}", value, unit)
        } else if value < 100.0 {
            format!("{:.1}{}", value, unit)
        } else {
            format!("{:.0}{}", value, unit)
        }
    }
}

impl<'a> Widget for TcpTlsPanel<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 3 {
            return;
        }

        // Create the block with rounded borders
        let title = format!(" tcp/tls/http ── port {} ", self.port);
        let block = Block::default()
            .title(title)
            .title_style(Style::default().fg(self.theme.title))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(area);
        block.render(area, buf);

        if inner.width < 10 || inner.height < 2 {
            return;
        }

        // Check for errors first
        let latest_tcp = self.store.latest_tcp();
        let latest_tls = self.store.latest_tls();
        let latest_http = self.store.latest_http();

        // Show error if any layer has an error
        if let Some(ref error) = latest_tcp.error {
            self.render_error(inner, buf, error);
            return;
        }
        if let Some(ref error) = latest_tls.error {
            self.render_error(inner, buf, error);
            return;
        }
        if let Some(ref error) = latest_http.error {
            self.render_error(inner, buf, error);
            return;
        }

        // Split inner area into sections
        let sparkline_height = if inner.height > 4 { 2 } else { 1 };
        let constraints = vec![
            Constraint::Length(sparkline_height), // Sparkline
            Constraint::Min(1),                   // Timing row
            Constraint::Min(1),                   // TLS/HTTP info row
        ];

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(inner);

        // Get TCP history
        let history = self.store.tcp_connect_history();

        // Render sparkline if we have data and space
        if !history.is_empty() && chunks[0].width > 0 && chunks[0].height > 0 {
            let sparkline = BrailleSparkline::new(history)
                .height(chunks[0].height)
                .color_fn(gradient_for_rtt);

            sparkline.render(chunks[0], buf);
        }

        // Render timing row
        if chunks[1].width > 0 {
            let mut spans = vec![];

            // TCP timing
            if let Some(ref data) = latest_tcp.data {
                spans.push(Span::styled(
                    "TCP: ",
                    Style::default().fg(self.theme.dimmed),
                ));
                spans.push(Span::styled(
                    self.format_value(data.connect_ms, "ms"),
                    Style::default().fg(self.theme.text),
                ));
            } else {
                spans.push(Span::styled(
                    "TCP: ",
                    Style::default().fg(self.theme.dimmed),
                ));
                spans.push(Span::styled("--", Style::default().fg(self.theme.dimmed)));
            }

            // TLS timing
            spans.push(Span::styled(
                "   TLS: ",
                Style::default().fg(self.theme.dimmed),
            ));
            if let Some(ref data) = latest_tls.data {
                spans.push(Span::styled(
                    self.format_value(data.handshake_ms, "ms"),
                    Style::default().fg(self.theme.text),
                ));
            } else {
                spans.push(Span::styled(
                    "disabled",
                    Style::default().fg(self.theme.dimmed),
                ));
            }

            // TTFB
            spans.push(Span::styled(
                "   TTFB: ",
                Style::default().fg(self.theme.dimmed),
            ));
            if let Some(ref data) = latest_http.data {
                spans.push(Span::styled(
                    self.format_value(data.ttfb_ms, "ms"),
                    Style::default().fg(self.theme.text),
                ));
            } else {
                spans.push(Span::styled(
                    "disabled",
                    Style::default().fg(self.theme.dimmed),
                ));
            }

            // Total time
            spans.push(Span::styled(
                "   Total: ",
                Style::default().fg(self.theme.dimmed),
            ));
            if let Some(ref data) = latest_http.data {
                spans.push(Span::styled(
                    self.format_value(data.total_ms, "ms"),
                    Style::default().fg(self.theme.text),
                ));
            } else {
                spans.push(Span::styled(
                    "disabled",
                    Style::default().fg(self.theme.dimmed),
                ));
            }

            // HTTP status
            spans.push(Span::styled(
                "   HTTP ",
                Style::default().fg(self.theme.dimmed),
            ));
            if let Some(ref data) = latest_http.data {
                let status_color = if data.status_code < 400 {
                    self.theme.excellent
                } else {
                    self.theme.critical
                };
                spans.push(Span::styled(
                    data.status_code.to_string(),
                    Style::default().fg(status_color),
                ));
            } else {
                spans.push(Span::styled(
                    "disabled",
                    Style::default().fg(self.theme.dimmed),
                ));
            }

            self.render_line(chunks[1], buf, spans);
        }

        // Render TLS/HTTP details row
        if chunks[2].width > 0 && chunks.len() >= 3 {
            let mut spans = vec![];

            if let Some(ref data) = latest_tls.data {
                // TLS version
                spans.push(Span::styled(
                    &data.version,
                    Style::default().fg(self.theme.text),
                ));
                spans.push(Span::styled("  ", Style::default()));

                // Cipher
                spans.push(Span::styled(
                    &data.cipher,
                    Style::default().fg(self.theme.dimmed),
                ));
                spans.push(Span::styled("  ", Style::default()));

                // Cert info
                spans.push(Span::styled(
                    "Cert: ",
                    Style::default().fg(self.theme.dimmed),
                ));
                let cert_color = self.theme.color_for_cert_days(data.cert_days_remaining);
                spans.push(Span::styled(
                    format!("{} days remaining", data.cert_days_remaining),
                    Style::default().fg(cert_color),
                ));
            } else if latest_http.data.is_some() {
                // Plain HTTP (no TLS)
                spans.push(Span::styled(
                    "Plain HTTP (no TLS)",
                    Style::default().fg(self.theme.dimmed),
                ));
            } else {
                spans.push(Span::styled(
                    "TLS/HTTP disabled",
                    Style::default().fg(self.theme.dimmed),
                ));
            }

            self.render_line(chunks[2], buf, spans);
        }
    }
}

impl<'a> TcpTlsPanel<'a> {
    fn render_error(&self, area: Rect, buf: &mut Buffer, error: &str) {
        let error_text = format!("Error: {}", error);
        let error_width = error_text.width() as u16;
        let x = area.x + (area.width.saturating_sub(error_width)) / 2;
        let y = area.y + area.height / 2;

        let mut current_x = x;
        for ch in error_text.chars() {
            let ch_width = ch.width().unwrap_or(1) as u16;
            if current_x >= area.x + area.width {
                break;
            }
            buf[(current_x, y)].set_char(ch);
            buf[(current_x, y)].set_style(Style::default().fg(self.theme.critical));
            current_x += ch_width;
        }
    }

    fn render_line(&self, area: Rect, buf: &mut Buffer, spans: Vec<Span>) {
        let line = Line::from(spans);
        let x = area.x;
        let y = area.y;
        let mut current_x = x;

        for span in line.spans {
            let text = span.content.to_string();
            let style = span.style;

            for ch in text.chars() {
                let ch_width = ch.width().unwrap_or(1) as u16;
                if current_x >= x + area.width {
                    break;
                }
                buf[(current_x, y)].set_char(ch);
                buf[(current_x, y)].set_style(style);
                current_x += ch_width;
            }

            if current_x >= x + area.width {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{HttpData, MetricsStore, TcpData, TlsData};
    use chrono::Utc;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn create_test_store() -> MetricsStore {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        // Add some sample TCP data
        store.push_tcp_connect(15.0);
        store.push_tcp_connect(20.0);
        store.push_tcp_connect(18.5);

        store.set_latest_tcp(Some(TcpData { connect_ms: 15.0 }), None);

        store.set_latest_tls(
            Some(TlsData {
                handshake_ms: 42.3,
                version: "TLSv1.3".to_string(),
                cipher: "TLS_AES_256_GCM_SHA384".to_string(),
                cert_subject: "CN=one.one.one.one".to_string(),
                cert_issuer: "CN=DigiCert".to_string(),
                cert_san: vec!["one.one.one.one".to_string()],
                cert_expiry: Utc::now() + chrono::Duration::days(89),
                cert_days_remaining: 89,
            }),
            None,
        );

        store.set_latest_http(
            Some(HttpData {
                ttfb_ms: 78.4,
                total_ms: 82.1,
                status_code: 200,
            }),
            None,
        );

        store
    }

    #[test]
    fn test_tcp_tls_panel_new() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = TcpTlsPanel::new(&store, &theme, 443);

        assert_eq!(panel.port, 443);
    }

    #[test]
    fn test_tcp_tls_panel_rendering() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = TcpTlsPanel::new(&store, &theme, 443);

        let backend = TestBackend::new(80, 8);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                let area = f.area();
                f.render_widget(panel, area);
            })
            .unwrap();

        // Verify something was rendered
        let buffer = terminal.backend().buffer().clone();
        let content: String = buffer.content.iter().map(|c| c.symbol()).collect();

        // Should contain port in title
        assert!(content.contains("443"));
    }

    #[test]
    fn test_tcp_tls_panel_with_error() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());
        store.set_latest_tcp(None, Some("Connection refused".to_string()));

        let theme = Theme::new();
        let panel = TcpTlsPanel::new(&store, &theme, 443);

        let backend = TestBackend::new(80, 6);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                let area = f.area();
                f.render_widget(panel, area);
            })
            .unwrap();

        // Verify error was rendered
        let buffer = terminal.backend().buffer().clone();
        let content: String = buffer.content.iter().map(|c| c.symbol()).collect();

        assert!(content.contains("Error"));
        assert!(content.contains("Connection refused"));
    }

    #[test]
    fn test_format_value() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = TcpTlsPanel::new(&store, &theme, 443);

        assert_eq!(panel.format_value(5.123, "ms"), "5.12ms");
        assert_eq!(panel.format_value(50.5, "ms"), "50.5ms");
        assert_eq!(panel.format_value(150.0, "ms"), "150ms");
    }
}
