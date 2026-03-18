//! TUI DNS panel widget
//!
//! Displays:
//! - Resolve time, IP list, TTL, DNS server
//! - BrailleSparkline for resolve time history
//! - Error display when DNS prober fails

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

/// DNS panel widget displaying DNS resolution statistics
#[derive(Debug)]
pub struct DnsPanel<'a> {
    store: &'a MetricsStore,
    theme: &'a Theme,
}

impl<'a> DnsPanel<'a> {
    /// Create a new DNS panel
    pub fn new(store: &'a MetricsStore, theme: &'a Theme) -> Self {
        Self { store, theme }
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

impl<'a> Widget for DnsPanel<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 3 {
            return;
        }

        // Create the block with rounded borders
        let block = Block::default()
            .title(" dns ")
            .title_style(Style::default().fg(self.theme.title))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(area);
        block.render(area, buf);

        if inner.width < 10 || inner.height < 2 {
            return;
        }

        // Check if there's an error
        let latest_dns = self.store.latest_dns();
        if let Some(ref error) = latest_dns.error {
            // Show error in red
            let error_text = format!("Error: {}", error);
            let error_width = error_text.width() as u16;
            let x = inner.x + (inner.width.saturating_sub(error_width)) / 2;
            let y = inner.y + inner.height / 2;

            let mut current_x = x;
            for ch in error_text.chars() {
                let ch_width = ch.width().unwrap_or(1) as u16;
                if current_x >= inner.x + inner.width {
                    break;
                }
                buf[(current_x, y)].set_char(ch);
                buf[(current_x, y)].set_style(Style::default().fg(self.theme.critical));
                current_x += ch_width;
            }
            return;
        }

        // Split inner area into sections
        let sparkline_height = if inner.height > 3 { 2 } else { 1 };
        let constraints = vec![
            Constraint::Length(sparkline_height), // Sparkline
            Constraint::Min(1),                   // Info row
        ];

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(inner);

        // Get DNS history
        let history = self.store.dns_resolve_history();

        // Render sparkline if we have data and space
        if !history.is_empty() && chunks[0].width > 0 && chunks[0].height > 0 {
            let sparkline = BrailleSparkline::new(history)
                .height(chunks[0].height)
                .color_fn(gradient_for_rtt);

            sparkline.render(chunks[0], buf);
        }

        // Render DNS info row
        if chunks[1].width > 0 {
            let mut spans = vec![];

            if let Some(ref data) = latest_dns.data {
                // Resolve time
                spans.push(Span::styled(
                    "Resolve: ",
                    Style::default().fg(self.theme.dimmed),
                ));
                spans.push(Span::styled(
                    self.format_value(data.resolve_ms, "ms"),
                    Style::default().fg(self.theme.text),
                ));

                // IPs - show first IP only with count if multiple
                spans.push(Span::styled(
                    "   IPs: ",
                    Style::default().fg(self.theme.dimmed),
                ));
                let ip_str = if data.ips.len() > 1 {
                    format!("{} ... ({} total)", data.ips[0], data.ips.len())
                } else {
                    data.ips[0].to_string()
                };
                spans.push(Span::styled(ip_str, Style::default().fg(self.theme.text)));

                // TTL
                if let Some(ttl) = data.ttl_secs {
                    spans.push(Span::styled(
                        "   TTL: ",
                        Style::default().fg(self.theme.dimmed),
                    ));
                    spans.push(Span::styled(
                        format!("{}s", ttl),
                        Style::default().fg(self.theme.text),
                    ));
                }

                // Server
                spans.push(Span::styled(
                    "   Server: ",
                    Style::default().fg(self.theme.dimmed),
                ));
                spans.push(Span::styled(
                    &data.server,
                    Style::default().fg(self.theme.text),
                ));
            } else {
                // No data yet
                spans.push(Span::styled(
                    "waiting for DNS resolution...",
                    Style::default().fg(self.theme.dimmed),
                ));
            }

            // Render the line
            let line = Line::from(spans);
            let x = chunks[1].x;
            let y = chunks[1].y;
            let mut current_x = x;

            for span in line.spans {
                let text = span.content.to_string();
                let style = span.style;

                for ch in text.chars() {
                    let ch_width = ch.width().unwrap_or(1) as u16;
                    if current_x >= x + chunks[1].width {
                        break;
                    }
                    buf[(current_x, y)].set_char(ch);
                    buf[(current_x, y)].set_style(style);
                    current_x += ch_width;
                }

                if current_x >= x + chunks[1].width {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{DnsData, MetricsStore};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn create_test_store() -> MetricsStore {
        let mut store = MetricsStore::new(100, "example.com".to_string());

        // Add some sample DNS data
        store.push_dns_resolve(5.0);
        store.push_dns_resolve(10.0);
        store.push_dns_resolve(7.5);

        store.set_latest_dns(
            Some(DnsData {
                resolve_ms: 5.0,
                ips: vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()],
                ttl_secs: Some(300),
                server: "8.8.8.8".to_string(),
            }),
            None,
        );

        store
    }

    #[test]
    fn test_dns_panel_new() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = DnsPanel::new(&store, &theme);

        // Just verify it doesn't panic
        let _ = panel.format_value(5.0, "ms");
    }

    #[test]
    fn test_dns_panel_rendering() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = DnsPanel::new(&store, &theme);

        let backend = TestBackend::new(80, 6);
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

        // Should contain "dns" in the title
        assert!(content.contains("dns"));
    }

    #[test]
    fn test_dns_panel_with_error() {
        let mut store = MetricsStore::new(100, "example.com".to_string());
        store.set_latest_dns(None, Some("DNS timeout".to_string()));

        let theme = Theme::new();
        let panel = DnsPanel::new(&store, &theme);

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
        assert!(content.contains("DNS timeout"));
    }
}
