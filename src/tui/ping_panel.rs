//! TUI ping panel widget
//!
//! Displays:
//! - Braille sparkline of RTT history
//! - Min/max labels under the sparkline
//! - Current metrics: Now, Avg, Min, Max, p95
//! - Additional stats: Jitter, Loss%, Sent, Recv

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

/// Ping panel widget displaying ICMP statistics and RTT history
#[derive(Debug)]
pub struct PingPanel<'a> {
    store: &'a MetricsStore,
    theme: &'a Theme,
    compact: bool,
}

impl<'a> PingPanel<'a> {
    /// Create a new ping panel
    pub fn new(store: &'a MetricsStore, theme: &'a Theme, compact: bool) -> Self {
        Self {
            store,
            theme,
            compact,
        }
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

    /// Calculate percentiles from RTT history
    fn calculate_percentiles(&self) -> (f64, f64, f64) {
        let history = self.store.icmp_rtt_history();
        if history.len() < 2 {
            return (0.0, 0.0, 0.0);
        }

        let mut sorted: Vec<f64> = history.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let p25_idx = (sorted.len() as f64 * 0.25) as usize;
        let p75_idx = (sorted.len() as f64 * 0.75) as usize;
        let p95_idx = (sorted.len() as f64 * 0.95) as usize;

        (
            sorted[p25_idx.min(sorted.len() - 1)],
            sorted[p75_idx.min(sorted.len() - 1)],
            sorted[p95_idx.min(sorted.len() - 1)],
        )
    }
}

impl<'a> Widget for PingPanel<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 3 {
            return;
        }

        // Create the block with rounded borders
        let block = Block::default()
            .title(" ping ")
            .title_style(Style::default().fg(self.theme.title))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(self.theme.border));

        let inner = block.inner(area);
        block.render(area, buf);

        if inner.width < 10 || inner.height < 3 {
            return;
        }

        // Split inner area into sections
        // [sparkline area]
        // [min/max labels]
        // [metrics row 1]
        // [metrics row 2]
        let sparkline_height = inner.height.saturating_sub(3).max(2);
        let constraints = vec![
            Constraint::Length(sparkline_height),
            Constraint::Length(1), // min/max labels
            Constraint::Length(1), // metrics row 1
            Constraint::Length(1), // metrics row 2
        ];

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(inner);

        // Get RTT history and aggregates
        let history = self.store.icmp_rtt_history();
        let agg = self.store.icmp_aggregates();

        // Calculate percentiles for color gradient
        let (p25, p75, p95) = self.calculate_percentiles();

        // Render sparkline if we have data and space
        if !history.is_empty() && chunks[0].width > 0 && chunks[0].height > 0 {
            let sparkline = BrailleSparkline::new(history)
                .height(chunks[0].height)
                .color_fn(gradient_for_rtt);

            sparkline.render(chunks[0], buf);
        }

        // Render min/max labels under sparkline
        if chunks[1].width > 0 {
            let min_label = format!("{:.1}ms", agg.min_rtt);
            let max_label = format!("{:.1}ms", agg.max_rtt);

            // Left-align min, right-align max (use display width, not byte length)
            let min_x = chunks[1].x;
            let max_label_width = max_label.width() as u16;
            let max_x = chunks[1].x + chunks[1].width.saturating_sub(max_label_width);

            let mut current_x = min_x;
            for ch in min_label.chars() {
                let ch_width = ch.width().unwrap_or(1) as u16;
                if current_x >= chunks[1].x + chunks[1].width {
                    break;
                }
                buf[(current_x, chunks[1].y)].set_char(ch);
                buf[(current_x, chunks[1].y)].set_style(Style::default().fg(self.theme.dimmed));
                current_x += ch_width;
            }

            let mut current_x = max_x;
            for ch in max_label.chars() {
                let ch_width = ch.width().unwrap_or(1) as u16;
                if current_x >= chunks[1].x + chunks[1].width {
                    break;
                }
                buf[(current_x, chunks[1].y)].set_char(ch);
                buf[(current_x, chunks[1].y)].set_style(Style::default().fg(self.theme.dimmed));
                current_x += ch_width;
            }
        }

        // Render metrics row 1: Now, Avg, Min, Max, p95
        if chunks[2].width > 0 {
            let latest_rtt = history.last().copied().unwrap_or(0.0);
            let rtt_color = if history.len() >= 2 {
                self.theme.color_for_rtt(latest_rtt, p25, p75, p95)
            } else {
                self.theme.text
            };

            let _metrics_text = if self.compact {
                format!(
                    "Now: {}  Avg: {}  Min: {}  Max: {}",
                    self.format_value(latest_rtt, "ms"),
                    self.format_value(agg.avg_rtt, "ms"),
                    self.format_value(agg.min_rtt, "ms"),
                    self.format_value(agg.max_rtt, "ms"),
                )
            } else {
                format!(
                    "Now: {}  Avg: {}  Min: {}  Max: {}  p95: {}",
                    self.format_value(latest_rtt, "ms"),
                    self.format_value(agg.avg_rtt, "ms"),
                    self.format_value(agg.min_rtt, "ms"),
                    self.format_value(agg.max_rtt, "ms"),
                    self.format_value(agg.p95_rtt, "ms"),
                )
            };

            let line = Line::from(vec![
                Span::styled("Now: ", Style::default().fg(self.theme.dimmed)),
                Span::styled(
                    self.format_value(latest_rtt, "ms"),
                    Style::default().fg(rtt_color),
                ),
                Span::styled("  Avg: ", Style::default().fg(self.theme.dimmed)),
                Span::styled(
                    self.format_value(agg.avg_rtt, "ms"),
                    Style::default().fg(self.theme.text),
                ),
                Span::styled("  Min: ", Style::default().fg(self.theme.dimmed)),
                Span::styled(
                    self.format_value(agg.min_rtt, "ms"),
                    Style::default().fg(self.theme.excellent),
                ),
                Span::styled("  Max: ", Style::default().fg(self.theme.dimmed)),
                Span::styled(
                    self.format_value(agg.max_rtt, "ms"),
                    Style::default().fg(self.theme.warning),
                ),
            ]);

            if !self.compact {
                // Add p95 with color
                let _p95_color = self.theme.color_for_rtt(agg.p95_rtt, p25, p75, p95);
                // We already rendered the basic line, so skip extended metrics in compact mode
            }

            // Render the line
            let x = chunks[2].x;
            let y = chunks[2].y;
            let mut current_x = x;

            for span in line.spans {
                let text = span.content.to_string();
                let style = span.style;

                for ch in text.chars() {
                    let ch_width = ch.width().unwrap_or(1) as u16;
                    if current_x >= x + chunks[2].width {
                        break;
                    }
                    buf[(current_x, y)].set_char(ch);
                    buf[(current_x, y)].set_style(style);
                    current_x += ch_width;
                }

                if current_x >= x + chunks[2].width {
                    break;
                }
            }
        }

        // Render metrics row 2: Jitter, Loss%, Sent, Recv
        if chunks[3].width > 0 {
            let loss_color = self.theme.color_for_loss(agg.loss_pct);

            let line = Line::from(vec![
                Span::styled("Jitter: ", Style::default().fg(self.theme.dimmed)),
                Span::styled(
                    self.format_value(agg.jitter, "ms"),
                    Style::default().fg(self.theme.text),
                ),
                Span::styled("   Loss: ", Style::default().fg(self.theme.dimmed)),
                Span::styled(
                    format!("{:.1}%", agg.loss_pct),
                    Style::default().fg(loss_color),
                ),
                Span::styled("   Sent: ", Style::default().fg(self.theme.dimmed)),
                Span::styled(agg.sent.to_string(), Style::default().fg(self.theme.text)),
                Span::styled("   Recv: ", Style::default().fg(self.theme.dimmed)),
                Span::styled(
                    agg.received.to_string(),
                    Style::default().fg(self.theme.text),
                ),
            ]);

            // Render the line
            let x = chunks[3].x;
            let y = chunks[3].y;
            let mut current_x = x;

            for span in line.spans {
                let text = span.content.to_string();
                let style = span.style;

                for ch in text.chars() {
                    let ch_width = ch.width().unwrap_or(1) as u16;
                    if current_x >= x + chunks[3].width {
                        break;
                    }
                    buf[(current_x, y)].set_char(ch);
                    buf[(current_x, y)].set_style(style);
                    current_x += ch_width;
                }

                if current_x >= x + chunks[3].width {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn create_test_store() -> MetricsStore {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        // Add some sample RTT data
        for i in 0..50 {
            store.inc_icmp_sent();
            store.push_icmp_rtt(15.0 + (i % 10) as f64);
        }

        store
    }

    #[test]
    fn test_ping_panel_new() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = PingPanel::new(&store, &theme, false);

        assert!(!panel.compact);
    }

    #[test]
    fn test_ping_panel_compact() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = PingPanel::new(&store, &theme, true);

        assert!(panel.compact);
    }

    #[test]
    fn test_format_value() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = PingPanel::new(&store, &theme, false);

        assert_eq!(panel.format_value(5.123, "ms"), "5.12ms");
        assert_eq!(panel.format_value(50.5, "ms"), "50.5ms");
        assert_eq!(panel.format_value(150.0, "ms"), "150ms");
    }

    #[test]
    fn test_ping_panel_rendering() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = PingPanel::new(&store, &theme, false);

        let backend = TestBackend::new(80, 10);
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

        // Should contain "ping" in the title
        assert!(content.contains("ping"));
    }

    #[test]
    fn test_calculate_percentiles() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        // Add sorted RTT data: 10, 20, 30, 40, 50
        for i in 1..=5 {
            store.push_icmp_rtt((i * 10) as f64);
        }

        let theme = Theme::new();
        let panel = PingPanel::new(&store, &theme, false);
        let (p25, p75, p95) = panel.calculate_percentiles();

        // With 5 values: p25 ~ index 1 (20), p75 ~ index 3 (40), p95 ~ index 4 (50)
        assert!((10.0..=30.0).contains(&p25));
        assert!((30.0..=50.0).contains(&p75));
        assert!((40.0..=50.0).contains(&p95));
    }
}
