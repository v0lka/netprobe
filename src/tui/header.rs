//! TUI header widget
//!
//! Displays: netprobe ── <host> (<ip>) ── <time> ── <session_duration> ── MOS <value> [<grade>]

use crate::store::MetricsStore;
use crate::tui::theme::Theme;
use crate::util::{compute_mos, format_duration, mos_to_grade};
use chrono::{Local, Utc};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Widget,
};
use unicode_width::UnicodeWidthChar;

/// Header widget displaying session info and MOS score
#[derive(Debug)]
pub struct HeaderWidget<'a> {
    store: &'a MetricsStore,
    theme: &'a Theme,
}

impl<'a> HeaderWidget<'a> {
    /// Create a new header widget
    pub fn new(store: &'a MetricsStore, theme: &'a Theme) -> Self {
        Self { store, theme }
    }

    /// Calculate MOS score from current aggregates
    fn calculate_mos(&self) -> f64 {
        let agg = self.store.icmp_aggregates();
        compute_mos(agg.avg_rtt, agg.jitter, agg.loss_pct)
    }

    /// Format the header line
    fn format_header(&self) -> Line<'a> {
        let target = self.store.target();

        // Current time
        let time_str = Local::now().format("%H:%M:%S").to_string();

        // Session duration
        let session_start = self.store.session_start();
        let duration_secs = (Utc::now() - session_start).num_seconds().max(0) as u64;
        let duration_str = format_duration(duration_secs);

        // MOS and grade
        let mos = self.calculate_mos();
        let grade = mos_to_grade(mos);
        let mos_color = self.theme.color_for_grade(grade);

        // Build the line
        let mut spans = vec![
            Span::styled(
                "NETPROBE ",
                Style::default()
                    .fg(self.theme.title)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("── ", Style::default().fg(self.theme.dimmed)),
            Span::styled(target.to_string(), Style::default().fg(self.theme.text)),
        ];

        // Add resolved IP with index if multiple IPs available
        let ip_count = self.store.resolved_ip_count();
        if ip_count > 0 {
            let active_ip = self.store.active_ip();
            let active_index = self.store.active_ip_index();
            if let Some(ip) = active_ip {
                let ip_display = if ip_count > 1 {
                    format!(" ({} {}/{})", ip, active_index + 1, ip_count)
                } else {
                    format!(" ({})", ip)
                };
                spans.push(Span::styled(
                    ip_display,
                    Style::default().fg(self.theme.dimmed),
                ));
            }
        }

        spans.extend([
            Span::styled(" ── ", Style::default().fg(self.theme.dimmed)),
            Span::styled(time_str, Style::default().fg(self.theme.text)),
            Span::styled(" ── ", Style::default().fg(self.theme.dimmed)),
            Span::styled(duration_str, Style::default().fg(self.theme.text)),
            Span::styled(" ── MOS ", Style::default().fg(self.theme.dimmed)),
            Span::styled(format!("{:.1}", mos), Style::default().fg(mos_color)),
            Span::styled(" [", Style::default().fg(self.theme.dimmed)),
            Span::styled(grade.to_string(), Style::default().fg(mos_color)),
            Span::styled("]", Style::default().fg(self.theme.dimmed)),
        ]);

        Line::from(spans)
    }
}

impl<'a> Widget for HeaderWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 || area.width == 0 {
            return;
        }

        let line = self.format_header();

        // Render the line centered or left-aligned
        let x = area.x;
        let y = area.y;

        // Render each span
        let mut current_x = x;
        for span in line.spans {
            let text = span.content.to_string();
            let style = span.style;

            for ch in text.chars() {
                let ch_width = ch.width().unwrap_or(1) as u16;
                if current_x >= area.x + area.width {
                    break;
                }
                buf[(current_x, y)].set_char(ch);
                buf[(current_x, y)].set_style(style);
                current_x += ch_width;
            }

            if current_x >= area.x + area.width {
                break;
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
        store.set_resolved_target(Some("one.one.one.one".to_string()));
        store.set_resolved_ip(Some("1.1.1.1".to_string()));

        // Add some sample data
        for _ in 0..10 {
            store.inc_icmp_sent();
            store.push_icmp_rtt(20.0);
        }

        store
    }

    #[test]
    fn test_header_widget_new() {
        let store = create_test_store();
        let theme = Theme::new();
        let widget = HeaderWidget::new(&store, &theme);

        // Just verify it doesn't panic
        let _mos = widget.calculate_mos();
    }

    #[test]
    fn test_header_rendering() {
        let store = create_test_store();
        let theme = Theme::new();
        let widget = HeaderWidget::new(&store, &theme);

        let backend = TestBackend::new(100, 1);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                let area = f.area();
                f.render_widget(widget, area);
            })
            .unwrap();

        // Verify something was rendered
        let buffer = terminal.backend().buffer().clone();
        let content: String = buffer.content.iter().map(|c| c.symbol()).collect();

        assert!(content.contains("NETPROBE"));
        assert!(content.contains("1.1.1.1"));
        assert!(content.contains("MOS"));
    }

    #[test]
    fn test_header_with_resolved_ip() {
        let store = create_test_store();
        let theme = Theme::new();
        let widget = HeaderWidget::new(&store, &theme);

        let backend = TestBackend::new(120, 1);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                let area = f.area();
                f.render_widget(widget, area);
            })
            .unwrap();

        let buffer = terminal.backend().buffer().clone();
        let content: String = buffer.content.iter().map(|c| c.symbol()).collect();

        // The header now shows resolved IP, not hostname
        assert!(content.contains("1.1.1.1"));
    }
}
