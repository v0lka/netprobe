//! TUI events panel widget
//!
//! Displays network anomaly events:
//! - Icons: ▲ spike, ▼ loss, ● route, ◆ dns, ✦ cert, ✕ error, ⬥ hop_rtt_anomaly
//! - Color by severity
//! - Scroll support with auto-scroll to latest

use crate::models::Severity;
use crate::store::MetricsStore;
use crate::tui::theme::Theme;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Style,
    widgets::{
        Block, BorderType, Borders, Scrollbar, ScrollbarOrientation, ScrollbarState,
        StatefulWidget, Widget,
    },
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Events panel widget
#[derive(Debug)]
pub struct EventsPanel<'a> {
    store: &'a MetricsStore,
    theme: &'a Theme,
    scroll_offset: usize,
    auto_scroll: bool,
    is_focused: bool,
}

impl<'a> EventsPanel<'a> {
    /// Create a new events panel
    #[allow(dead_code)]
    pub fn new(store: &'a MetricsStore, theme: &'a Theme) -> Self {
        Self {
            store,
            theme,
            scroll_offset: 0,
            auto_scroll: true,
            is_focused: false,
        }
    }

    /// Create a new events panel with scroll offset and focus state
    pub fn with_scroll_and_focus(
        store: &'a MetricsStore,
        theme: &'a Theme,
        scroll_offset: usize,
        auto_scroll: bool,
        is_focused: bool,
    ) -> Self {
        Self {
            store,
            theme,
            scroll_offset,
            auto_scroll,
            is_focused,
        }
    }

    /// Get icon for event type
    fn event_icon(&self, event_type: &str) -> &'static str {
        match event_type {
            "rtt_spike" => "▲",
            "jitter_spike" => "▲",
            "loss_burst" => "▼",
            "route_change" => "●",
            "dns_change" => "◆",
            "cert_expiry_warning" => "✦",
            "http_error" => "✕",
            "tcp_refused" => "✕",
            "hop_rtt_anomaly" => "⬥",
            _ => "•",
        }
    }

    /// Get color for severity
    fn severity_color(&self, severity: &Severity) -> ratatui::style::Color {
        match severity {
            Severity::Info => self.theme.info,
            Severity::Warning => self.theme.warning,
            Severity::Critical => self.theme.critical,
        }
    }

    /// Format timestamp as HH:MM:SS
    fn format_time(&self, timestamp: &chrono::DateTime<chrono::Utc>) -> String {
        timestamp.format("%H:%M:%S").to_string()
    }

    /// Render a single line with truncation and ellipsis
    fn render_line_truncated(
        &self,
        buf: &mut Buffer,
        x: u16,
        y: u16,
        max_width: u16,
        parts: &[(&str, Style)],
    ) {
        let mut current_x = x;
        let end_x = x + max_width;
        let ellipsis_width = 1u16;

        for (text, style) in parts {
            for ch in text.chars() {
                let ch_width = ch.width().unwrap_or(1) as u16;

                if current_x + ch_width > end_x.saturating_sub(ellipsis_width) {
                    if current_x < end_x {
                        buf[(current_x, y)].set_char('…');
                        buf[(current_x, y)].set_style(*style);
                    }
                    return;
                }

                if current_x + ch_width > end_x {
                    return;
                }

                buf[(current_x, y)].set_char(ch);
                buf[(current_x, y)].set_style(*style);
                current_x += ch_width;
            }
        }
    }
}

impl<'a> Widget for EventsPanel<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 3 {
            return;
        }

        // Create the block with rounded borders
        let border_color = if self.is_focused {
            self.theme.focused_border
        } else {
            self.theme.border
        };

        let block = Block::default()
            .title(" events ")
            .title_style(Style::default().fg(self.theme.title))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color));

        let inner = block.inner(area);
        block.render(area, buf);

        if inner.width < 10 || inner.height < 1 {
            return;
        }

        // Get events
        let events = self.store.events();

        // Handle no events
        if events.is_empty() {
            let text = "waiting for events...";
            let text_width = text.width() as u16;
            let x = inner.x + (inner.width.saturating_sub(text_width)) / 2;
            let y = inner.y + inner.height / 2;

            let mut current_x = x;
            for ch in text.chars() {
                let ch_width = ch.width().unwrap_or(1) as u16;
                if current_x >= inner.x + inner.width {
                    break;
                }
                buf[(current_x, y)].set_char(ch);
                buf[(current_x, y)].set_style(Style::default().fg(self.theme.dimmed));
                current_x += ch_width;
            }
            return;
        }

        // Calculate visible events based on scroll offset
        let visible_lines = inner.height as usize;
        let event_count = events.len();

        // Auto-scroll to bottom if enabled
        let scroll_offset = if self.auto_scroll {
            event_count.saturating_sub(visible_lines)
        } else {
            let max_scroll = event_count.saturating_sub(visible_lines);
            self.scroll_offset.min(max_scroll)
        };

        let visible_events: Vec<_> = events
            .iter()
            .skip(scroll_offset)
            .take(visible_lines)
            .collect();

        // Render each event
        for (line_idx, event) in visible_events.iter().enumerate() {
            let y = inner.y + line_idx as u16;
            if y >= inner.y + inner.height {
                break;
            }

            // Build parts for rendering
            let time_str = format!("{}  ", self.format_time(&event.timestamp));
            let icon = self.event_icon(&event.event_type);
            let icon_color = self.severity_color(&event.severity);

            let time_style = Style::default().fg(self.theme.dimmed);
            let icon_style = Style::default().fg(icon_color);
            let msg_style = Style::default().fg(self.theme.text);

            let parts: Vec<(&str, Style)> = vec![
                (&time_str, time_style),
                (icon, icon_style),
                ("  ", Style::default()),
                (&event.message, msg_style),
            ];

            self.render_line_truncated(buf, inner.x, y, inner.width, &parts);
        }

        // Render scrollbar if content overflows
        if event_count > visible_lines {
            let scrollbar = Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some("│"))
                .thumb_symbol("█")
                .style(Style::default().fg(self.theme.dimmed));

            let mut scrollbar_state = ScrollbarState::new(event_count)
                .position(scroll_offset)
                .viewport_content_length(visible_lines);

            scrollbar.render(inner, buf, &mut scrollbar_state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MetricsStore;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn create_test_store() -> MetricsStore {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        // Add some sample events
        store.push_event(
            "rtt_spike".to_string(),
            Severity::Warning,
            "RTT spike: 47.1ms (3.2σ above mean)".to_string(),
        );
        store.push_event(
            "route_change".to_string(),
            Severity::Warning,
            "Route change: hop 4 changed".to_string(),
        );
        store.push_event(
            "loss_burst".to_string(),
            Severity::Critical,
            "Loss burst: 3 consecutive".to_string(),
        );
        store.push_event(
            "dns_change".to_string(),
            Severity::Info,
            "DNS: new IP 1.0.0.1".to_string(),
        );

        store
    }

    #[test]
    fn test_events_panel_new() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = EventsPanel::new(&store, &theme);

        assert_eq!(panel.scroll_offset, 0);
        assert!(panel.auto_scroll);
    }

    #[test]
    fn test_events_panel_with_scroll_and_focus() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = EventsPanel::with_scroll_and_focus(&store, &theme, 2, false, true);

        assert_eq!(panel.scroll_offset, 2);
        assert!(!panel.auto_scroll);
        assert!(panel.is_focused);
    }

    #[test]
    fn test_events_panel_rendering() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = EventsPanel::new(&store, &theme);

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

        // Should contain "events" in the title
        assert!(content.contains("events"));
    }

    #[test]
    fn test_event_icons() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = EventsPanel::new(&store, &theme);

        assert_eq!(panel.event_icon("rtt_spike"), "▲");
        assert_eq!(panel.event_icon("jitter_spike"), "▲");
        assert_eq!(panel.event_icon("loss_burst"), "▼");
        assert_eq!(panel.event_icon("route_change"), "●");
        assert_eq!(panel.event_icon("dns_change"), "◆");
        assert_eq!(panel.event_icon("cert_expiry_warning"), "✦");
        assert_eq!(panel.event_icon("http_error"), "✕");
        assert_eq!(panel.event_icon("tcp_refused"), "✕");
        assert_eq!(panel.event_icon("hop_rtt_anomaly"), "⬥");
        assert_eq!(panel.event_icon("unknown"), "•");
    }

    #[test]
    fn test_severity_colors() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = EventsPanel::new(&store, &theme);

        assert_eq!(panel.severity_color(&Severity::Info), theme.info);
        assert_eq!(panel.severity_color(&Severity::Warning), theme.warning);
        assert_eq!(panel.severity_color(&Severity::Critical), theme.critical);
    }

    #[test]
    fn test_format_time() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = EventsPanel::new(&store, &theme);

        let timestamp = chrono::Utc::now();
        let formatted = panel.format_time(&timestamp);

        // Should be in HH:MM:SS format
        assert_eq!(formatted.len(), 8);
        assert!(formatted.contains(':'));
    }
}
