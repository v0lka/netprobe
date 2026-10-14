//! TUI logs panel widget
//!
//! Displays tracing/log messages from the application.
//! Icons: ✕ error, ⚠ warn, ℹ info, ○ debug, · trace
//! Color by severity

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

/// Logs panel widget
#[derive(Debug)]
pub struct LogsPanel<'a> {
    store: &'a MetricsStore,
    theme: &'a Theme,
    scroll_offset: usize,
    auto_scroll: bool,
    is_focused: bool,
}

impl<'a> LogsPanel<'a> {
    /// Create a new logs panel with scroll offset and focus state
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

    /// Get icon for log level
    fn log_icon(&self, event_type: &str) -> &'static str {
        match event_type {
            "log_error" => "✕",
            "log_warn" => "⚠",
            "log_info" => "ℹ",
            "log_debug" => "○",
            "log_trace" => "·",
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

    /// Format timestamp as HH:MM:SS in the viewer's local timezone (the
    /// header clock is local too, so both agree on screen; the on-disk `ts`
    /// stays UTC).
    fn format_time(&self, timestamp: &chrono::DateTime<chrono::Utc>) -> String {
        timestamp
            .with_timezone(&chrono::Local)
            .format("%H:%M:%S")
            .to_string()
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
        let ellipsis_width = 1u16; // Unicode ellipsis is width 1

        // The ellipsis is only drawn when content is actually dropped: a
        // line whose total rendered width fits is written out in full
        let total_width: u16 = parts
            .iter()
            .map(|(text, _)| {
                text.chars()
                    .map(|ch| ch.width().unwrap_or(1) as u16)
                    .sum::<u16>()
            })
            .sum();
        let is_truncated = total_width > max_width;

        for (text, style) in parts {
            for ch in text.chars() {
                let ch_width = ch.width().unwrap_or(1) as u16;

                // Check if we need to add ellipsis (leave space for it)
                if is_truncated && current_x + ch_width > end_x.saturating_sub(ellipsis_width) {
                    // Add ellipsis if there's space
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

impl<'a> Widget for LogsPanel<'a> {
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
            .title(" logs ")
            .title_style(Style::default().fg(self.theme.title))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color));

        let inner = block.inner(area);
        block.render(area, buf);

        if inner.width < 10 || inner.height < 1 {
            return;
        }

        // Get logs
        let logs = self.store.logs();

        // Handle no logs
        if logs.is_empty() {
            let text = "no logs yet...";
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

        // Calculate visible logs based on scroll offset
        let visible_lines = inner.height as usize;
        let log_count = logs.len();
        let needs_scrollbar = log_count > visible_lines;

        // Reserve the scrollbar column so the track never overwrites the
        // last character of a rendered line.
        let content_width = inner.width.saturating_sub(u16::from(needs_scrollbar));

        // Auto-scroll to bottom if enabled
        let scroll_offset = if self.auto_scroll {
            log_count.saturating_sub(visible_lines)
        } else {
            let max_scroll = log_count.saturating_sub(visible_lines);
            self.scroll_offset.min(max_scroll)
        };

        let visible_logs: Vec<_> = logs
            .iter()
            .skip(scroll_offset)
            .take(visible_lines)
            .collect();

        // Render each log entry
        for (line_idx, log) in visible_logs.iter().enumerate() {
            let y = inner.y + line_idx as u16;
            if y >= inner.y + inner.height {
                break;
            }

            // Build parts for rendering
            let time_str = format!("{}  ", self.format_time(&log.timestamp));
            let icon = self.log_icon(&log.event_type);
            let icon_color = self.severity_color(&log.severity);

            let time_style = Style::default().fg(self.theme.dimmed);
            let icon_style = Style::default().fg(icon_color);
            let msg_style = Style::default().fg(self.theme.text);

            let parts: Vec<(&str, Style)> = vec![
                (&time_str, time_style),
                (icon, icon_style),
                ("  ", Style::default()),
                (&log.message, msg_style),
            ];

            self.render_line_truncated(buf, inner.x, y, content_width, &parts);
        }

        // Render scrollbar if content overflows
        if needs_scrollbar {
            let scrollbar = Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some("│"))
                .thumb_symbol("█")
                .style(Style::default().fg(self.theme.dimmed));

            let mut scrollbar_state = ScrollbarState::new(log_count)
                .position(scroll_offset)
                .viewport_content_length(visible_lines);

            // Render the scrollbar into its reserved rightmost column
            let scrollbar_area = Rect::new(
                inner.x + inner.width.saturating_sub(1),
                inner.y,
                1,
                inner.height,
            );
            scrollbar.render(scrollbar_area, buf, &mut scrollbar_state);
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

        // Add some sample log entries (the TUI tracing path)
        store.push_log_event(
            tracing::Level::ERROR,
            "netprobe::probe",
            "TCP connect refused".to_string(),
        );
        store.push_log_event(
            tracing::Level::WARN,
            "netprobe::probe::icmp",
            "ICMP sequence gap".to_string(),
        );
        store.push_log_event(
            tracing::Level::INFO,
            "netprobe::app",
            "Session started".to_string(),
        );

        store
    }

    #[test]
    fn test_logs_panel_with_scroll_and_focus() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = LogsPanel::with_scroll_and_focus(&store, &theme, 2, false, true);

        assert_eq!(panel.scroll_offset, 2);
        assert!(!panel.auto_scroll);
        assert!(panel.is_focused);
    }

    #[test]
    fn test_logs_panel_rendering() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = LogsPanel::with_scroll_and_focus(&store, &theme, 0, true, false);

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

        // Should contain "logs" in the title and a rendered message
        assert!(content.contains("logs"));
        assert!(content.contains("Session started"));
    }

    #[test]
    fn test_logs_panel_empty_state() {
        let store = MetricsStore::new(100, "1.1.1.1".to_string());
        let theme = Theme::new();
        let panel = LogsPanel::with_scroll_and_focus(&store, &theme, 0, true, false);

        let backend = TestBackend::new(80, 10);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                let area = f.area();
                f.render_widget(panel, area);
            })
            .unwrap();

        let buffer = terminal.backend().buffer().clone();
        let content: String = buffer.content.iter().map(|c| c.symbol()).collect();

        assert!(content.contains("no logs yet"));
    }

    #[test]
    fn test_log_icons() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = LogsPanel::with_scroll_and_focus(&store, &theme, 0, true, false);

        assert_eq!(panel.log_icon("log_error"), "✕");
        assert_eq!(panel.log_icon("log_warn"), "⚠");
        assert_eq!(panel.log_icon("log_info"), "ℹ");
        assert_eq!(panel.log_icon("log_debug"), "○");
        assert_eq!(panel.log_icon("log_trace"), "·");
        assert_eq!(panel.log_icon("unknown"), "•");
    }

    #[test]
    fn test_severity_colors() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = LogsPanel::with_scroll_and_focus(&store, &theme, 0, true, false);

        assert_eq!(panel.severity_color(&Severity::Info), theme.info);
        assert_eq!(panel.severity_color(&Severity::Warning), theme.warning);
        assert_eq!(panel.severity_color(&Severity::Critical), theme.critical);
    }

    #[test]
    fn test_format_time() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = LogsPanel::with_scroll_and_focus(&store, &theme, 0, true, false);

        let timestamp = chrono::Utc::now();
        let formatted = panel.format_time(&timestamp);

        // Should be in HH:MM:SS format
        assert_eq!(formatted.len(), 8);
        assert!(formatted.contains(':'));
    }
}
