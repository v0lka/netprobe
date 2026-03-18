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
        let ellipsis_width = 1u16; // Unicode ellipsis is width 1

        for (text, style) in parts {
            for ch in text.chars() {
                let ch_width = ch.width().unwrap_or(1) as u16;

                // Check if we need to add ellipsis (leave space for it)
                if current_x + ch_width > end_x.saturating_sub(ellipsis_width) {
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

            self.render_line_truncated(buf, inner.x, y, inner.width, &parts);
        }

        // Render scrollbar if content overflows
        if log_count > visible_lines {
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

            scrollbar.render(inner, buf, &mut scrollbar_state);
        }
    }
}
