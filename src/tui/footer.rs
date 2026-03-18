//! TUI footer widget
//!
//! Displays hotkeys: q:quit  t:force traceroute  r:reset stats  ?:help

use crate::tui::theme::Theme;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Widget,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Footer widget displaying hotkeys
#[derive(Debug)]
pub struct FooterWidget<'a> {
    theme: &'a Theme,
}

impl<'a> FooterWidget<'a> {
    /// Create a new footer widget
    pub fn new(theme: &'a Theme) -> Self {
        Self { theme }
    }

    /// Format the footer line
    fn format_footer(&self) -> Line<'a> {
        Line::from(vec![
            Span::styled("q", Style::default().fg(self.theme.title)),
            Span::styled(":quit  ", Style::default().fg(self.theme.dimmed)),
            Span::styled("t", Style::default().fg(self.theme.title)),
            Span::styled(":traceroute  ", Style::default().fg(self.theme.dimmed)),
            Span::styled("n/p", Style::default().fg(self.theme.title)),
            Span::styled(":switch IP  ", Style::default().fg(self.theme.dimmed)),
            Span::styled("r", Style::default().fg(self.theme.title)),
            Span::styled(":reset  ", Style::default().fg(self.theme.dimmed)),
            Span::styled("↑↓", Style::default().fg(self.theme.title)),
            Span::styled(":scroll  ", Style::default().fg(self.theme.dimmed)),
            Span::styled("Tab", Style::default().fg(self.theme.title)),
            Span::styled(":focus  ", Style::default().fg(self.theme.dimmed)),
            Span::styled("?", Style::default().fg(self.theme.title)),
            Span::styled(":help", Style::default().fg(self.theme.dimmed)),
        ])
    }
}

impl<'a> Widget for FooterWidget<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.height == 0 || area.width == 0 {
            return;
        }

        let line = self.format_footer();

        // Center the footer - calculate display width properly
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        let text_width = text.width() as u16;
        let start_x = if text_width < area.width {
            area.x + (area.width - text_width) / 2
        } else {
            area.x
        };

        let y = area.y;
        let mut current_x = start_x;

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

    #[test]
    fn test_footer_widget_new() {
        let theme = Theme::new();
        let footer = FooterWidget::new(&theme);

        // Just verify it doesn't panic
        let _line = footer.format_footer();
    }

    #[test]
    fn test_footer_rendering() {
        let theme = Theme::new();
        let footer = FooterWidget::new(&theme);

        let backend = TestBackend::new(80, 1);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                let area = f.area();
                f.render_widget(footer, area);
            })
            .unwrap();

        // Verify something was rendered
        let buffer = terminal.backend().buffer().clone();
        let content: String = buffer.content.iter().map(|c| c.symbol()).collect();

        assert!(content.contains("q"));
        assert!(content.contains("quit"));
        assert!(content.contains("t"));
        assert!(content.contains("traceroute"));
        assert!(content.contains("n/p"));
        assert!(content.contains("switch IP"));
        assert!(content.contains("r"));
        assert!(content.contains("reset"));
        assert!(content.contains("?"));
        assert!(content.contains("help"));
    }

    #[test]
    fn test_footer_empty_area() {
        let theme = Theme::new();
        let footer = FooterWidget::new(&theme);

        let backend = TestBackend::new(0, 0);
        let mut terminal = Terminal::new(backend).unwrap();

        // Should not panic with empty area
        terminal
            .draw(|f| {
                let area = f.area();
                f.render_widget(footer, area);
            })
            .unwrap();
    }
}
