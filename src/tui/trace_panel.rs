//! TUI traceroute panel widget
//!
//! Displays:
//! - Hop list: number, IP (or * * *), RTT, horizontal bar proportional to RTT
//! - Bar colors based on absolute RTT thresholds
//! - Scroll when >10 hops
//! - "traceroute unavailable: insufficient privileges" when disabled
//! - Error display when traceroute fails

use crate::store::{HopData, MetricsStore};
use crate::tui::sparkline::gradient_for_rtt;
use crate::tui::theme::Theme;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Style,
    text::Span,
    widgets::{
        Block, BorderType, Borders, Scrollbar, ScrollbarOrientation, ScrollbarState,
        StatefulWidget, Widget,
    },
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Traceroute panel widget
#[derive(Debug)]
pub struct TracePanel<'a> {
    store: &'a MetricsStore,
    theme: &'a Theme,
    scroll_offset: usize,
    is_focused: bool,
}

impl<'a> TracePanel<'a> {
    /// Create a new traceroute panel
    #[allow(dead_code)]
    pub fn new(store: &'a MetricsStore, theme: &'a Theme) -> Self {
        Self {
            store,
            theme,
            scroll_offset: 0,
            is_focused: false,
        }
    }

    /// Create a new traceroute panel with scroll offset and focus state
    pub fn with_scroll_and_focus(
        store: &'a MetricsStore,
        theme: &'a Theme,
        scroll_offset: usize,
        is_focused: bool,
    ) -> Self {
        Self {
            store,
            theme,
            scroll_offset,
            is_focused,
        }
    }

    /// Get the maximum RTT for scaling bar width
    fn max_rtt(&self, hops: &[HopData]) -> f64 {
        hops.iter()
            .filter_map(|h| h.rtt_ms)
            .fold(1.0, |max, rtt| if rtt > max { rtt } else { max })
    }
}

impl<'a> Widget for TracePanel<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 3 {
            return;
        }

        // Check if traceroute is available
        let traceroute_available = self.store.traceroute_available();

        // Get latest traceroute data
        let latest = self.store.latest_traceroute();
        let hops = latest
            .data
            .as_ref()
            .map(|d| d.hops.as_slice())
            .unwrap_or(&[]);

        // Create the block with rounded borders
        let title = if traceroute_available && !hops.is_empty() {
            format!(" traceroute ── hops: {} ", hops.len())
        } else {
            " traceroute ".to_string()
        };

        let border_color = if self.is_focused {
            self.theme.focused_border
        } else {
            self.theme.border
        };

        let block = Block::default()
            .title(title)
            .title_style(Style::default().fg(self.theme.title))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color));

        let inner = block.inner(area);
        block.render(area, buf);

        if inner.width < 10 || inner.height < 1 {
            return;
        }

        // Handle traceroute unavailable
        if !traceroute_available {
            // Show informative message with platform-specific hint
            let line1 = "traceroute unavailable: insufficient privileges";
            #[cfg(target_os = "linux")]
            let line2 = "hint: sudo setcap cap_net_raw+ep ./netprobe";
            #[cfg(target_os = "macos")]
            let line2 = "hint: run with sudo";
            #[cfg(target_os = "windows")]
            let line2 = "hint: run as Administrator";
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            let line2 = "hint: run with elevated privileges";

            let line1_width = line1.width() as u16;
            let line2_width = line2.width() as u16;

            // Center vertically (2 lines)
            let y1 = inner.y + inner.height / 2;
            let y2 = y1.saturating_add(1).min(inner.y + inner.height - 1);

            // Render line 1 (warning)
            let x1 = inner.x + (inner.width.saturating_sub(line1_width)) / 2;
            let mut current_x = x1;
            for ch in line1.chars() {
                let ch_width = ch.width().unwrap_or(1) as u16;
                if current_x >= inner.x + inner.width {
                    break;
                }
                buf[(current_x, y1)].set_char(ch);
                buf[(current_x, y1)].set_style(Style::default().fg(self.theme.warning));
                current_x += ch_width;
            }

            // Render line 2 (hint) if there's space
            if y2 > y1 && y2 < inner.y + inner.height {
                let x2 = inner.x + (inner.width.saturating_sub(line2_width)) / 2;
                let mut current_x = x2;
                for ch in line2.chars() {
                    let ch_width = ch.width().unwrap_or(1) as u16;
                    if current_x >= inner.x + inner.width {
                        break;
                    }
                    buf[(current_x, y2)].set_char(ch);
                    buf[(current_x, y2)].set_style(Style::default().fg(self.theme.dimmed));
                    current_x += ch_width;
                }
            }
            return;
        }

        // Handle error
        if let Some(ref error) = latest.error {
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

        // Handle no data yet
        if hops.is_empty() {
            let text = "waiting for traceroute...";
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

        // Calculate visible hops based on scroll offset
        let visible_lines = inner.height as usize;
        let needs_scrollbar = hops.len() > visible_lines;
        let max_scroll = hops.len().saturating_sub(visible_lines);
        let scroll_offset = self.scroll_offset.min(max_scroll);

        let visible_hops = &hops[scroll_offset..(scroll_offset + visible_lines).min(hops.len())];
        let max_rtt = self.max_rtt(hops);

        // Pre-calculate scrollbar width for bars
        let scrollbar_width = if needs_scrollbar { 1 } else { 0 };

        // Render each hop
        for (line_idx, hop) in visible_hops.iter().enumerate() {
            let y = inner.y + line_idx as u16;
            if y >= inner.y + inner.height {
                break;
            }

            let mut spans = vec![];

            // Hop number (right-aligned, 3 chars)
            let hop_num = format!("{:>3}  ", hop.hop);
            spans.push(Span::styled(
                hop_num,
                Style::default().fg(self.theme.dimmed),
            ));

            // IP or hostname
            let ip_display = if let Some(ref host) = hop.host {
                format!("{:<20}  ", host)
            } else if let Some(ip) = hop.ip {
                format!("{:<20}  ", ip.to_string())
            } else {
                "* * *                 ".to_string()
            };
            spans.push(Span::styled(
                ip_display,
                Style::default().fg(self.theme.text),
            ));

            // RTT
            if let Some(rtt) = hop.rtt_ms {
                let rtt_str = format!("{:>6.1}ms  ", rtt);
                spans.push(Span::styled(rtt_str, Style::default().fg(self.theme.text)));

                // Bar - reserve space for scrollbar when content overflows
                // Text before bar: hop_num (5) + ip_display (22) + rtt_str (11) = 38 chars
                let bar_max_width = inner.width.saturating_sub(38 + scrollbar_width) as usize;
                if bar_max_width > 5 {
                    let bar_width = ((rtt / max_rtt) * bar_max_width as f64) as usize;
                    let bar_width = bar_width.max(1).min(bar_max_width);
                    let bar = "█".repeat(bar_width);
                    let bar_color = gradient_for_rtt(rtt);
                    spans.push(Span::styled(bar, Style::default().fg(bar_color)));
                }
            } else {
                spans.push(Span::styled(
                    "   ---  ",
                    Style::default().fg(self.theme.dimmed),
                ));
            }

            // Render the line
            let mut current_x = inner.x;
            for span in spans {
                let text = span.content.to_string();
                let style = span.style;

                for ch in text.chars() {
                    let ch_width = ch.width().unwrap_or(1) as u16;
                    if current_x >= inner.x + inner.width {
                        break;
                    }
                    buf[(current_x, y)].set_char(ch);
                    buf[(current_x, y)].set_style(style);
                    current_x += ch_width;
                }

                if current_x >= inner.x + inner.width {
                    break;
                }
            }
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

            // Create scrollbar state with correct positioning
            // Use max_scroll + 1 as content_length for proper thumb positioning
            // Position is scroll_offset, so thumb goes from top to bottom correctly
            let scrollable_range = max_scroll + 1;
            let position = scroll_offset.min(max_scroll);
            let mut scrollbar_state = ScrollbarState::new(scrollable_range).position(position);

            // Render scrollbar in the rightmost column of inner area
            let scrollbar_area = ratatui::layout::Rect::new(
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
    use crate::store::{HopData, MetricsStore, TracerouteData};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn create_test_store() -> MetricsStore {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());

        store.set_latest_traceroute(
            Some(TracerouteData {
                hops: vec![
                    HopData {
                        hop: 1,
                        ip: Some("192.168.1.1".parse().unwrap()),
                        rtt_ms: Some(1.2),
                        host: Some("router.local".to_string()),
                    },
                    HopData {
                        hop: 2,
                        ip: Some("10.0.0.1".parse().unwrap()),
                        rtt_ms: Some(4.1),
                        host: None,
                    },
                    HopData {
                        hop: 3,
                        ip: Some("72.14.215.85".parse().unwrap()),
                        rtt_ms: Some(8.3),
                        host: None,
                    },
                    HopData {
                        hop: 4,
                        ip: None,
                        rtt_ms: None,
                        host: None,
                    },
                    HopData {
                        hop: 5,
                        ip: Some("1.1.1.1".parse().unwrap()),
                        rtt_ms: Some(14.2),
                        host: Some("one.one.one.one".to_string()),
                    },
                ],
                hop_count: 5,
            }),
            None,
        );

        store
    }

    #[test]
    fn test_trace_panel_new() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = TracePanel::new(&store, &theme);

        assert_eq!(panel.scroll_offset, 0);
    }

    #[test]
    fn test_trace_panel_with_scroll_and_focus() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = TracePanel::with_scroll_and_focus(&store, &theme, 2, true);

        assert_eq!(panel.scroll_offset, 2);
        assert!(panel.is_focused);
    }

    #[test]
    fn test_trace_panel_rendering() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = TracePanel::new(&store, &theme);

        let backend = TestBackend::new(80, 12);
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

        // Should contain hop count in title
        assert!(content.contains("hops: 5"));
    }

    #[test]
    fn test_trace_panel_unavailable() {
        let mut store = MetricsStore::new(100, "1.1.1.1".to_string());
        store.set_traceroute_available(false);

        let theme = Theme::new();
        let panel = TracePanel::new(&store, &theme);

        let backend = TestBackend::new(80, 8);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                let area = f.area();
                f.render_widget(panel, area);
            })
            .unwrap();

        // Verify unavailable message was rendered
        let buffer = terminal.backend().buffer().clone();
        let content: String = buffer.content.iter().map(|c| c.symbol()).collect();

        assert!(content.contains("traceroute unavailable"));
    }

    #[test]
    fn test_max_rtt() {
        let store = create_test_store();
        let theme = Theme::new();
        let panel = TracePanel::new(&store, &theme);

        let hops = vec![
            HopData {
                hop: 1,
                ip: Some("1.1.1.1".parse().unwrap()),
                rtt_ms: Some(10.0),
                host: None,
            },
            HopData {
                hop: 2,
                ip: Some("2.2.2.2".parse().unwrap()),
                rtt_ms: Some(50.0),
                host: None,
            },
        ];

        assert_eq!(panel.max_rtt(&hops), 50.0);
    }

    #[test]
    fn test_rtt_bar_color() {
        use crate::tui::sparkline::{gradient_for_rtt, rtt_thresholds::*};
        use ratatui::style::Color;

        // Low RTT - excellent (green)
        assert_eq!(gradient_for_rtt(EXCELLENT - 1.0), Color::Rgb(0, 255, 0));

        // Medium RTT - good (yellow-green)
        assert_eq!(gradient_for_rtt(EXCELLENT + 1.0), Color::Rgb(170, 255, 0));

        // High RTT - warning (orange)
        assert_eq!(gradient_for_rtt(GOOD + 1.0), Color::Rgb(255, 170, 0));

        // Very high RTT - critical (red)
        assert_eq!(gradient_for_rtt(WARNING + 1.0), Color::Rgb(255, 0, 0));
    }
}
