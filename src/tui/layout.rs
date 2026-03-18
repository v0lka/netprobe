//! TUI layout management
//!
//! Defines the vertical stack layout with adaptive proportions based on terminal size.
//! Proportions (from spec):
//! - Header: 1 row (fixed)
//! - Ping panel: ~30%
//! - DNS panel: ~12%
//! - TCP/TLS/HTTP panel: ~15%
//! - Traceroute panel: ~20%
//! - Events panel: ~18%
//! - Footer: 1 row (fixed)
//!
//! Adaptive behavior:
//! - Height < 24: hide traceroute and events panels
//! - Width < 80: use shortened format for values

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Layout configuration for the dashboard
#[derive(Debug, Clone, Copy)]
pub struct DashboardLayout {
    /// Whether to show traceroute panel
    pub show_traceroute: bool,
    /// Whether to show events panel
    pub show_events: bool,
    /// Whether to use compact mode (width < 80)
    pub compact: bool,
    /// Available area
    pub area: Rect,
}

impl DashboardLayout {
    /// Minimum height to show all panels
    pub const MIN_HEIGHT_FULL: u16 = 24;
    /// Minimum width for full format
    pub const MIN_WIDTH_FULL: u16 = 80;

    /// Create a new layout configuration based on terminal size
    pub fn new(area: Rect) -> Self {
        Self {
            show_traceroute: area.height >= Self::MIN_HEIGHT_FULL,
            show_events: area.height >= Self::MIN_HEIGHT_FULL,
            compact: area.width < Self::MIN_WIDTH_FULL,
            area,
        }
    }

    /// Calculate the layout constraints
    ///
    /// Returns a vector of constraints for the vertical layout
    fn constraints(&self) -> Vec<Constraint> {
        let _available_height = self.area.height.saturating_sub(2); // Subtract header and footer

        if self.show_traceroute && self.show_events {
            // Full layout with all panels
            // Proportions: ping 30%, dns 12%, tcp 15%, trace 20%, events 18% = 95%
            // Remaining 5% distributed
            vec![
                Constraint::Length(1),      // Header
                Constraint::Percentage(32), // Ping panel
                Constraint::Percentage(13), // DNS panel
                Constraint::Percentage(16), // TCP/TLS/HTTP panel
                Constraint::Percentage(21), // Traceroute panel
                Constraint::Percentage(18), // Events panel
                Constraint::Length(1),      // Footer
            ]
        } else {
            // Compact layout without traceroute and events
            // Distribute space among remaining panels
            vec![
                Constraint::Length(1),      // Header
                Constraint::Percentage(45), // Ping panel (larger)
                Constraint::Percentage(20), // DNS panel
                Constraint::Percentage(25), // TCP/TLS/HTTP panel
                Constraint::Length(1),      // Footer
            ]
        }
    }

    /// Build the layout and return the areas for each panel
    ///
    /// Returns: (header, ping, dns, tcp_tls, traceroute, events, footer)
    /// Note: traceroute and events will be zero-sized if not shown
    pub fn build(&self) -> (Rect, Rect, Rect, Rect, Rect, Rect, Rect) {
        let constraints = self.constraints();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(self.area);

        if self.show_traceroute && self.show_events {
            (
                chunks[0], // header
                chunks[1], // ping
                chunks[2], // dns
                chunks[3], // tcp_tls
                chunks[4], // traceroute
                chunks[5], // events
                chunks[6], // footer
            )
        } else {
            (
                chunks[0],       // header
                chunks[1],       // ping
                chunks[2],       // dns
                chunks[3],       // tcp_tls
                Rect::default(), // traceroute (hidden)
                Rect::default(), // events (hidden)
                chunks[4],       // footer
            )
        }
    }

    /// Check if we're in compact mode (narrow terminal)
    pub fn is_compact(&self) -> bool {
        self.compact
    }

    /// Check if traceroute panel is visible
    pub fn is_traceroute_visible(&self) -> bool {
        self.show_traceroute
    }

    /// Check if events panel is visible
    pub fn is_events_visible(&self) -> bool {
        self.show_events
    }
}

/// Build layout from area - convenience function
#[allow(dead_code)]
pub fn build_layout(area: Rect) -> DashboardLayout {
    DashboardLayout::new(area)
}

/// Calculate inner area for a panel (accounting for borders)
#[allow(dead_code)]
pub fn inner_area(area: Rect) -> Rect {
    if area.width >= 2 && area.height >= 2 {
        Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width - 2,
            height: area.height - 2,
        }
    } else {
        area
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_full() {
        let area = Rect::new(0, 0, 100, 30);
        let layout = DashboardLayout::new(area);

        assert!(layout.show_traceroute);
        assert!(layout.show_events);
        assert!(!layout.compact);

        let (header, ping, dns, tcp_tls, traceroute, events, footer) = layout.build();

        assert!(header.height > 0);
        assert!(ping.height > 0);
        assert!(dns.height > 0);
        assert!(tcp_tls.height > 0);
        assert!(traceroute.height > 0);
        assert!(events.height > 0);
        assert!(footer.height > 0);
    }

    #[test]
    fn test_layout_compact_height() {
        let area = Rect::new(0, 0, 100, 20);
        let layout = DashboardLayout::new(area);

        assert!(!layout.show_traceroute);
        assert!(!layout.show_events);
        assert!(!layout.compact);

        let (header, ping, dns, tcp_tls, traceroute, events, footer) = layout.build();

        assert!(header.height > 0);
        assert!(ping.height > 0);
        assert!(dns.height > 0);
        assert!(tcp_tls.height > 0);
        assert_eq!(traceroute.height, 0);
        assert_eq!(events.height, 0);
        assert!(footer.height > 0);
    }

    #[test]
    fn test_layout_compact_width() {
        let area = Rect::new(0, 0, 60, 30);
        let layout = DashboardLayout::new(area);

        assert!(layout.compact);
    }

    #[test]
    fn test_inner_area() {
        let area = Rect::new(0, 0, 10, 10);
        let inner = inner_area(area);

        assert_eq!(inner.x, 1);
        assert_eq!(inner.y, 1);
        assert_eq!(inner.width, 8);
        assert_eq!(inner.height, 8);
    }

    #[test]
    fn test_inner_area_small() {
        let area = Rect::new(0, 0, 1, 1);
        let inner = inner_area(area);

        // Should return same area if too small
        assert_eq!(inner, area);
    }

    #[test]
    fn test_build_layout() {
        let area = Rect::new(0, 0, 100, 30);
        let layout = build_layout(area);

        assert_eq!(layout.area, area);
    }
}
