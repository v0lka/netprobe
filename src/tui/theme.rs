//! TUI color theme - btop-inspired palette

use ratatui::style::Color;

/// Color theme for the TUI dashboard
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// Border color (muted gray)
    pub border: Color,
    /// Title color on borders (cyan/blue)
    pub title: Color,
    /// Text color (white)
    pub text: Color,
    /// Dimmed/inactive text (dark gray)
    pub dimmed: Color,
    /// Excellent quality (bright green)
    pub excellent: Color,
    /// Good quality (yellow-green)
    pub good: Color,
    /// Warning quality (orange)
    pub warning: Color,
    /// Critical quality (red)
    pub critical: Color,
    /// Info severity (blue)
    pub info: Color,
    /// Background (transparent/default)
    #[allow(dead_code)]
    pub background: Color,
    /// Focused panel border color (bright cyan)
    pub focused_border: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self::new()
    }
}

impl Theme {
    /// Create a new theme with btop-inspired colors
    pub fn new() -> Self {
        Self {
            border: Color::Rgb(100, 100, 100),
            title: Color::Rgb(0, 170, 255),
            text: Color::White,
            dimmed: Color::DarkGray,
            excellent: Color::Rgb(0, 255, 0),
            good: Color::Rgb(170, 255, 0),
            warning: Color::Rgb(255, 170, 0),
            critical: Color::Rgb(255, 0, 0),
            info: Color::Rgb(0, 170, 255),
            background: Color::Reset,
            focused_border: Color::Rgb(0, 255, 255),
        }
    }

    /// Get color for RTT value based on percentiles
    /// - <= p25: excellent (green)
    /// - <= p75: good (yellow-green)
    /// - <= p95: warning (orange)
    /// - > p95: critical (red)
    pub fn color_for_rtt(&self, rtt: f64, p25: f64, p75: f64, p95: f64) -> Color {
        if rtt <= p25 {
            self.excellent
        } else if rtt <= p75 {
            self.good
        } else if rtt <= p95 {
            self.warning
        } else {
            self.critical
        }
    }

    /// Get color for severity level
    #[allow(dead_code)]
    pub fn color_for_severity(&self, severity: &str) -> Color {
        match severity.to_lowercase().as_str() {
            "info" => self.info,
            "warning" => self.warning,
            "critical" => self.critical,
            _ => self.text,
        }
    }

    /// Get color for MOS grade
    pub fn color_for_grade(&self, grade: char) -> Color {
        match grade {
            'A' => self.excellent,
            'B' => self.good,
            'C' => self.warning,
            'D' | 'F' => self.critical,
            _ => self.text,
        }
    }

    /// Get color for packet loss percentage
    pub fn color_for_loss(&self, loss_pct: f64) -> Color {
        if loss_pct == 0.0 {
            self.excellent
        } else if loss_pct < 1.0 {
            self.good
        } else if loss_pct < 5.0 {
            self.warning
        } else {
            self.critical
        }
    }

    /// Get color for certificate days remaining
    pub fn color_for_cert_days(&self, days: i64) -> Color {
        if days > 60 {
            self.excellent
        } else if days > 30 {
            self.good
        } else if days > 7 {
            self.warning
        } else {
            self.critical
        }
    }
}

/// Global theme instance
#[allow(dead_code)]
pub static THEME: Theme = Theme {
    border: Color::Rgb(100, 100, 100),
    title: Color::Rgb(0, 170, 255),
    text: Color::White,
    dimmed: Color::DarkGray,
    excellent: Color::Rgb(0, 255, 0),
    good: Color::Rgb(170, 255, 0),
    warning: Color::Rgb(255, 170, 0),
    critical: Color::Rgb(255, 0, 0),
    info: Color::Rgb(0, 170, 255),
    background: Color::Reset,
    focused_border: Color::Rgb(0, 255, 255),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_default() {
        let theme = Theme::new();
        assert_eq!(theme.border, Color::Rgb(100, 100, 100));
        assert_eq!(theme.title, Color::Rgb(0, 170, 255));
        assert_eq!(theme.excellent, Color::Rgb(0, 255, 0));
    }

    #[test]
    fn test_color_for_rtt() {
        let theme = Theme::new();

        // Low RTT - excellent
        assert_eq!(
            theme.color_for_rtt(10.0, 20.0, 50.0, 100.0),
            theme.excellent
        );

        // Medium RTT - good
        assert_eq!(theme.color_for_rtt(30.0, 20.0, 50.0, 100.0), theme.good);

        // High RTT - warning
        assert_eq!(theme.color_for_rtt(75.0, 20.0, 50.0, 100.0), theme.warning);

        // Very high RTT - critical
        assert_eq!(
            theme.color_for_rtt(150.0, 20.0, 50.0, 100.0),
            theme.critical
        );
    }

    #[test]
    fn test_color_for_severity() {
        let theme = Theme::new();

        assert_eq!(theme.color_for_severity("info"), theme.info);
        assert_eq!(theme.color_for_severity("INFO"), theme.info);
        assert_eq!(theme.color_for_severity("warning"), theme.warning);
        assert_eq!(theme.color_for_severity("critical"), theme.critical);
        assert_eq!(theme.color_for_severity("unknown"), theme.text);
    }

    #[test]
    fn test_color_for_grade() {
        let theme = Theme::new();

        assert_eq!(theme.color_for_grade('A'), theme.excellent);
        assert_eq!(theme.color_for_grade('B'), theme.good);
        assert_eq!(theme.color_for_grade('C'), theme.warning);
        assert_eq!(theme.color_for_grade('D'), theme.critical);
        assert_eq!(theme.color_for_grade('F'), theme.critical);
    }

    #[test]
    fn test_color_for_loss() {
        let theme = Theme::new();

        assert_eq!(theme.color_for_loss(0.0), theme.excellent);
        assert_eq!(theme.color_for_loss(0.5), theme.good);
        assert_eq!(theme.color_for_loss(2.0), theme.warning);
        assert_eq!(theme.color_for_loss(10.0), theme.critical);
    }

    #[test]
    fn test_color_for_cert_days() {
        let theme = Theme::new();

        assert_eq!(theme.color_for_cert_days(90), theme.excellent);
        assert_eq!(theme.color_for_cert_days(45), theme.good);
        assert_eq!(theme.color_for_cert_days(15), theme.warning);
        assert_eq!(theme.color_for_cert_days(5), theme.critical);
    }
}
