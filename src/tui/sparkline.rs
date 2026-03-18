//! Custom braille sparkline widget
//!
//! Uses Unicode braille characters (U+2800-U+28FF) to render high-resolution sparklines.
//! Each braille character represents a 2x4 dot matrix, allowing:
//! - 2 data points per character horizontally
//! - 4 vertical levels per row (8 levels with 2 rows)
//!
//! This provides much higher resolution than standard block characters.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

/// RTT threshold constants (in milliseconds)
pub mod rtt_thresholds {
    /// RTT below this is excellent (green)
    pub const EXCELLENT: f64 = 50.0;
    /// RTT below this is good (yellow-green)
    pub const GOOD: f64 = 100.0;
    /// RTT below this is warning (orange)
    pub const WARNING: f64 = 400.0;
    // RTT >= WARNING is critical (red)
}

/// Braille dot patterns for each position in the 2x4 matrix
///
/// The braille pattern uses dots numbered:
///   1 4
///   2 5
///   3 6
///   7 8
const BRAILLE_PATTERNS: [[u8; 4]; 2] = [
    [0x01, 0x02, 0x04, 0x40], // Left column: dots 1, 2, 3, 7
    [0x08, 0x10, 0x20, 0x80], // Right column: dots 4, 5, 6, 8
];

/// Base Unicode codepoint for braille patterns
const BRAILLE_BASE: u32 = 0x2800;

/// Custom braille sparkline widget
pub struct BrailleSparkline<'a> {
    /// Data to display
    data: &'a [f64],
    /// Minimum value for scaling
    min: f64,
    /// Maximum value for scaling
    max: f64,
    /// Height in terminal rows (default: 2)
    height: u16,
    /// Style for the sparkline
    style: Style,
    /// Optional color function that takes the raw data value and returns a color
    color_fn: Option<Box<dyn Fn(f64) -> Color + 'a>>,
}

impl<'a> std::fmt::Debug for BrailleSparkline<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrailleSparkline")
            .field("data_len", &self.data.len())
            .field("min", &self.min)
            .field("max", &self.max)
            .field("height", &self.height)
            .field("style", &self.style)
            .field("has_color_fn", &self.color_fn.is_some())
            .finish()
    }
}

impl<'a> Clone for BrailleSparkline<'a> {
    fn clone(&self) -> Self {
        Self {
            data: self.data,
            min: self.min,
            max: self.max,
            height: self.height,
            style: self.style,
            color_fn: None, // Cannot clone the closure, so we lose the color function on clone
        }
    }
}

impl<'a> BrailleSparkline<'a> {
    /// Create a new braille sparkline
    pub fn new(data: &'a [f64]) -> Self {
        let (min, max) = Self::calculate_bounds(data);
        Self {
            data,
            min,
            max,
            height: 2,
            style: Style::default(),
            color_fn: None,
        }
    }

    /// Set the height in terminal rows
    pub fn height(mut self, height: u16) -> Self {
        self.height = height;
        self
    }

    /// Set the style
    #[allow(dead_code)]
    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// Set a custom color function that receives raw data values
    pub fn color_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(f64) -> Color + 'a,
    {
        self.color_fn = Some(Box::new(f));
        self
    }

    /// Set explicit min/max bounds
    #[allow(dead_code)]
    pub fn bounds(mut self, min: f64, max: f64) -> Self {
        self.min = min;
        self.max = max;
        self
    }

    /// Calculate min/max bounds from data
    fn calculate_bounds(data: &[f64]) -> (f64, f64) {
        if data.is_empty() {
            return (0.0, 1.0);
        }
        let mut min = data[0];
        let mut max = data[0];
        for &v in data.iter().skip(1) {
            if v < min {
                min = v;
            }
            if v > max {
                max = v;
            }
        }
        // Ensure we have some range
        if min == max {
            max = min + 1.0;
        }
        (min, max)
    }

    /// Normalize a value to 0.0-1.0 range
    fn normalize(&self, value: f64) -> f64 {
        if self.max == self.min {
            return 0.5;
        }
        ((value - self.min) / (self.max - self.min)).clamp(0.0, 1.0)
    }

    /// Get color for a data value
    fn get_color(&self, value: f64) -> Color {
        if let Some(ref color_fn) = self.color_fn {
            color_fn(value)
        } else {
            self.style.fg.unwrap_or(Color::White)
        }
    }

    /// Calculate the braille pattern for two data points at a specific row
    ///
    /// Each row handles 4 vertical levels. With 2 rows, we get 8 levels total.
    fn calculate_braille_for_row(left_val: f64, right_val: f64, row: u16, height: u16) -> char {
        let levels_per_row = 4u16;
        let total_levels = levels_per_row * height;

        // Scale values to total levels
        let left_level = (left_val * total_levels as f64).min(total_levels as f64 - 1.0) as u16;
        let right_level = (right_val * total_levels as f64).min(total_levels as f64 - 1.0) as u16;

        // Determine which dots to set for this row
        let row_start = row * levels_per_row;
        let _row_end = row_start + levels_per_row;

        let mut pattern: u8 = 0;

        // Left value dots
        for i in 0..levels_per_row {
            let level = row_start + i;
            if left_level >= level {
                pattern |= BRAILLE_PATTERNS[0][i as usize];
            }
        }

        // Right value dots
        for i in 0..levels_per_row {
            let level = row_start + i;
            if right_level >= level {
                pattern |= BRAILLE_PATTERNS[1][i as usize];
            }
        }

        char::from_u32(BRAILLE_BASE + pattern as u32).unwrap_or(' ')
    }
}

impl<'a> Widget for BrailleSparkline<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 || self.data.is_empty() {
            return;
        }

        let width = area.width as usize;
        let height = self.height.min(area.height);

        // Each character displays 2 data points, so we need 2*width data points
        let data_points_needed = width * 2;

        // Sample or interpolate data to fit the width
        let sampled_data: Vec<f64> = if self.data.len() >= data_points_needed {
            // Take the last data_points_needed values
            self.data[self.data.len() - data_points_needed..].to_vec()
        } else {
            // Pad with zeros at the beginning if we don't have enough data
            let padding = data_points_needed - self.data.len();
            let mut padded = vec![self.min; padding];
            padded.extend_from_slice(self.data);
            padded
        };

        // Render each row from top to bottom
        for row in 0..height {
            let y = area.y + row;
            if y >= area.y + area.height {
                break;
            }

            for col in 0..width {
                let x = area.x + col as u16;
                if x >= area.x + area.width {
                    break;
                }

                // Get the two data points for this column
                let data_idx = col * 2;
                if data_idx + 1 >= sampled_data.len() {
                    break;
                }

                let raw_left = sampled_data[data_idx];
                let raw_right = sampled_data[data_idx + 1];
                let left_val = self.normalize(raw_left);
                let right_val = self.normalize(raw_right);

                // Calculate braille character
                let ch = Self::calculate_braille_for_row(left_val, right_val, row, height);

                // Calculate color based on average of the raw values
                let avg_raw = (raw_left + raw_right) / 2.0;
                let color = self.get_color(avg_raw);

                buf[(x, y)].set_char(ch);
                buf[(x, y)].set_style(self.style.fg(color));
            }
        }
    }
}

/// Helper function to create a gradient color from green to red
#[allow(dead_code)]
pub fn gradient_green_to_red(normalized: f64) -> Color {
    // normalized: 0.0 = green (excellent), 1.0 = red (critical)
    let r = (normalized * 255.0) as u8;
    let g = ((1.0 - normalized) * 255.0) as u8;
    Color::Rgb(r, g, 0)
}

/// Helper function to create a color based on absolute RTT thresholds (in ms)
pub fn gradient_for_rtt(rtt_ms: f64) -> Color {
    use rtt_thresholds::*;
    if rtt_ms < EXCELLENT {
        Color::Rgb(0, 255, 0) // Excellent - bright green
    } else if rtt_ms < GOOD {
        Color::Rgb(170, 255, 0) // Good - yellow-green
    } else if rtt_ms < WARNING {
        Color::Rgb(255, 170, 0) // Warning - orange
    } else {
        Color::Rgb(255, 0, 0) // Critical - red (>= WARNING)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_braille_sparkline_new() {
        let data = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let sparkline = BrailleSparkline::new(&data);

        assert_eq!(sparkline.min, 10.0);
        assert_eq!(sparkline.max, 50.0);
        assert_eq!(sparkline.height, 2);
    }

    #[test]
    fn test_braille_sparkline_empty() {
        let data: Vec<f64> = vec![];
        let sparkline = BrailleSparkline::new(&data);

        assert_eq!(sparkline.min, 0.0);
        assert_eq!(sparkline.max, 1.0);
    }

    #[test]
    fn test_braille_sparkline_single_value() {
        let data = vec![42.0];
        let sparkline = BrailleSparkline::new(&data);

        assert_eq!(sparkline.min, 42.0);
        assert_eq!(sparkline.max, 43.0); // Single value gets +1 range
    }

    #[test]
    fn test_normalize() {
        let data = vec![0.0, 50.0, 100.0];
        let sparkline = BrailleSparkline::new(&data);

        assert_eq!(sparkline.normalize(0.0), 0.0);
        assert_eq!(sparkline.normalize(50.0), 0.5);
        assert_eq!(sparkline.normalize(100.0), 1.0);
    }

    #[test]
    fn test_calculate_braille_for_row() {
        // Test that we get valid characters
        let ch = BrailleSparkline::calculate_braille_for_row(0.5, 0.5, 0, 2);
        assert!(ch as u32 >= 0x2800 && ch as u32 <= 0x28FF);

        // Full height should give full pattern
        let ch_full = BrailleSparkline::calculate_braille_for_row(1.0, 1.0, 0, 2);
        assert!(ch_full as u32 > 0x2800);
    }

    #[test]
    fn test_gradient_green_to_red() {
        let green = gradient_green_to_red(0.0);
        assert!(matches!(green, Color::Rgb(0, 255, 0)));

        let red = gradient_green_to_red(1.0);
        assert!(matches!(red, Color::Rgb(255, 0, 0)));

        let mid = gradient_green_to_red(0.5);
        assert!(matches!(mid, Color::Rgb(127, 127, 0)));
    }

    #[test]
    fn test_gradient_for_rtt() {
        use super::rtt_thresholds::*;
        // Excellent (< EXCELLENT ms)
        assert_eq!(gradient_for_rtt(0.0), Color::Rgb(0, 255, 0));
        assert_eq!(gradient_for_rtt(EXCELLENT - 1.0), Color::Rgb(0, 255, 0));
        // Good (EXCELLENT to GOOD ms)
        assert_eq!(gradient_for_rtt(EXCELLENT), Color::Rgb(170, 255, 0));
        assert_eq!(gradient_for_rtt(GOOD - 1.0), Color::Rgb(170, 255, 0));
        // Warning (GOOD to WARNING ms)
        assert_eq!(gradient_for_rtt(GOOD), Color::Rgb(255, 170, 0));
        assert_eq!(gradient_for_rtt(WARNING - 1.0), Color::Rgb(255, 170, 0));
        // Critical (>= WARNING ms)
        assert_eq!(gradient_for_rtt(WARNING), Color::Rgb(255, 0, 0));
        assert_eq!(gradient_for_rtt(1000.0), Color::Rgb(255, 0, 0));
    }
}
