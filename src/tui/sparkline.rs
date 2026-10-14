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
///
/// Each array is ordered bottom→top: index 0 is the cell's bottom dot, so a
/// larger level fills dots closer to the top (bottom-up fill, as documented
/// in `specs/domains/tui/sparkline.md`).
const BRAILLE_PATTERNS: [[u8; 4]; 2] = [
    [0x40, 0x04, 0x02, 0x01], // Left column: dots 7, 3, 2, 1 (bottom→top)
    [0x80, 0x20, 0x10, 0x08], // Right column: dots 8, 6, 5, 4 (bottom→top)
];

/// Base Unicode codepoint for braille patterns
const BRAILLE_BASE: u32 = 0x2800;

/// Custom braille sparkline widget
#[derive(Clone)]
pub struct BrailleSparkline<'a> {
    /// Data to display
    data: &'a [f64],
    /// Height in terminal rows (default: 2)
    height: u16,
    /// Style for the sparkline
    style: Style,
    /// Optional color function that takes the raw data value and returns a color
    color_fn: Option<std::sync::Arc<dyn Fn(f64) -> Color + 'a>>,
}

impl<'a> std::fmt::Debug for BrailleSparkline<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrailleSparkline")
            .field("data_len", &self.data.len())
            .field("height", &self.height)
            .field("style", &self.style)
            .field("has_color_fn", &self.color_fn.is_some())
            .finish()
    }
}

impl<'a> BrailleSparkline<'a> {
    /// Create a new braille sparkline
    pub fn new(data: &'a [f64]) -> Self {
        Self {
            data,
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

    /// Set a custom color function that receives raw data values
    pub fn color_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(f64) -> Color + 'a,
    {
        self.color_fn = Some(std::sync::Arc::new(f));
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
    fn normalize(min: f64, max: f64, value: f64) -> f64 {
        if max == min {
            return 0.5;
        }
        ((value - min) / (max - min)).clamp(0.0, 1.0)
    }

    /// Get color for a data value
    fn get_color(&self, value: f64) -> Color {
        if let Some(color_fn) = &self.color_fn {
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

        // Rows are emitted top→bottom on screen; each cell's level band is
        // indexed from the bottom so higher values fill dots closer to the
        // top (bottom-up fill).
        let row_start = (height - 1 - row) * levels_per_row;

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

        // Only the rendered tail contributes to auto-bounds: a single old
        // extreme must not pin the scale of the visible window.
        let tail: &[f64] = if self.data.len() >= data_points_needed {
            &self.data[self.data.len() - data_points_needed..]
        } else {
            self.data
        };
        let (min, max) = Self::calculate_bounds(tail);

        // Sample or interpolate data to fit the width
        let sampled_data: Vec<f64> = if tail.len() >= data_points_needed {
            tail.to_vec()
        } else {
            // Pad with `min` at the beginning so the chart grows from the right
            let padding = data_points_needed - tail.len();
            let mut padded = vec![min; padding];
            padded.extend_from_slice(tail);
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
                let left_val = Self::normalize(min, max, raw_left);
                let right_val = Self::normalize(min, max, raw_right);

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

        assert_eq!(sparkline.height, 2);
        assert_eq!(sparkline.data, &data[..]);
    }

    #[test]
    fn test_calculate_bounds() {
        let data = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        assert_eq!(BrailleSparkline::calculate_bounds(&data), (10.0, 50.0));

        // Empty data gets a default range
        assert_eq!(BrailleSparkline::calculate_bounds(&[]), (0.0, 1.0));

        // Single value gets +1 range
        assert_eq!(BrailleSparkline::calculate_bounds(&[42.0]), (42.0, 43.0));
    }

    #[test]
    fn test_normalize() {
        assert_eq!(BrailleSparkline::normalize(0.0, 100.0, 0.0), 0.0);
        assert_eq!(BrailleSparkline::normalize(0.0, 100.0, 50.0), 0.5);
        assert_eq!(BrailleSparkline::normalize(0.0, 100.0, 100.0), 1.0);
        // Degenerate range maps to mid-scale
        assert_eq!(BrailleSparkline::normalize(5.0, 5.0, 5.0), 0.5);
    }

    #[test]
    fn test_braille_orientation_bottom_up() {
        // A single-row chart (4 levels): the minimum must light only the
        // bottom dots (0x40 left, 0x80 right), never the top ones.
        let ch_min = BrailleSparkline::calculate_braille_for_row(0.0, 0.0, 0, 1);
        assert_eq!(ch_min as u32, 0x2800 + 0x40 + 0x80);

        // The maximum must fill the whole cell (all dots set).
        let ch_max = BrailleSparkline::calculate_braille_for_row(1.0, 1.0, 0, 1);
        assert_eq!(
            ch_max as u32,
            0x2800 + 0x40 + 0x04 + 0x02 + 0x01 + 0x80 + 0x20 + 0x10 + 0x08
        );

        // With two rows, the bottom row fills first: a mid value (level 2 of
        // 8) paints the three lowest dots of the bottom row and nothing in
        // the top row.
        let ch_mid_bottom = BrailleSparkline::calculate_braille_for_row(0.25, 0.25, 1, 2);
        assert_eq!(
            ch_mid_bottom as u32,
            0x2800 + 0x40 + 0x04 + 0x02 + 0x80 + 0x20 + 0x10
        );
        let ch_mid_top = BrailleSparkline::calculate_braille_for_row(0.25, 0.25, 0, 2);
        assert_eq!(ch_mid_top as u32, 0x2800);
    }

    #[test]
    fn test_render_bounds_follow_visible_tail() {
        // A large spike far in the past must not pin the scale of the
        // rendered tail (width 1 cell = 2 data points → tail is [21, 22]).
        let data = vec![500.0, 20.0, 21.0, 22.0];
        let sparkline = BrailleSparkline::new(&data).height(1);

        let backend = ratatui::backend::TestBackend::new(1, 1);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                use ratatui::widgets::Widget;
                sparkline.clone().render(f.area(), f.buffer_mut());
            })
            .unwrap();

        // The tail values (21 vs 22) span the full scale: the left column is
        // at its minimum (bottom dot only) while the right column is at its
        // maximum (all 4 dots). With whole-history bounds the tail would
        // collapse to the bottom dot on both columns.
        let cell = terminal.backend().buffer()[(0, 0)].symbol();
        let ch = cell.chars().next().unwrap();
        assert_eq!(ch as u32, 0x2800 + 0x40 + 0x80 + 0x20 + 0x10 + 0x08);
    }

    #[test]
    fn test_braille_clone_preserves_color_fn() {
        let data = vec![1.0, 2.0, 3.0];
        let sparkline = BrailleSparkline::new(&data).color_fn(gradient_for_rtt);
        let cloned = sparkline.clone();

        assert!(cloned.color_fn.is_some());
        // The cloned color function still maps values through the gradient
        assert_eq!(
            (cloned.color_fn.as_ref().unwrap())(0.0),
            gradient_for_rtt(0.0)
        );
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
