//! Utility functions

/// Compute jitter as mean absolute difference between consecutive RTT values
/// Formula: mean(|rtt[i] - rtt[i-1]|)
/// Returns 0.0 if less than 2 samples
pub fn compute_jitter(rtt_history: &[f64]) -> f64 {
    if rtt_history.len() < 2 {
        return 0.0;
    }

    let mut jitter_sum = 0.0;
    for i in 1..rtt_history.len() {
        jitter_sum += (rtt_history[i] - rtt_history[i - 1]).abs();
    }

    jitter_sum / (rtt_history.len() - 1) as f64
}

/// Compute MOS (Mean Opinion Score) using simplified E-model (ITU-T G.107)
///
/// Formula:
/// effective_latency = avg_rtt + jitter * 2 + 10
/// R = 93.2 - (effective_latency / 40) - (packet_loss_pct * 2.5)
/// MOS = 1 + 0.035 * R + 0.000007 * R * (R - 60) * (100 - R)
///
/// Result is clamped to [1.0, 4.5]
pub fn compute_mos(avg_rtt: f64, jitter: f64, loss_pct: f64) -> f64 {
    let effective_latency = avg_rtt + jitter * 2.0 + 10.0;
    let r = 93.2 - (effective_latency / 40.0) - (loss_pct * 2.5);

    // The G.107 polynomial is only valid for R in [0, 100]. Without this
    // clamp, heavy loss drives R negative and the cubic term turns
    // positive again — a dead target would grade "A".
    let r = r.clamp(0.0, 100.0);

    let mos = 1.0 + 0.035 * r + 0.000007 * r * (r - 60.0) * (100.0 - r);

    // Clamp to valid MOS range [1.0, 4.5]
    mos.clamp(1.0, 4.5)
}

/// Convert MOS score to letter grade
/// A: >= 4.0
/// B: >= 3.5
/// C: >= 3.0
/// D: >= 2.5
/// F: < 2.5
pub fn mos_to_grade(mos: f64) -> char {
    if mos >= 4.0 {
        'A'
    } else if mos >= 3.5 {
        'B'
    } else if mos >= 3.0 {
        'C'
    } else if mos >= 2.5 {
        'D'
    } else {
        'F'
    }
}

/// Format duration in seconds to HH:MM:SS string
pub fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

/// Calculate a percentile of a slice of values.
///
/// This is a lower-index quantile: the rank is `index = (p * (n - 1)) as usize`
/// into the ascending order (not the textbook nearest-rank `ceil(p * n)`).
/// Uses partial selection (O(n) average) instead of a full sort, and a total
/// order (`total_cmp`) so a `NaN` sample cannot panic the comparison.
pub fn calculate_percentile(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut owned: Vec<f64> = values.to_vec();
    let index = (percentile * (owned.len() - 1) as f64) as usize;
    owned.select_nth_unstable_by(index, |a, b| a.total_cmp(b));
    owned[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_jitter_basic() {
        // Sequence: 10, 20, 10, 20
        // Differences: |10|, |10|, |10|
        // Mean: 10.0
        let rtt = vec![10.0, 20.0, 10.0, 20.0];
        assert_eq!(compute_jitter(&rtt), 10.0);
    }

    #[test]
    fn test_compute_jitter_single_value() {
        let rtt = vec![10.0];
        assert_eq!(compute_jitter(&rtt), 0.0);
    }

    #[test]
    fn test_compute_jitter_empty() {
        let rtt: Vec<f64> = vec![];
        assert_eq!(compute_jitter(&rtt), 0.0);
    }

    #[test]
    fn test_compute_jitter_stable() {
        // Stable RTT - no jitter
        let rtt = vec![20.0, 20.0, 20.0, 20.0];
        assert_eq!(compute_jitter(&rtt), 0.0);
    }

    #[test]
    fn test_compute_jitter_increasing() {
        // Increasing RTT: 10, 20, 30, 40
        // Differences: 10, 10, 10
        // Mean: 10.0
        let rtt = vec![10.0, 20.0, 30.0, 40.0];
        assert_eq!(compute_jitter(&rtt), 10.0);
    }

    #[test]
    fn test_compute_mos_perfect() {
        // Perfect connection: 0ms RTT, 0% loss
        // E-model formula with these values gives ~4.41, not 4.5
        let mos = compute_mos(0.0, 0.0, 0.0);
        assert!(
            mos > 4.0,
            "Perfect connection MOS should be > 4.0, got {}",
            mos
        );
        assert!(
            mos <= 4.5,
            "Perfect connection MOS should be <= 4.5, got {}",
            mos
        );
    }

    #[test]
    fn test_compute_mos_ideal() {
        // Ideal connection: 20ms RTT, 0.1ms jitter, 0% loss
        let mos = compute_mos(20.0, 0.1, 0.0);
        assert!(
            mos > 4.0,
            "Ideal connection MOS should be > 4.0, got {}",
            mos
        );
    }

    #[test]
    fn test_compute_mos_good() {
        // Good connection: 50ms RTT, 2ms jitter, 0.5% loss
        let mos = compute_mos(50.0, 2.0, 0.5);
        assert!(
            (3.5..4.5).contains(&mos),
            "Good connection MOS should be in [3.5, 4.5), got {}",
            mos
        );
    }

    #[test]
    fn test_compute_mos_poor() {
        // Poor connection: 200ms RTT, 10ms jitter, 5% loss
        let mos = compute_mos(200.0, 10.0, 5.0);
        // E-model is more lenient than expected - 200ms/5% still gives decent MOS
        assert!(
            mos >= 2.0,
            "Poor connection MOS should be >= 2.0, got {}",
            mos
        );
        assert!(
            mos < 4.5,
            "Poor connection MOS should be < 4.5, got {}",
            mos
        );
    }

    #[test]
    fn test_compute_mos_bad() {
        // Bad connection: 500ms RTT, 50ms jitter, 20% loss
        let mos = compute_mos(500.0, 50.0, 20.0);
        assert!(mos < 2.5, "Bad connection MOS should be < 2.5, got {}", mos);
    }

    #[test]
    fn test_compute_mos_clamped_minimum() {
        // Very bad connection: high latency and packet loss
        // Note: E-model formula has a polynomial that behaves unexpectedly at extremes
        // Using moderate-high values that produce low MOS (around 1.0-1.5)
        let mos = compute_mos(1000.0, 100.0, 30.0);
        // With these values, MOS should be at or near minimum
        assert!(
            (1.0..=1.5).contains(&mos),
            "MOS should be low for bad connection, got {}",
            mos
        );
    }

    #[test]
    fn test_compute_mos_clamped_maximum() {
        // Very good connection should give MOS close to maximum
        let mos = compute_mos(0.0, 0.0, 0.0);
        // MOS is clamped to 4.5 at the upper bound
        assert!(mos <= 4.5, "MOS should be <= 4.5, got {mos}");
        assert!(
            mos > 4.0,
            "Perfect connection should have MOS > 4.0, got {mos}"
        );
    }

    #[test]
    fn test_compute_mos_high_loss_grades_f() {
        // Regression: R must be clamped to [0, 100] before the G.107
        // polynomial. Without the clamp the cubic term turns positive for
        // R < 0 and heavy loss grades "A / Excellent".
        for loss in [60.0, 80.0, 100.0] {
            let mos = compute_mos(0.0, 0.0, loss);
            assert!(mos < 2.5, "{loss}% loss must grade F, got MOS {mos}");
            assert_eq!(mos_to_grade(mos), 'F');
        }

        // Monotonicity: more loss never improves the score.
        let m30 = compute_mos(0.0, 0.0, 30.0);
        let m60 = compute_mos(0.0, 0.0, 60.0);
        let m100 = compute_mos(0.0, 0.0, 100.0);
        assert!(m100 <= m60 && m60 <= m30);
    }

    #[test]
    fn test_mos_to_grade_a() {
        assert_eq!(mos_to_grade(4.5), 'A');
        assert_eq!(mos_to_grade(4.0), 'A');
        assert_eq!(mos_to_grade(4.2), 'A');
    }

    #[test]
    fn test_mos_to_grade_b() {
        assert_eq!(mos_to_grade(3.9), 'B');
        assert_eq!(mos_to_grade(3.5), 'B');
        assert_eq!(mos_to_grade(3.7), 'B');
    }

    #[test]
    fn test_mos_to_grade_c() {
        assert_eq!(mos_to_grade(3.4), 'C');
        assert_eq!(mos_to_grade(3.0), 'C');
        assert_eq!(mos_to_grade(3.2), 'C');
    }

    #[test]
    fn test_mos_to_grade_d() {
        assert_eq!(mos_to_grade(2.9), 'D');
        assert_eq!(mos_to_grade(2.5), 'D');
        assert_eq!(mos_to_grade(2.7), 'D');
    }

    #[test]
    fn test_mos_to_grade_f() {
        assert_eq!(mos_to_grade(2.4), 'F');
        assert_eq!(mos_to_grade(1.0), 'F');
        assert_eq!(mos_to_grade(2.0), 'F');
    }

    #[test]
    fn test_format_duration_zero() {
        assert_eq!(format_duration(0), "00:00:00");
    }

    #[test]
    fn test_format_duration_seconds_only() {
        assert_eq!(format_duration(45), "00:00:45");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(125), "00:02:05");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3661), "01:01:01");
    }

    #[test]
    fn test_format_duration_large() {
        assert_eq!(format_duration(86400), "24:00:00");
    }

    #[test]
    fn test_calculate_percentile() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];

        assert_eq!(calculate_percentile(&data, 0.0), 1.0);
        assert_eq!(calculate_percentile(&data, 0.5), 5.0);
        assert_eq!(calculate_percentile(&data, 0.95), 9.0);
        assert_eq!(calculate_percentile(&data, 1.0), 10.0);
    }

    #[test]
    fn test_calculate_percentile_empty() {
        let data: Vec<f64> = vec![];
        assert_eq!(calculate_percentile(&data, 0.5), 0.0);
    }

    #[test]
    fn test_calculate_percentile_nan_safe() {
        // A NaN sample must not panic the ordering (total_cmp, not partial_cmp)
        let data = vec![10.0, f64::NAN, 30.0];
        let _ = calculate_percentile(&data, 0.5);
    }
}
