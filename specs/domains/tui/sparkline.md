# Braille Sparkline

## Role

Custom ratatui widget (`BrailleSparkline`) that renders time-series data as Unicode braille dot patterns (U+2800–U+28FF) for 2× the horizontal density and up to 8 vertical levels in two terminal rows — versus 1 level per row for block-character sparklines.

## Key Files

- `src/tui/sparkline.rs` — `BrailleSparkline`, `BRAILLE_PATTERNS`, `rtt_thresholds` module

## Core Types

```rust
pub struct BrailleSparkline<'a> {
    data: &'a [f64],
    height: u16,                     // terminal rows, default 2, clamped to area
    style: Style,
    color_fn: Option<std::sync::Arc<dyn Fn(f64) -> Color + 'a>>,   // .color_fn(|raw_value| Color)
}

pub mod rtt_thresholds {           // severity colors by raw value (ms)
    pub const EXCELLENT: f64 = 50.0;   // below → green
    pub const GOOD: f64 = 100.0;       // below → yellow-green
    pub const WARNING: f64 = 400.0;    // below → orange; ≥ → red
}
```

## Behavior

### Encoding

Each braille character is a 2×4 dot matrix with dot bit patterns:

```
dots:  1 4        left column  bits: 0x40, 0x04, 0x02, 0x01  (bottom→top: dots 7, 3, 2, 1)
       2 5        right column bits: 0x80, 0x20, 0x10, 0x08  (bottom→top: dots 8, 6, 5, 4)
       3 6
       7 8        char = U+2800 + OR of set bits
```

- One character column holds **2 data points** (left, right); one terminal row covers **4 vertical levels**; with the default height 2 → 8 levels total.
- `total_levels = 4 × height`. A normalized value maps to `level = floor(value × total_levels)` clamped to `total_levels − 1`; in each row, dot `i` is set when `level ≥ row_start + i`, and row bands are indexed from the bottom (`row_start = (height − 1 − row) × 4`) — so higher values fill dots closer to the top of the chart (bottom-up fill).

### Rendering pipeline (`Widget::render`)

1. Empty area or empty data → no-op.
2. Fit data to `width × 2` points: take the **tail** if longer; pad with `min` at the **beginning** if shorter (chart grows from the right).
3. Normalize each point: `(v − min) / (max − min)` clamped to `[0, 1]`; degenerate range (`max == min`) normalizes to `0.5`.
4. Per column: build the braille char from both points; color = `color_fn(avg(raw_left, raw_right))` if set, else the style's `fg` (default `Color::White`).
5. Default bounds are the min/max of the sampled tail, computed in `render` (a single old extreme cannot pin the visible scale); when the range is flat, `max` is raised to `min + 1` so the chart stays non-degenerate and auto-scales per frame.

### Usage

Panels pass a history slice (`store.*_history()`) and a `color_fn` built from `rtt_thresholds` so colors encode absolute value (severity), while dot height encodes relative position within the visible window's range.

## Error Handling

Rendering is infallible: invalid codepoints fall back to `' '`; out-of-area cells are skipped; short data is padded rather than rejected.

## Invariants

1. The widget reads only the borrowed slice — all its state lives in its own fields and the `render` arguments.
2. Data density is exactly 2 points per terminal column (after tail-sampling/padding).
3. Auto-bounds are recomputed from the visible data (the rendered tail) on every render.
4. Color reflects the raw data value; height reflects the normalized value — the two encodings are independent.

## Related Specs

- [panels-and-layout.md](panels-and-layout.md) — which panels embed the sparkline and with which histories
- [../../domains/metrics-store.md](../../domains/metrics-store.md) — ring buffers feeding `data`
