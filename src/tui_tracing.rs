//! Custom tracing layer for TUI mode
//!
//! Captures tracing events and sends them to a channel for display in the TUI.
//! In quiet mode, the standard stderr subscriber is used instead.

use tokio::sync::mpsc;
use tracing::{Level, Subscriber};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

/// A log entry captured from tracing
#[derive(Debug, Clone)]
pub struct TracingLogEntry {
    pub level: Level,
    pub target: String,
    pub message: String,
}

/// Custom tracing layer that sends events to a channel
pub struct TuiTracingLayer {
    sender: mpsc::Sender<TracingLogEntry>,
}

impl TuiTracingLayer {
    /// Capacity of the bounded channel feeding the TUI log consumer
    pub const CHANNEL_BUFFER_SIZE: usize = 1024;

    /// Create a new TUI tracing layer with a channel
    pub fn new() -> (Self, mpsc::Receiver<TracingLogEntry>) {
        let (sender, receiver) = mpsc::channel(Self::CHANNEL_BUFFER_SIZE);
        (Self { sender }, receiver)
    }
}

impl<S> Layer<S> for TuiTracingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        // Extract level
        let level = *event.metadata().level();

        // Extract target (module path)
        let target = event.metadata().target().to_string();

        // Extract message from the event fields
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let entry = TracingLogEntry {
            level,
            target,
            message: visitor.message,
        };

        // Bounded channel: drop the entry if the TUI consumer cannot keep up
        // instead of growing the queue without bound. The store's log deque
        // is bounded — the channel must not be the unbounded link in between.
        let _ = self.sender.try_send(entry);
    }
}

/// Visitor to extract the message field from tracing events
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let rendered = format!("{:?}", value);
            // Strip the surrounding quotes `Debug` adds for strings. This
            // must be lenient: a rendering of exactly one `"` satisfies both
            // predicates and would panic on a `1..0` slice.
            self.message = rendered
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .map(str::to_owned)
                .unwrap_or(rendered);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }
}

/// Receiver handle for consuming tracing log entries
pub type TracingLogReceiver = mpsc::Receiver<TracingLogEntry>;
