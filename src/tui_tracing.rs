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
    sender: mpsc::UnboundedSender<TracingLogEntry>,
}

impl TuiTracingLayer {
    /// Create a new TUI tracing layer with a channel
    pub fn new() -> (Self, mpsc::UnboundedReceiver<TracingLogEntry>) {
        let (sender, receiver) = mpsc::unbounded_channel();
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

        // Send to channel (ignore errors if receiver is dropped)
        let _ = self.sender.send(entry);
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
            self.message = format!("{:?}", value);
            // Remove surrounding quotes if present
            if self.message.starts_with('"') && self.message.ends_with('"') {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }
}

/// Receiver handle for consuming tracing log entries
pub type TracingLogReceiver = mpsc::UnboundedReceiver<TracingLogEntry>;
