//! TUI module for dashboard display
//!
//! Implements the main TUI event loop with:
//! - Terminal setup (raw mode, alternate screen)
//! - Event handling (keyboard input)
//! - Rendering loop (~4 FPS)
//! - Graceful shutdown

pub mod dns_panel;
pub mod events_panel;
pub mod footer;
pub mod header;
pub mod layout;
pub mod logs_panel;
pub mod ping_panel;
pub mod sparkline;
pub mod tcp_tls_panel;
pub mod theme;
pub mod trace_panel;

use crate::config::Config;
use crate::store::{MetricsStore, SharedStore};
use crate::tui::{
    dns_panel::DnsPanel, events_panel::EventsPanel, footer::FooterWidget, header::HeaderWidget,
    layout::DashboardLayout, logs_panel::LogsPanel, ping_panel::PingPanel,
    tcp_tls_panel::TcpTlsPanel, theme::Theme, trace_panel::TracePanel,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{
        EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode, size,
    },
};
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
};
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Focusable panels for keyboard navigation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPanel {
    /// Traceroute panel
    Traceroute,
    /// Events panel
    Events,
    /// Logs panel
    Logs,
}

/// Restores the terminal when dropped, so an early return from
/// [`TuiApp::run`] (failed setup, panic-hook path) never leaves the shell in
/// raw mode with the alternate screen still active. The cursor is re-shown
/// too: ratatui keeps it hidden while drawing, and only the normal exit path
/// restores it via `Terminal::show_cursor`.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = execute!(io::stdout(), crossterm::cursor::Show);
    }
}

/// TUI application state
#[derive(Debug)]
pub struct TuiApp {
    /// Shared metrics store
    store: SharedStore,
    /// Configuration
    config: Config,
    /// Cancellation token for graceful shutdown
    cancel: CancellationToken,
    /// Notification for forcing traceroute
    trace_notify: std::sync::Arc<Notify>,
    /// Notification for statistics reset (re-warms the ICMP anomaly detector)
    reset_notify: std::sync::Arc<Notify>,
    /// Channel for IP address changes
    ip_change_tx: tokio::sync::watch::Sender<std::net::IpAddr>,
    /// Theme
    theme: Theme,
    /// Help popup visible
    show_help: bool,
    /// Currently focused panel (for scrolling)
    focused_panel: FocusPanel,
    /// Scroll offset for traceroute panel
    trace_scroll: usize,
    /// Scroll offset for events panel
    events_scroll: usize,
    /// Whether events panel is in auto-scroll mode
    events_auto_scroll: bool,
    /// Scroll offset for logs panel
    logs_scroll: usize,
    /// Whether logs panel is in auto-scroll mode
    logs_auto_scroll: bool,
}

impl TuiApp {
    /// Create a new TUI application
    pub fn new(
        store: SharedStore,
        config: Config,
        cancel: CancellationToken,
        trace_notify: std::sync::Arc<Notify>,
        reset_notify: std::sync::Arc<Notify>,
        ip_change_tx: tokio::sync::watch::Sender<std::net::IpAddr>,
    ) -> Self {
        Self {
            store,
            config,
            cancel,
            trace_notify,
            reset_notify,
            ip_change_tx,
            theme: Theme::new(),
            show_help: false,
            focused_panel: FocusPanel::Logs,
            trace_scroll: 0,
            events_scroll: 0,
            events_auto_scroll: true,
            logs_scroll: 0,
            logs_auto_scroll: true,
        }
    }

    /// Run the TUI main loop
    pub async fn run(&mut self) -> anyhow::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        // From here on, any early return must still restore the terminal:
        // the guard covers the fallible setup below (alternate screen,
        // backend creation) that used to leak raw mode on failure.
        let terminal_guard = TerminalGuard;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;

        // Setup panic hook to restore the terminal when the TUI itself
        // panics. The hook is process-global and the multi-threaded tokio
        // runtime migrates tasks between worker threads, so thread identity
        // cannot distinguish "the TUI panicked" from "a probe task panicked
        // on the same worker"; the panic location can. Only a panic rooted
        // in `src/tui/` tears down the terminal here — which keeps the panic
        // message readable — while probe-task panics leave the running
        // dashboard untouched (their unwind is contained by the task join in
        // app.rs). Any panic unwinding through `run()` still restores the
        // terminal via `TerminalGuard`'s drop, including panics surfaced from
        // dependencies, whose locations this check deliberately ignores.
        let original_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let from_tui = info
                .location()
                .is_some_and(|loc| loc.file().replace('\\', "/").contains("src/tui/"));
            if from_tui {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen);
            }
            original_hook(info);
        }));

        // Create backend and terminal
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Focus may start on a panel that is hidden at this terminal size
        self.clamp_focus_to_visible();

        // Main loop
        let result = self.run_loop(&mut terminal).await;

        // Restore terminal
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        // The normal path restored the terminal above; defuse the guard so
        // Drop does not run a second (harmless but noisy) restore.
        std::mem::forget(terminal_guard);

        result
    }

    /// Main event loop
    async fn run_loop<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> anyhow::Result<()> {
        let mut last_draw = Instant::now();
        let draw_interval = Duration::from_millis(250); // 4 FPS

        loop {
            // Check for cancellation
            if self.cancel.is_cancelled() {
                break;
            }

            // Draw if needed
            let now = Instant::now();
            if now.duration_since(last_draw) >= draw_interval {
                // Read store BEFORE entering synchronous draw closure
                // This avoids blocking/async issues inside terminal.draw()
                let store = self.store.read().await;
                terminal
                    .draw(|f| {
                        self.draw(f, &store);
                    })
                    .map_err(|e| anyhow::anyhow!("Terminal draw error: {}", e))?;
                drop(store); // Explicitly drop the read guard
                last_draw = now;
            }

            // Handle events with timeout
            let timeout = draw_interval.saturating_sub(now.duration_since(last_draw));
            if crossterm::event::poll(timeout)?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
                && self.handle_key(key).await?
            {
                break;
            }
        }

        Ok(())
    }

    /// Handle keyboard input
    /// Returns true if the app should exit
    async fn handle_key(&mut self, key: KeyEvent) -> anyhow::Result<bool> {
        match key.code {
            // Quit (documented Ctrl+C shortcut; raw mode delivers it as a
            // key event, not as SIGINT)
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.cancel.cancel();
                return Ok(true);
            }

            // Quit
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.cancel.cancel();
                return Ok(true);
            }

            // Force traceroute
            KeyCode::Char('t') | KeyCode::Char('T') => {
                self.trace_notify.notify_one();
            }

            // Reset statistics
            KeyCode::Char('r') | KeyCode::Char('R') => {
                {
                    let mut store = self.store.write().await;
                    store.reset();
                }
                // Tell the ICMP probe loop so its anomaly-detection baseline
                // re-warms against the fresh statistics
                self.reset_notify.notify_one();
            }

            // Toggle help
            KeyCode::Char('?') => {
                self.show_help = !self.show_help;
            }

            // Scroll up
            KeyCode::Up => match self.focused_panel {
                FocusPanel::Traceroute if !self.trace_hidden() => {
                    self.trace_scroll = self.trace_scroll.saturating_sub(1);
                }
                FocusPanel::Events if !self.events_hidden() => {
                    let max_scroll = self.events_max_scroll().await;
                    let (offset, auto) = Self::apply_scroll_up(
                        self.events_scroll,
                        self.events_auto_scroll,
                        max_scroll,
                    );
                    self.events_scroll = offset;
                    self.events_auto_scroll = auto;
                }
                FocusPanel::Logs if !self.logs_hidden() => {
                    let max_scroll = self.logs_max_scroll().await;
                    let (offset, auto) =
                        Self::apply_scroll_up(self.logs_scroll, self.logs_auto_scroll, max_scroll);
                    self.logs_scroll = offset;
                    self.logs_auto_scroll = auto;
                }
                // Hidden panels: keys are no-ops instead of mutating
                // invisible scroll state
                _ => {}
            },

            // Scroll down (reaching the tail re-enables auto-scroll)
            KeyCode::Down => match self.focused_panel {
                FocusPanel::Traceroute if !self.trace_hidden() => {
                    let max_scroll = self.trace_max_scroll().await;
                    self.trace_scroll = (self.trace_scroll.min(max_scroll) + 1).min(max_scroll);
                }
                FocusPanel::Events if !self.events_hidden() => {
                    let max_scroll = self.events_max_scroll().await;
                    let (offset, auto) = Self::apply_scroll_down(
                        self.events_scroll,
                        self.events_auto_scroll,
                        max_scroll,
                    );
                    self.events_scroll = offset;
                    self.events_auto_scroll = auto;
                }
                FocusPanel::Logs if !self.logs_hidden() => {
                    let max_scroll = self.logs_max_scroll().await;
                    let (offset, auto) = Self::apply_scroll_down(
                        self.logs_scroll,
                        self.logs_auto_scroll,
                        max_scroll,
                    );
                    self.logs_scroll = offset;
                    self.logs_auto_scroll = auto;
                }
                _ => {}
            },

            // Tab to switch focus (cycles visible panels only)
            KeyCode::Tab => {
                let visible = self.visible_panels();
                if visible.is_empty() {
                    // Nothing focusable at this terminal size
                } else if let Some(pos) = visible.iter().position(|p| *p == self.focused_panel) {
                    self.focused_panel = visible[(pos + 1) % visible.len()];
                } else {
                    // Current focus is on a hidden panel: jump to the first visible one
                    self.focused_panel = visible[0];
                }
            }

            // n/N to switch to next IP address
            KeyCode::Char('n') | KeyCode::Char('N') => {
                let mut store = self.store.write().await;
                if store.next_ip() {
                    let new_ip = store.active_ip();
                    drop(store);
                    if let Some(ip) = new_ip {
                        tracing::info!("Switched to next IP: {}", ip);
                        // Notify probes about IP change
                        let _ = self.ip_change_tx.send(ip);
                    }
                }
            }

            // p/P to switch to previous IP address
            KeyCode::Char('p') | KeyCode::Char('P') => {
                let mut store = self.store.write().await;
                if store.prev_ip() {
                    let new_ip = store.active_ip();
                    drop(store);
                    if let Some(ip) = new_ip {
                        tracing::info!("Switched to previous IP: {}", ip);
                        // Notify probes about IP change
                        let _ = self.ip_change_tx.send(ip);
                    }
                }
            }

            // Escape to close help
            KeyCode::Esc if self.show_help => {
                self.show_help = false;
            }

            _ => {}
        }

        Ok(false)
    }

    /// Scroll one row toward the tail.
    ///
    /// Returns the new `(offset, auto_scroll)` pair. Leaving auto-scroll
    /// anchors the offset at the tail, so the first `Up` moves exactly one
    /// row back instead of jumping to the top of the buffer; scrolling back
    /// down to the tail re-enables auto-scroll; the offset never grows past
    /// the bottom.
    fn apply_scroll_down(offset: usize, auto_scroll: bool, max_scroll: usize) -> (usize, bool) {
        if auto_scroll {
            // Already following the tail: Down there is a no-op and stays in
            // auto-scroll (there is nothing below the tail)
            return (max_scroll, true);
        }
        let target = offset.min(max_scroll) + 1;
        if target >= max_scroll {
            // The tail is reached again: resume following new output
            (max_scroll, true)
        } else {
            (target, false)
        }
    }

    /// Scroll one row away from the tail (see [`Self::apply_scroll_down`]).
    fn apply_scroll_up(offset: usize, auto_scroll: bool, max_scroll: usize) -> (usize, bool) {
        if auto_scroll {
            (max_scroll.saturating_sub(1), false)
        } else {
            (offset.saturating_sub(1), false)
        }
    }

    /// Panels that are currently rendered at this terminal size
    fn visible_panels(&self) -> Vec<FocusPanel> {
        match size() {
            Ok((width, height)) => {
                let layout = DashboardLayout::new(Rect::new(0, 0, width, height));
                let mut panels = Vec::with_capacity(3);
                if layout.is_traceroute_visible() {
                    panels.push(FocusPanel::Traceroute);
                }
                if layout.is_events_visible() {
                    panels.push(FocusPanel::Events);
                    panels.push(FocusPanel::Logs);
                }
                panels
            }
            // Size unknown (e.g. detached terminal): keep every panel usable
            Err(_) => vec![FocusPanel::Traceroute, FocusPanel::Events, FocusPanel::Logs],
        }
    }

    /// Move focus onto a panel that is actually rendered, if any
    fn clamp_focus_to_visible(&mut self) {
        let visible = self.visible_panels();
        if visible.contains(&self.focused_panel) {
            return;
        }
        if let Some(&first) = visible.first() {
            self.focused_panel = first;
        }
    }

    /// True when the events/logs panels are known to be hidden at the
    /// current terminal size (unknown size → assumed visible)
    fn events_hidden(&self) -> bool {
        match size() {
            Ok((width, height)) => {
                !DashboardLayout::new(Rect::new(0, 0, width, height)).is_events_visible()
            }
            Err(_) => false,
        }
    }

    fn logs_hidden(&self) -> bool {
        self.events_hidden()
    }

    /// True when the traceroute panel is known to be hidden
    fn trace_hidden(&self) -> bool {
        match size() {
            Ok((width, height)) => {
                !DashboardLayout::new(Rect::new(0, 0, width, height)).is_traceroute_visible()
            }
            Err(_) => false,
        }
    }

    /// Inner height (content rows) of the events/logs panels, when the
    /// terminal size is known and the panels are rendered
    fn events_viewport(&self) -> Option<usize> {
        let (width, height) = size().ok()?;
        let layout = DashboardLayout::new(Rect::new(0, 0, width, height));
        if !layout.is_events_visible() {
            return None;
        }
        let (_, _, _, _, _, events_area, _) = layout.build();
        Some(events_area.height.saturating_sub(2) as usize) // minus borders
    }

    fn logs_viewport(&self) -> Option<usize> {
        self.events_viewport()
    }

    /// Inner height (content rows) of the traceroute panel
    fn trace_viewport(&self) -> Option<usize> {
        let (width, height) = size().ok()?;
        let layout = DashboardLayout::new(Rect::new(0, 0, width, height));
        if !layout.is_traceroute_visible() {
            return None;
        }
        let (_, _, _, _, trace_area, _, _) = layout.build();
        Some(trace_area.height.saturating_sub(2) as usize) // minus borders
    }

    /// Max scroll offset for the events panel (item count minus viewport)
    async fn events_max_scroll(&self) -> usize {
        let store = self.store.read().await;
        let viewport = self
            .events_viewport()
            .unwrap_or_else(|| store.events().len().max(1));
        store.events().len().saturating_sub(viewport)
    }

    /// Max scroll offset for the logs panel
    async fn logs_max_scroll(&self) -> usize {
        let store = self.store.read().await;
        let viewport = self
            .logs_viewport()
            .unwrap_or_else(|| store.logs().len().max(1));
        store.logs().len().saturating_sub(viewport)
    }

    /// Max scroll offset for the traceroute panel (hop count minus viewport)
    async fn trace_max_scroll(&self) -> usize {
        let store = self.store.read().await;
        let hop_count = store
            .latest_traceroute()
            .data
            .as_ref()
            .map(|d| d.hops.len())
            .unwrap_or(0);
        let viewport = self.trace_viewport().unwrap_or(hop_count.max(1));
        hop_count.saturating_sub(viewport)
    }

    /// Draw the UI
    ///
    /// This is a synchronous function that takes a pre-acquired store guard.
    /// The store must be read BEFORE calling terminal.draw() to avoid
    /// blocking/async issues inside the synchronous draw closure.
    fn draw(&self, frame: &mut ratatui::Frame<'_>, store: &MetricsStore) {
        let area = frame.area();

        // Build layout
        let layout = DashboardLayout::new(area);
        let (header_area, ping_area, dns_area, tcp_tls_area, trace_area, events_area, footer_area) =
            layout.build();

        // Draw header
        let header = HeaderWidget::new(store, &self.theme);
        frame.render_widget(header, header_area);

        // Draw ping panel
        let ping_panel = PingPanel::new(store, &self.theme, layout.is_compact());
        frame.render_widget(ping_panel, ping_area);

        // Draw DNS panel
        let dns_panel = DnsPanel::new(store, &self.theme);
        frame.render_widget(dns_panel, dns_area);

        // Draw TCP/TLS/HTTP panel
        let tcp_tls_panel = TcpTlsPanel::new(store, &self.theme, self.config.port);
        frame.render_widget(tcp_tls_panel, tcp_tls_area);

        // Draw traceroute panel (if visible)
        if layout.is_traceroute_visible() {
            let trace_panel = TracePanel::with_scroll_and_focus(
                store,
                &self.theme,
                self.trace_scroll,
                self.focused_panel == FocusPanel::Traceroute,
            );
            frame.render_widget(trace_panel, trace_area);
        }

        // Draw events and logs panels side by side (if visible)
        if layout.is_events_visible() {
            // Split events_area horizontally into two columns
            let events_logs_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(events_area);

            let events_panel = EventsPanel::with_scroll_and_focus(
                store,
                &self.theme,
                self.events_scroll,
                self.events_auto_scroll,
                self.focused_panel == FocusPanel::Events,
            );
            frame.render_widget(events_panel, events_logs_chunks[0]);

            let logs_panel = LogsPanel::with_scroll_and_focus(
                store,
                &self.theme,
                self.logs_scroll,
                self.logs_auto_scroll,
                self.focused_panel == FocusPanel::Logs,
            );
            frame.render_widget(logs_panel, events_logs_chunks[1]);
        }

        // Draw footer
        let footer = FooterWidget::new(&self.theme);
        frame.render_widget(footer, footer_area);

        // Draw help popup if visible
        if self.show_help {
            self.draw_help_popup(frame, area);
        }
    }

    /// Draw help popup overlay
    fn draw_help_popup(&self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        use ratatui::{
            layout::Rect,
            style::Style,
            widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
        };

        // Calculate popup size (centered, 60% of screen)
        let popup_width = (area.width as f32 * 0.6) as u16;
        let popup_height = (area.height as f32 * 0.6) as u16;
        let popup_x = (area.width - popup_width) / 2;
        let popup_y = (area.height - popup_height) / 2;

        let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

        // Clear background
        frame.render_widget(Clear, popup_area);

        // Help text
        let help_text = "netprobe - Network Quality Monitor\n\n\
            Hotkeys:\n\
            ─────────\n\
            q           Quit application\n\
            t           Force traceroute (run immediately)\n\
            r           Reset statistics\n\
            n/p         Switch active IP address\n\
            ↑/↓         Scroll the focused panel (trace/events/logs)\n\
            Tab         Switch focus between panels\n\
            ?           Toggle this help\n\
            Esc         Close help\n\n\
            Ctrl+C      Quit application"
            .to_string();

        let paragraph = Paragraph::new(help_text)
            .block(
                Block::default()
                    .title(" Help ")
                    .title_style(Style::default().fg(self.theme.title))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(self.theme.border)),
            )
            .style(Style::default().fg(self.theme.text))
            .wrap(Wrap { trim: true });

        frame.render_widget(paragraph, popup_area);
    }
}

/// Run the TUI application
///
/// This is the main entry point for the TUI. It sets up the terminal,
/// runs the event loop, and handles graceful shutdown.
pub async fn run_tui(
    store: SharedStore,
    config: Config,
    cancel: CancellationToken,
    trace_notify: std::sync::Arc<Notify>,
    reset_notify: std::sync::Arc<Notify>,
    ip_change_tx: tokio::sync::watch::Sender<std::net::IpAddr>,
) -> anyhow::Result<()> {
    // External termination (`kill <pid>`, service managers) must go through
    // the graceful-shutdown token so the terminal is restored and a final
    // session_end is written, instead of the default handler killing the
    // process mid-dashboard. (Ctrl+C inside the terminal arrives as a key
    // event in raw mode; this covers delivered signals.)
    spawn_signal_forwarder(cancel.clone());

    let mut app = TuiApp::new(
        store,
        config,
        cancel,
        trace_notify,
        reset_notify,
        ip_change_tx,
    );
    app.run().await
}

/// Cancel the shutdown token when a termination signal arrives
///
/// The first signal starts the graceful shutdown; a repeat during the
/// bounded shutdown window force-exits (130 for SIGINT, mirroring the
/// quiet-mode watchdog in `app.rs`; 143 for SIGTERM). Tokio's signal
/// handlers stay installed for the process lifetime, so one-shot
/// listeners would silently swallow the repeat and let a wedged shutdown
/// hang forever with the dashboard already torn down.
#[cfg(unix)]
fn spawn_signal_forwarder(cancel: CancellationToken) {
    use tokio::signal::unix::{SignalKind, signal};

    let cancel_sigterm = cancel.clone();
    tokio::spawn(async move {
        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            sigterm.recv().await;
            tracing::info!("SIGTERM received; shutting down");
            cancel_sigterm.cancel();
            if sigterm.recv().await.is_some() {
                tracing::info!("second SIGTERM received; forcing exit");
                std::process::exit(143);
            }
        }
    });

    tokio::spawn(async move {
        if let Ok(mut sigint) = signal(SignalKind::interrupt()) {
            sigint.recv().await;
            tracing::info!("SIGINT received; shutting down");
            cancel.cancel();
            if sigint.recv().await.is_some() {
                tracing::info!("second SIGINT received; forcing exit");
                std::process::exit(130);
            }
        }
    });
}

/// No portable signal handling on non-Unix targets
#[cfg(not(unix))]
fn spawn_signal_forwarder(_cancel: CancellationToken) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MetricsStore;
    use ratatui::backend::TestBackend;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_store() -> SharedStore {
        Arc::new(RwLock::new(MetricsStore::new(100, "1.1.1.1".to_string())))
    }

    fn create_test_ip_channel() -> (
        tokio::sync::watch::Sender<IpAddr>,
        tokio::sync::watch::Receiver<IpAddr>,
    ) {
        let ip = IpAddr::from_str("1.1.1.1").unwrap();
        tokio::sync::watch::channel(ip)
    }

    fn create_test_config() -> Config {
        Config {
            target: "1.1.1.1".to_string(),
            log_path: std::path::PathBuf::from("/tmp/test.jsonl"),
            port: 443,
            http_path: "/".to_string(),
            no_http: false,
            no_tls: false,
            interval_icmp_ms: 1000,
            interval_dns_sec: 30,
            interval_tcp_sec: 10,
            interval_trace_sec: 60,
            history: 3600,
            timeout_icmp_ms: 2000,
            timeout_tcp_ms: 5000,
            timeout_dns_ms: 5000,
            timeout_http_ms: 10000,
            timeout_trace_ms: 30000,
            dns_server: None,
            quiet: false,
        }
    }

    #[test]
    fn test_tui_app_new() {
        let store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let app = TuiApp::new(store, config, cancel, trace_notify, reset_notify, ip_tx);

        assert!(!app.show_help);
        assert_eq!(app.trace_scroll, 0);
        assert_eq!(app.events_scroll, 0);
        assert!(app.events_auto_scroll);
        assert_eq!(app.logs_scroll, 0);
        assert!(app.logs_auto_scroll);
        assert!(matches!(app.focused_panel, FocusPanel::Logs));
    }

    #[tokio::test]
    async fn test_handle_key_quit() {
        let store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(
            store,
            config,
            cancel.clone(),
            trace_notify,
            reset_notify,
            ip_tx,
        );

        let should_exit = app
            .handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE))
            .await
            .unwrap();
        assert!(should_exit);
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn test_handle_key_help() {
        let store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(store, config, cancel, trace_notify, reset_notify, ip_tx);

        assert!(!app.show_help);
        let should_exit = app
            .handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE))
            .await
            .unwrap();
        assert!(!should_exit);
        assert!(app.show_help);

        // Toggle off
        let should_exit = app
            .handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE))
            .await
            .unwrap();
        assert!(!should_exit);
        assert!(!app.show_help);
    }

    #[tokio::test]
    async fn test_handle_key_esc() {
        let store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(store, config, cancel, trace_notify, reset_notify, ip_tx);

        // First enable help
        app.show_help = true;

        // Esc should close help
        let should_exit = app
            .handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .await
            .unwrap();
        assert!(!should_exit);
        assert!(!app.show_help);
    }

    #[tokio::test]
    async fn test_handle_key_ctrl_c_quits() {
        let store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(
            store,
            config,
            cancel.clone(),
            trace_notify,
            reset_notify,
            ip_tx,
        );

        // Plain 'c' does NOT quit...
        let should_exit = app
            .handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE))
            .await
            .unwrap();
        assert!(!should_exit);
        assert!(!cancel.is_cancelled());

        // ...but Ctrl+C does (the documented quit shortcut)
        let should_exit = app
            .handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL))
            .await
            .unwrap();
        assert!(should_exit);
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn test_apply_scroll_down_anchors_at_tail_and_reenables() {
        use TuiApp as T;

        // Leaving auto-scroll anchors the offset at the tail; the keypress
        // that reaches the tail re-enables auto-scroll
        assert_eq!(T::apply_scroll_down(0, true, 190), (190, true));

        // Manual scrolling walks one row at a time and clamps at the tail
        assert_eq!(T::apply_scroll_down(5, false, 190), (6, false));
        assert_eq!(T::apply_scroll_down(189, false, 190), (190, true));

        // Over-scroll is impossible: the offset never passes the bottom
        assert_eq!(T::apply_scroll_down(500, false, 190), (190, true));

        // Content that fits has no scroll range at all
        assert_eq!(T::apply_scroll_down(0, true, 0), (0, true));
    }

    #[test]
    fn test_apply_scroll_up_seeds_from_tail() {
        use TuiApp as T;

        // The first Up from auto-scroll lands one row above the tail, not
        // at the top of the buffer
        assert_eq!(T::apply_scroll_up(0, true, 190), (189, false));

        // Manual Up keeps walking upward
        assert_eq!(T::apply_scroll_up(189, false, 190), (188, false));

        // Everything visible: Up simply detaches auto-scroll at offset 0
        assert_eq!(T::apply_scroll_up(0, true, 0), (0, false));
    }

    #[tokio::test]
    async fn test_handle_key_scroll() {
        let store = create_test_store();
        {
            let mut store = store.write().await;
            for i in 0..5 {
                store.push_log_event(
                    if i % 2 == 0 {
                        tracing::Level::INFO
                    } else {
                        tracing::Level::WARN
                    },
                    "netprobe::test",
                    format!("log line {}", i),
                );
            }
        }
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(store, config, cancel, trace_notify, reset_notify, ip_tx);

        // Initial state - focused on Logs, following the tail
        assert_eq!(app.logs_scroll, 0);
        assert!(app.logs_auto_scroll);

        // Scroll keys must leave the state consistent. (The terminal size is
        // not determinable in tests, so the exact offset is
        // environment-dependent; the invariants are: the offset never passes
        // the bottom, Up detaches auto-scroll, and re-reaching the tail
        // re-enables it.)
        let _ = app
            .handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE))
            .await
            .unwrap();
        assert!(app.logs_scroll <= 5);
        let _ = app
            .handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE))
            .await
            .unwrap();
        assert!(!app.logs_auto_scroll);

        // Scrolling back down to the tail resumes auto-scroll
        for _ in 0..10 {
            if app.logs_auto_scroll {
                break;
            }
            let _ = app
                .handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE))
                .await
                .unwrap();
        }
        assert!(app.logs_auto_scroll);
    }

    #[tokio::test]
    async fn test_handle_key_tab_focus() {
        let store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(store, config, cancel, trace_notify, reset_notify, ip_tx);

        // Initial focus is Logs
        assert!(matches!(app.focused_panel, FocusPanel::Logs));

        // Tab switches to Traceroute
        let _ = app
            .handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE))
            .await
            .unwrap();
        assert!(matches!(app.focused_panel, FocusPanel::Traceroute));

        // Tab switches to Events
        let _ = app
            .handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE))
            .await
            .unwrap();
        assert!(matches!(app.focused_panel, FocusPanel::Events));

        // Tab switches back to Logs
        let _ = app
            .handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE))
            .await
            .unwrap();
        assert!(matches!(app.focused_panel, FocusPanel::Logs));
    }

    /// Test that draw() works correctly with a TestBackend.
    /// This verifies the synchronous draw function doesn't panic.
    #[test]
    fn test_draw_with_test_backend() {
        let shared_store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let app = TuiApp::new(
            shared_store.clone(),
            config,
            cancel,
            trace_notify,
            reset_notify,
            ip_tx,
        );

        // Create a test terminal
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        // Create a local store for the test (simulating what run_loop does)
        let store = MetricsStore::new(100, "1.1.1.1".to_string());

        // Draw should not panic
        terminal
            .draw(|f| {
                app.draw(f, &store);
            })
            .unwrap();
    }

    /// Test that draw() works within a tokio runtime context.
    /// This is the critical test that would have caught the original bug.
    #[tokio::test]
    async fn test_draw_in_async_context() {
        let shared_store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let app = TuiApp::new(
            shared_store.clone(),
            config,
            cancel,
            trace_notify,
            reset_notify,
            ip_tx,
        );

        // Create a test terminal
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        // Read the store asynchronously (as run_loop does)
        let store = shared_store.read().await;

        // Draw within async context - this would have panicked with the old code
        terminal
            .draw(|f| {
                app.draw(f, &store);
            })
            .unwrap();
    }

    /// Test that draw() works with populated store data.
    #[tokio::test]
    async fn test_draw_with_data() {
        let shared_store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        // Populate the store with some data
        {
            let mut store = shared_store.write().await;
            store.inc_icmp_sent();
            store.push_icmp_rtt(10.5);
            store.push_dns_resolve(5.2);
            store.push_tcp_connect(15.3);
        }

        let app = TuiApp::new(
            shared_store.clone(),
            config,
            cancel,
            trace_notify,
            reset_notify,
            ip_tx,
        );

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        let store = shared_store.read().await;

        // Should render without panic
        terminal
            .draw(|f| {
                app.draw(f, &store);
            })
            .unwrap();
    }

    /// Test that draw() works with help popup visible.
    #[tokio::test]
    async fn test_draw_with_help_popup() {
        let shared_store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(
            shared_store.clone(),
            config,
            cancel,
            trace_notify,
            reset_notify,
            ip_tx,
        );
        app.show_help = true;

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        let store = shared_store.read().await;

        // Should render help popup without panic
        terminal
            .draw(|f| {
                app.draw(f, &store);
            })
            .unwrap();
    }

    /// Test draw with small terminal size (compact mode).
    #[tokio::test]
    async fn test_draw_compact_mode() {
        let shared_store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let app = TuiApp::new(
            shared_store.clone(),
            config,
            cancel,
            trace_notify,
            reset_notify,
            ip_tx,
        );

        // Small terminal triggers compact mode
        let backend = TestBackend::new(60, 20);
        let mut terminal = Terminal::new(backend).unwrap();

        let store = shared_store.read().await;

        // Should handle compact mode without panic
        terminal
            .draw(|f| {
                app.draw(f, &store);
            })
            .unwrap();
    }

    /// Test multiple consecutive draws (simulating the event loop).
    #[tokio::test]
    async fn test_multiple_draws() {
        let shared_store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let reset_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let app = TuiApp::new(
            shared_store.clone(),
            config,
            cancel,
            trace_notify,
            reset_notify,
            ip_tx,
        );

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        // Simulate multiple frames
        for i in 0..5 {
            // Update store data each frame
            {
                let mut store = shared_store.write().await;
                store.inc_icmp_sent();
                store.push_icmp_rtt(10.0 + i as f64);
            }

            // Read and draw
            let store = shared_store.read().await;
            terminal
                .draw(|f| {
                    app.draw(f, &store);
                })
                .unwrap();
        }
    }
}
