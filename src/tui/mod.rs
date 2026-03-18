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
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
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
    /// Channel for IP address changes
    ip_change_tx: tokio::sync::watch::Sender<std::net::IpAddr>,
    /// Theme
    theme: Theme,
    /// Help popup visible
    show_help: bool,
    /// Last frame time for FPS calculation
    last_frame: Instant,
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
        ip_change_tx: tokio::sync::watch::Sender<std::net::IpAddr>,
    ) -> Self {
        Self {
            store,
            config,
            cancel,
            trace_notify,
            ip_change_tx,
            theme: Theme::new(),
            show_help: false,
            last_frame: Instant::now(),
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
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

        // Setup panic hook to restore terminal
        let original_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
            original_hook(info);
        }));

        // Create backend and terminal
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Main loop
        let result = self.run_loop(&mut terminal).await;

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

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
                self.last_frame = now;
            }

            // Handle events with timeout
            let timeout = draw_interval.saturating_sub(now.duration_since(last_draw));
            if crossterm::event::poll(timeout)?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
                && self.handle_key(key.code).await?
            {
                break;
            }
        }

        Ok(())
    }

    /// Handle keyboard input
    /// Returns true if the app should exit
    async fn handle_key(&mut self, key: KeyCode) -> anyhow::Result<bool> {
        match key {
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
                let mut store = self.store.write().await;
                store.reset();
            }

            // Toggle help
            KeyCode::Char('?') => {
                self.show_help = !self.show_help;
            }

            // Scroll up
            KeyCode::Up => match self.focused_panel {
                FocusPanel::Traceroute => {
                    if self.trace_scroll > 0 {
                        self.trace_scroll -= 1;
                    }
                }
                FocusPanel::Events => {
                    self.events_auto_scroll = false;
                    if self.events_scroll > 0 {
                        self.events_scroll -= 1;
                    }
                }
                FocusPanel::Logs => {
                    self.logs_auto_scroll = false;
                    if self.logs_scroll > 0 {
                        self.logs_scroll -= 1;
                    }
                }
            },

            // Scroll down
            KeyCode::Down => match self.focused_panel {
                FocusPanel::Traceroute => {
                    self.trace_scroll += 1;
                }
                FocusPanel::Events => {
                    self.events_auto_scroll = false;
                    self.events_scroll += 1;
                }
                FocusPanel::Logs => {
                    self.logs_auto_scroll = false;
                    self.logs_scroll += 1;
                }
            },

            // Tab to switch focus
            KeyCode::Tab => {
                self.focused_panel = match self.focused_panel {
                    FocusPanel::Traceroute => FocusPanel::Events,
                    FocusPanel::Events => FocusPanel::Logs,
                    FocusPanel::Logs => FocusPanel::Traceroute,
                };
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
            KeyCode::Esc => {
                if self.show_help {
                    self.show_help = false;
                }
            }

            _ => {}
        }

        Ok(false)
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
            ↑/↓         Scroll events/trace panels\n\
            Tab         Switch focus between panels\n\
            ?           Toggle this help\n\
            Esc         Close help\n\n\
            Ctrl+C      Quit application\n\n\
            Press any key to close..."
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
    ip_change_tx: tokio::sync::watch::Sender<std::net::IpAddr>,
) -> anyhow::Result<()> {
    let mut app = TuiApp::new(store, config, cancel, trace_notify, ip_change_tx);
    app.run().await
}

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
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let app = TuiApp::new(store, config, cancel, trace_notify, ip_tx);

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
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(store, config, cancel.clone(), trace_notify, ip_tx);

        let should_exit = app.handle_key(KeyCode::Char('q')).await.unwrap();
        assert!(should_exit);
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn test_handle_key_help() {
        let store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(store, config, cancel, trace_notify, ip_tx);

        assert!(!app.show_help);
        let should_exit = app.handle_key(KeyCode::Char('?')).await.unwrap();
        assert!(!should_exit);
        assert!(app.show_help);

        // Toggle off
        let should_exit = app.handle_key(KeyCode::Char('?')).await.unwrap();
        assert!(!should_exit);
        assert!(!app.show_help);
    }

    #[tokio::test]
    async fn test_handle_key_esc() {
        let store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(store, config, cancel, trace_notify, ip_tx);

        // First enable help
        app.show_help = true;

        // Esc should close help
        let should_exit = app.handle_key(KeyCode::Esc).await.unwrap();
        assert!(!should_exit);
        assert!(!app.show_help);
    }

    #[tokio::test]
    async fn test_handle_key_scroll() {
        let store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(store, config, cancel, trace_notify, ip_tx);

        // Initial state - focused on Logs
        assert_eq!(app.logs_scroll, 0);
        assert!(app.logs_auto_scroll);

        // Scroll down
        let _ = app.handle_key(KeyCode::Down).await.unwrap();
        assert_eq!(app.logs_scroll, 1);
        assert!(!app.logs_auto_scroll); // Auto-scroll disabled

        // Scroll up
        let _ = app.handle_key(KeyCode::Up).await.unwrap();
        assert_eq!(app.logs_scroll, 0);
    }

    #[tokio::test]
    async fn test_handle_key_tab_focus() {
        let store = create_test_store();
        let config = create_test_config();
        let cancel = CancellationToken::new();
        let trace_notify = std::sync::Arc::new(Notify::new());
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(store, config, cancel, trace_notify, ip_tx);

        // Initial focus is Logs
        assert!(matches!(app.focused_panel, FocusPanel::Logs));

        // Tab switches to Traceroute
        let _ = app.handle_key(KeyCode::Tab).await.unwrap();
        assert!(matches!(app.focused_panel, FocusPanel::Traceroute));

        // Tab switches to Events
        let _ = app.handle_key(KeyCode::Tab).await.unwrap();
        assert!(matches!(app.focused_panel, FocusPanel::Events));

        // Tab switches back to Logs
        let _ = app.handle_key(KeyCode::Tab).await.unwrap();
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
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let app = TuiApp::new(shared_store.clone(), config, cancel, trace_notify, ip_tx);

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
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let app = TuiApp::new(shared_store.clone(), config, cancel, trace_notify, ip_tx);

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
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        // Populate the store with some data
        {
            let mut store = shared_store.write().await;
            store.inc_icmp_sent();
            store.push_icmp_rtt(10.5);
            store.push_dns_resolve(5.2);
            store.push_tcp_connect(15.3);
        }

        let app = TuiApp::new(shared_store.clone(), config, cancel, trace_notify, ip_tx);

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
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let mut app = TuiApp::new(shared_store.clone(), config, cancel, trace_notify, ip_tx);
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
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let app = TuiApp::new(shared_store.clone(), config, cancel, trace_notify, ip_tx);

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
        let (ip_tx, _ip_rx) = create_test_ip_channel();

        let app = TuiApp::new(shared_store.clone(), config, cancel, trace_notify, ip_tx);

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
