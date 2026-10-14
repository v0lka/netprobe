//! CLI integration test: run the real binary end-to-end and validate the
//! JSONL session flow (`session_start` → probe records → `session_end`).
//!
//! Unix only: graceful shutdown is triggered with SIGINT via the system `kill`
//! utility (mirrors Ctrl+C). The test needs no elevated privileges — the
//! monitor works unprivileged and traceroute is simply unavailable.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use trippy_privilege::Privilege;

const RUN_DURATION: Duration = Duration::from_secs(4);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

/// RAII guard: kills the child if it is still alive when the guard drops, so
/// a failing assertion cannot orphan a quietly probing `netprobe` process
/// (whose `TempDir` log is unlinked while the orphan still holds the
/// descriptor). On the happy path the child has already been reaped by
/// `try_wait`, and the failed `kill` is the no-op.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if self.0.kill().is_ok() {
            // Reap the killed child so no zombie lingers
            let _ = self.0.wait();
        }
    }
}

#[test]
fn test_cli_session_lifecycle_jsonl() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let log_path = temp_dir.path().join("session.jsonl");

    let child = Command::new(env!("CARGO_BIN_EXE_netprobe"))
        .arg("127.0.0.1")
        .arg("--quiet")
        .arg("--log")
        .arg(&log_path)
        .args(["--interval-icmp", "200"])
        .args(["--interval-dns", "1"])
        .args(["--interval-tcp", "1"])
        .arg("--no-http")
        .arg("--no-tls")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn netprobe binary");
    let mut child = KillOnDrop(child);

    // Let the session collect probes.
    std::thread::sleep(RUN_DURATION);

    // Graceful stop with SIGINT (mirrors Ctrl+C).
    let pid = child.0.id().to_string();
    let sent = Command::new("kill")
        .args(["-INT", &pid])
        .output()
        .expect("run kill");
    assert!(
        sent.status.success(),
        "failed to send SIGINT to pid {pid}: {}",
        String::from_utf8_lossy(&sent.stderr)
    );

    // Wait for the graceful shutdown to finish.
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("poll child process") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "netprobe did not shut down within {SHUTDOWN_TIMEOUT:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(status.success(), "netprobe exited with {status}");

    // Parse the JSONL log: every line must be a valid tagged record.
    let file = std::fs::File::open(&log_path).expect("log file exists after run");
    let mut types: Vec<String> = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.expect("read log line");
        let value: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("line {} is not valid JSON: {e}", i + 1));
        let kind = value["type"]
            .as_str()
            .unwrap_or_else(|| panic!("line {} has no type tag: {}", i + 1, value["type"]));
        types.push(kind.to_string());
    }

    assert!(
        types.len() >= 5,
        "expected at least 5 records, got {}",
        types.len()
    );
    assert_eq!(
        types
            .iter()
            .filter(|t| t.as_str() == "session_start")
            .count(),
        1,
        "exactly one session_start expected"
    );
    assert_eq!(
        types.iter().filter(|t| t.as_str() == "session_end").count(),
        1,
        "exactly one session_end expected"
    );
    assert_eq!(
        types.first().map(String::as_str),
        Some("session_start"),
        "first record must be session_start"
    );
    assert_eq!(
        types.last().map(String::as_str),
        Some("session_end"),
        "last record must be session_end"
    );

    let icmp_count = types.iter().filter(|t| t.as_str() == "icmp").count();
    assert!(icmp_count >= 1, "expected at least one icmp record");
    assert!(
        types.iter().any(|t| t.as_str() == "dns"),
        "expected at least one dns record"
    );
    assert!(
        types.iter().any(|t| t.as_str() == "tcp"),
        "expected at least one tcp record"
    );

    // Validate the session_start schema.
    let content = std::fs::read_to_string(&log_path).expect("read log file");
    let first: serde_json::Value =
        serde_json::from_str(content.lines().next().expect("non-empty log")).unwrap();
    assert_eq!(first["target"], "127.0.0.1");
    assert!(
        first["traceroute_available"].is_boolean(),
        "traceroute_available must be a boolean"
    );
    assert!(
        first["config"]["icmp_strategy"].is_string(),
        "config.icmp_strategy must be a string"
    );
    // `traceroute_available` must mirror the binary's own privilege gate —
    // `TracerouteProber::new(...).is_ok()`, i.e. `CAP_NET_RAW` in the
    // effective set on Linux and the euid elsewhere — rather than the uid, so
    // a capability-bearing (setcap) test binary does not produce a spurious
    // failure while running unprivileged.
    let has_privileges = Privilege::discover()
        .expect("privilege discovery succeeds")
        .has_privileges();
    assert_eq!(
        first["traceroute_available"], has_privileges,
        "traceroute_available must match the binary's privilege gate"
    );
}
