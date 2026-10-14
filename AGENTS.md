# AGENTS.md

Instructions for AI coding agents working in this repository.

## Project

netprobe — a Rust console utility for deep network connection-quality monitoring with a btop-style TUI dashboard and structured JSONL logging. It monitors a single target across four layers (ICMP, DNS, TCP/TLS/HTTP) plus traceroute. Linux, macOS, Windows; Rust edition 2024; ratatui + crossterm + tokio.

## Build & Verify

```bash
cargo fmt -- --check
cargo clippy -- -D warnings
cargo test
cargo build --release
```

CI (`.github/workflows/ci.yml`) runs all four on Linux, macOS, and Windows — keep them green.

## Specifications

Detailed system specs live in `specs/`. Before making structural changes, read the relevant spec:

- Start with `specs/INDEX.md` to find the right document for your task.
- `specs/META.md` defines spec formats and update rules.
- `specs/WORKFLOW.md` has step-by-step workflows for typical tasks (new CLI option, new probe layer, new anomaly detector, JSONL changes, new TUI panel).

Rules:

- The code in `src/` is the source of truth; if a spec disagrees with the code, fix the spec.
- After changing documented behavior, update the affected specs in the same change.
- Boundary changes require walking the Breaking Change Checklist of the affected contract in `specs/contracts/`.
- New architectural decisions get an ADR in `specs/decisions/` (template there).

## Conventions

- Rust edition 2024, single crate, `cargo fmt`/`clippy -D warnings` clean.
- Probe errors are never fatal — statuses/events, not panics; only startup failures (log file, ICMP init, DNS resolve) abort with `anyhow`.
- One JSONL record per probe attempt, schemas owned solely by `src/models.rs`.
- The TUI reads the shared store; it never writes metrics or calls probers directly.
