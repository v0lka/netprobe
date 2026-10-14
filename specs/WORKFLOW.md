# Specification Workflow

A reference guide for developers and AI agents on using the netprobe specification system. Formats and templates live in [META.md](META.md); navigation in [INDEX.md](INDEX.md).

---

## 1. General Philosophy

These specs document netprobe **as implemented**. `src/` is the source of truth: when a spec and the code disagree, fix the spec. (`.qoder/specs/netprobe-spec.md` is the historical design document in Russian — useful for intent, not authoritative for behavior.)

- Specs are optimized for AI agents: predictable structure, explicit cross-references, no filler.
- Organized by **domains** (probing, metrics store, anomaly detection, logging, TUI), not by directory layout.
- **Contracts** are first-class documents for boundaries: CLI→app, probe pipeline, store readers, and the external JSONL format.

---

## 2. Build, Test, Verify

Commands (mirroring `.github/workflows/ci.yml`; CI runs them on Linux, macOS, Windows):

```bash
cargo fmt -- --check          # formatting gate
cargo clippy -- -D warnings   # lint gate (warnings are errors)
cargo build --release         # build
cargo test                    # unit tests (~300 across modules)
```

Manual smoke test (needs elevated privileges for traceroute on Linux/macOS):

```bash
sudo setcap cap_net_raw+ep target/release/netprobe   # Linux, one-time
netprobe example.com                                  # TUI mode
netprobe 1.1.1.1 -q --log out.jsonl                   # quiet mode
```

Windows: traceroute works without elevation (`tracert.exe`); ICMP uses the subprocess strategy.

---

## 3. Getting Started: Navigation

1. Open [INDEX.md](INDEX.md) → find your task in the Task → Spec table.
2. Start at the domain `README.md` (Purpose / Key Files / Core Types / Flow / Invariants / Extension Points).
3. Drill into the detail file for the component you touch; check the contract if you cross a boundary.

---

## 4. Update Protocol

### When to update

- After any change that alters documented behavior
- After adding/removing interfaces that appear in a contract (each contract ends with a Breaking Change Checklist)
- After changing architectural boundaries or invariants
- After a new architectural decision → create an ADR
- After adding/removing a spec file → update [INDEX.md](INDEX.md)

### How to update

1. Read the current spec fully before modifying
2. Preserve the section format defined in [META.md](META.md)
3. Update cross-references if paths changed
4. Verify claims against the code — never copy stale statements forward
5. Accepted ADRs are immutable; supersede with a new ADR

---

## 5. Workflow for Typical Tasks

### Add a CLI option (e.g. `--cert-warning-days`)

1. Read [contracts/cli-to-app.md](contracts/cli-to-app.md).
2. Add `DEFAULT_*` to `Config` (`src/config.rs`), the `#[arg]` to `Cli` (`src/main.rs`), map in `into_config`.
3. Wire the value through `app.rs` into the consuming loop/panel.
4. Update: `contracts/cli-to-app.md` (defaults table), the domain spec's Configuration section, `docs/USER_GUIDE.md`.
5. `cargo clippy -- -D warnings && cargo test`

### Add a probe layer (e.g. QUIC handshake timing)

1. Read [domains/probing/README.md](domains/probing/README.md) (loop template) and [contracts/probe-pipeline.md](contracts/probe-pipeline.md).
2. Add `src/probe/<name>.rs`: `Prober` struct + `<name>_probe_loop` honoring `cancel`, writing the store, sending `LogRecord`s.
3. Add the record struct + `LogRecord` variant in `src/models.rs`; store slots in `src/store.rs`.
4. Spawn the task in `app.rs`; add CLI knobs if needed (see the CLI task above).
5. Update: probing README (catalog + config table), `contracts/jsonl-log-format.md`, `domains/metrics-store.md`, INDEX if new files.
6. Add unit tests for parsing/classification next to the implementation (see `src/probe/icmp.rs` tests for the pattern).

### Add an anomaly detector (e.g. `mos_degradation`)

1. Read [domains/anomaly-detection.md](domains/anomaly-detection.md).
2. Add the detector method to `AnomalyDetector` (`src/anomaly.rs`) — pure logic only.
3. Call it from the owning probe loop after the store push; route the event through `store.push_event` + `to_event_record` → `log_tx`.
4. Update the detector catalog table and the `event` record list in `contracts/jsonl-log-format.md`.

### Modify the JSONL format

1. Read [contracts/jsonl-log-format.md](contracts/jsonl-log-format.md) — it is an **external** contract.
2. Change serde structs in `src/models.rs`; prefer additive optional fields.
3. Update the format contract, `domains/logging.md`, and `docs/USER_GUIDE.md` (log format section); flag breaking changes in release notes.

### Add a TUI panel

1. Read [domains/tui/README.md](domains/tui/README.md) and [domains/tui/panels-and-layout.md](domains/tui/panels-and-layout.md).
2. Add the widget module in `src/tui/`; render it in `TuiApp::draw`; extend `DashboardLayout::build` (both constraint branches + layout tests).
3. If scrollable: add a `FocusPanel` variant + scroll state in `TuiApp`, wire `Tab`/arrows in `handle_key`.
4. Update the panels table in the TUI specs.

### Make an architectural decision

1. Check [decisions/](decisions/) for existing ADRs.
2. Copy `decisions/_template.md` → `NNNN-kebab-slug.md`; fill all five sections; state rejected alternatives.
3. Update INDEX.md and any domain spec that references the decision.

---

## 6. Content Rules

- Invariants are stated affirmatively ("The loop always sends one record per attempt") — never negatively.
- Code paths in Key Files are repo-root-relative backtick paths.
- Reference tables (interfaces, defaults, detectors) use markdown tables.
- Flows/architecture use ASCII diagrams that render in monospace.
- Divergences from `.qoder/specs/netprobe-spec.md` are called out explicitly in a blockquote `> Note:` (see [domains/probing/traceroute.md](domains/probing/traceroute.md) for the pattern).

---

## 7. Anti-Patterns

| Anti-pattern | Why it's bad | Do instead |
| ------------ | ------------ | ---------- |
| Writing specs from imagination after a code change | Spec/code drift | Verify every claim with `rg`/read before writing |
| Editing an accepted ADR | Loses decision history | New ADR + `Superseded by` link |
| Skipping the Breaking Change Checklist | Silent consumer breakage | Walk the checklist before merging |
| Mirroring `src/` file structure in specs | One file participates in many domains | Organize by domain |
| Filler prose for human readers | Wastes agent context | Necessary and sufficient only |

---

## 8. Quick Start (TL;DR)

1. Learn → [INDEX.md](INDEX.md) → task table → spec
2. Change code → domain spec + contract → implement → update spec → `cargo clippy -- -D warnings && cargo test`
3. New decision → ADR from template → INDEX.md
4. New spec file → format from [META.md](META.md) → INDEX.md
