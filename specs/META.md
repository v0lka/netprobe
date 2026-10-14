# Specification System

This document defines the format, rules, and procedures for creating and maintaining netprobe project specifications. It is the source of truth for how specs are structured.

## Purpose

Specifications provide AI coding agents with deterministic context about system behavior, interfaces, and architectural decisions. They enable agents to make safe, informed changes without extensive codebase exploration.

## Principles

1. **Code is the source of truth.** These specs document the system as implemented. A discrepancy between spec and code is resolved in favor of the code — fix the spec.
2. **Self-standing documents** — every spec can be read without this conversation. No "see chat" references.
3. **Agent-optimized** — predictable structure, explicit cross-references, no filler prose. Every section has a purpose.
4. **Living documents** — updated after code changes that alter documented behavior. Never silently drifting.
5. **Domain-based** — organized by conceptual domains (probing, metrics store, anomaly detection, logging, TUI), NOT by directory structure alone.
6. **Contracts are first-class** — cross-boundary interfaces (CLI → app, probe pipeline, store readers, JSONL format) deserve their own documents.
7. **Language: English.** Domain terms (ring buffer, sparkline, MOS, probe) stay in English.

## File Organization

```
specs/
├── META.md                                 this file
├── INDEX.md                                navigation: task -> spec file(s)
├── WORKFLOW.md                             reference guide for spec system usage
│
├── architecture/                           system-level concerns
│   ├── layers.md                           layer hierarchy, import rules, responsibilities
│   └── concurrency.md                      tokio task model, channels, shutdown, lock discipline
│
├── domains/                                by conceptual domain
│   ├── probing/                            all network probe layers
│   │   ├── README.md                       domain overview: Prober pattern, probe loops
│   │   ├── icmp.md                         ICMP prober: hybrid strategy, fallback chain
│   │   ├── dns.md                          DNS prober: resolution, change detection
│   │   ├── tcp-tls-http.md                 TCP connect + TLS handshake + HTTP healthcheck pipeline
│   │   └── traceroute.md                   traceroute prober: trippy, privilege gating, route diff
│   ├── metrics-store.md                    MetricsStore: ring buffers, aggregates, IP switching
│   ├── anomaly-detection.md                sliding Welford, detectors, thresholds, warm-up
│   ├── logging.md                          JSONL logger, LogRecord enum, serde models
│   └── tui/                                terminal dashboard
│       ├── README.md                       TUI loop, events, terminal lifecycle, hotkeys
│       ├── panels-and-layout.md            panel set, layout proportions, responsive rules
│       └── sparkline.md                    custom braille sparkline widget
│
├── contracts/                              interfaces between layers
│   ├── cli-to-app.md                       Cli -> Config -> app::run boundary
│   ├── probe-pipeline.md                   probe task obligations (store + logger + cancellation)
│   ├── store-readers.md                    read-path contract: TUI and session_end consumers
│   └── jsonl-log-format.md                 on-disk JSONL schema (external interface)
│
└── decisions/                              Architecture Decision Records
    ├── _template.md                        ADR template
    ├── 0001-low-level-tls-timing.md        socket2 -> rustls -> raw HTTP instead of reqwest
    ├── 0002-hybrid-icmp-strategy.md        unprivileged -> raw -> subprocess fallback chain
    ├── 0003-shared-state-architecture.md   Arc<RwLock<MetricsStore>> + mpsc logger
    ├── 0004-jsonl-single-file-logging.md   one structured log file as sole persistence
    ├── 0005-traceroute-privilege-gating.md per-trace privilege gating (superseded by 0006)
    └── 0006-traceroute-startup-privilege-gating.md startup privilege discovery, accurate traceroute_available
```

## Naming Conventions

- Files: `kebab-case.md`
- Directories within `domains/`: created when a domain requires multiple files
- `README.md` inside a domain directory: overview and entry point for that domain
- `_template.md` prefix: template files (not actual specs)
- ADR files: `NNNN-kebab-case-slug.md` (four-digit number, kebab-case slug)
- Spec files reference source code as backtick paths from repo root, e.g. `src/probe/icmp.rs`

## Document Formats

### Domain README (`domains/*/README.md` or `domains/*.md`)

Required sections in order:

```markdown
# [Domain Name]

## Purpose

1-3 sentences. What this domain does in the system.

## Key Files

- `path/from/repo/root/file.ext` — role description

## Core Types

Key type definitions (code blocks) with brief explanations.

## Flow

ASCII diagram or numbered sequence showing the primary happy path.

## Invariants

Bullet list of properties that ALWAYS hold. Use affirmative phrasing.

## Configuration

Key parameters from configuration with defaults and valid values.

## Extension Points

How to add new behavior without breaking existing functionality.

## Related Specs

- [link](relative/path.md) — context of relationship
```

### Domain Detail (`domains/*/<name>.md`)

For individual components within a domain:

```markdown
# [Component Name]

## Role

1 sentence: what this component does within its domain.

## Key Files

- `path/to/file.ext` — description

## Behavior

Detailed description. May include:
- State machines (ASCII)
- Decision tables
- Pseudocode
- Sequence diagrams

## Error Handling

How this component handles and propagates errors.

## Invariants

Properties that always hold for this component.

## Related Specs

- [link](relative/path.md) — relationship context
```

### Contract (`contracts/*.md`)

```markdown
# Contract: [Layer A] <-> [Layer B]

## Boundary Rule

One sentence: direction of dependency and what is NOT allowed.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |

## Initialization

How components are wired together at startup.

## Data Flow Across Boundary

What data crosses the boundary, in what form, in which direction.

## Error Propagation

Rules for wrapping/transforming errors at this boundary.

## Breaking Change Checklist

If you change X, you MUST also update Y.
```

### Architecture (`architecture/*.md`)

```markdown
# [Topic]

## Context

Why this architectural aspect matters.

## [Main Content]

Diagrams, rules, descriptions. Structure varies by topic.

## Invariants

Architectural rules that must never be violated.

## Anti-Patterns

What NOT to do, with brief explanation of why.
```

### ADR (`decisions/NNNN-slug.md`)

```markdown
# ADR-NNNN: [Title]

## Status

Accepted | Superseded by [NNNN](./NNNN-slug.md)

## Context

The problem or question that required a decision.

## Decision

What was decided.

## Consequences

Positive and negative impacts on the codebase.

## Alternatives Considered

What was evaluated and why it was rejected.

## Related Specs

Links to the specs affected by or related to this decision.
```

## Cross-References

- Always use relative paths from `specs/` directory
- Format: `[display text](relative/path.md)`
- For intra-file section references: `[display text](relative/path.md#section-name)` (lowercase, hyphens)
- When referencing source code: backtick path from repo root, e.g. `src/store.rs`

## Update Protocol

### When to update specs

- After any change that alters documented behavior
- After adding/removing/renaming interfaces that appear in a contract
- After changing architectural boundaries or invariants
- After adding a CLI option (update `contracts/cli-to-app.md` and the domain's Configuration section)
- After changing the JSONL schema (update `contracts/jsonl-log-format.md`, `domains/logging.md`, and bump docs)
- After making a new architectural decision (create ADR)

### How to update

1. Read the current spec fully before modifying
2. Preserve the document format (sections, ordering) defined in this META.md
3. Update cross-references if file paths changed
4. After adding or removing a spec file, update `INDEX.md`
5. ADRs with `Status: Accepted` are immutable; create a new ADR to supersede
6. Verify claims against the current code — never copy stale statements forward

### Validation checklist

- [ ] All sections from the template are present
- [ ] Cross-references point to existing files
- [ ] Code paths in Key Files are accurate
- [ ] Invariants are stated affirmatively
- [ ] INDEX.md reflects the current file set
