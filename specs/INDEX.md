# INDEX

Navigation for the netprobe specification system. Formats and update rules: [META.md](META.md). Daily workflow: [WORKFLOW.md](WORKFLOW.md).

## Task → Spec

| Task | Read first | Then |
| ---- | ---------- | ---- |
| Understand the architecture before any change | [architecture/layers.md](architecture/layers.md) | [architecture/concurrency.md](architecture/concurrency.md) |
| Add or change a CLI option | [contracts/cli-to-app.md](contracts/cli-to-app.md) | target domain's Configuration section |
| Add a new probe layer | [domains/probing/README.md](domains/probing/README.md) | [contracts/probe-pipeline.md](contracts/probe-pipeline.md), [contracts/jsonl-log-format.md](contracts/jsonl-log-format.md) |
| Modify ICMP behavior | [domains/probing/icmp.md](domains/probing/icmp.md) | [ADR-0002](decisions/0002-hybrid-icmp-strategy.md) |
| Modify DNS behavior | [domains/probing/dns.md](domains/probing/dns.md) | — |
| Modify TCP/TLS/HTTP pipeline | [domains/probing/tcp-tls-http.md](domains/probing/tcp-tls-http.md) | [ADR-0001](decisions/0001-low-level-tls-timing.md) |
| Modify traceroute | [domains/probing/traceroute.md](domains/probing/traceroute.md) | [ADR-0006](decisions/0006-traceroute-startup-privilege-gating.md) |
| Add an anomaly detector | [domains/anomaly-detection.md](domains/anomaly-detection.md) | owning probe loop spec |
| Add a metric / store slot | [domains/metrics-store.md](domains/metrics-store.md) | [contracts/store-readers.md](contracts/store-readers.md) |
| Change the JSONL format | [contracts/jsonl-log-format.md](contracts/jsonl-log-format.md) | [domains/logging.md](domains/logging.md) |
| Add a TUI panel or hotkey | [domains/tui/README.md](domains/tui/README.md) | [domains/tui/panels-and-layout.md](domains/tui/panels-and-layout.md) |
| Modify the sparkline widget | [domains/tui/sparkline.md](domains/tui/sparkline.md) | — |
| Understand locking / shutdown | [architecture/concurrency.md](architecture/concurrency.md) | [contracts/probe-pipeline.md](contracts/probe-pipeline.md) |
| Understand why X is designed this way | [decisions/](decisions/) (ADRs) | domain spec Invariants |
| Change documented behavior | [WORKFLOW.md](WORKFLOW.md) (update protocol) | [META.md](META.md) (formats) |

## Dependency Graph

```
                 main.rs ── app.rs ── tui/*
                    │          │        │
              config.rs        │     store.rs (read)
                               │        ▲
              probe/* (write) ──┼────────┘
                    │           │
                    ├─▶ anomaly.rs ──▶ models.rs
                    └─▶ models.rs      ▲
                                       │
              logger.rs (JSONL out) ───┘
```

Spec-level dependencies: `META.md` defines every template; `INDEX.md` and `WORKFLOW.md` reference all files; contracts rely on architecture invariants; domain specs link to the contracts that bound them; ADRs justify choices referenced by domain specs.

## Directory

```
specs/
├── META.md                                 formats, templates, update protocol
├── INDEX.md                                this file
├── WORKFLOW.md                             build/test commands, task workflows
├── architecture/
│   ├── layers.md                           layer hierarchy, import rules
│   └── concurrency.md                      tasks, channels, shutdown, locking
├── domains/
│   ├── probing/
│   │   ├── README.md                       probe domain overview, loop pattern
│   │   ├── icmp.md                         hybrid ICMP strategy
│   │   ├── dns.md                          resolver + change detection
│   │   ├── tcp-tls-http.md                 L4/L7 pipeline
│   │   └── traceroute.md                   trippy / tracert, privilege gating
│   ├── metrics-store.md                    MetricsStore, ring buffers, aggregates
│   ├── anomaly-detection.md                Welford windows, detector catalog
│   ├── logging.md                          logger task, record models
│   └── tui/
│       ├── README.md                       event loop, hotkeys, lifecycle
│       ├── panels-and-layout.md            panels, proportions, compact mode
│       └── sparkline.md                    braille widget
├── contracts/
│   ├── cli-to-app.md                       CLI → Config → app::run
│   ├── probe-pipeline.md                   loop obligations (store/logger/control)
│   ├── store-readers.md                    TUI + session summary read path
│   └── jsonl-log-format.md                 on-disk schema (external)
└── decisions/
    ├── _template.md                        ADR template
    ├── 0001-low-level-tls-timing.md        socket2+rustls vs HTTP clients
    ├── 0002-hybrid-icmp-strategy.md        unprivileged → raw → subprocess
    ├── 0003-shared-state-architecture.md   RwLock store + mpsc logger
    ├── 0004-jsonl-single-file-logging.md   one JSONL as sole persistence
    ├── 0005-traceroute-privilege-gating.md degrade, never crash
    └── 0006-traceroute-startup-privilege-gating.md startup privilege discovery, accurate flag
```
