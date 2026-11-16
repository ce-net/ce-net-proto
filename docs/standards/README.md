# ce-net standards (CES)

Numbered, versioned standards for cells: what a cell must declare and do so that many of them, written by
anyone, can share machines and a mesh. Each has RFC 2119 words, a conformance section naming its checks, and
vectors any implementation can run. The process is CES-0.

| No. | Standard | Version | Vectors | Reference checkers |
|---|---|---|---|---|
| [CES-0](CES-0-process.md) | Process: numbering, versions, vectors, check ids | v0.1 | - | - |
| [CES-1](CES-1-budget.md) | Cell resource budget | v0.1 draft | [`tests/ces1/`](../../tests/ces1) | Rust `ces1`, CLI `ces-check` |
| CES-2 | Cell lifecycle (on-demand start, idle stop, leases on live systems) | planned | | |
| CES-3 | Cell observability (`CellStat`, `NodeBudget`) | planned | | |
| CES-4 | Cell container (isolation classes, metering, typed boundary) | planned | | |
| CES-5 | Run records and metering receipts | planned | | |
| CES-6 | Offers, pricing and settlement | planned | | |
| CES-7 | Wrapped software | planned | | |
| [CES-8](CES-8-nesting.md) | Nested cells and recursive capabilities | v0.1 draft | [`tests/ces8/`](../../tests/ces8) | Rust `ces8` |

The capability token itself ([TOKEN-FORMAT.md](../TOKEN-FORMAT.md), [CAPABILITY-PROGRAMS.md](../CAPABILITY-PROGRAMS.md))
and CAL ([CAL.md](../CAL.md)) are referenced by these standards, not renumbered.

A guide for people and agents building cells to these standards: [docs/guide/BUILDING-CELLS.md](../guide/BUILDING-CELLS.md);
the agent skill: [skills/cell-build](../../skills/cell-build/SKILL.md).
