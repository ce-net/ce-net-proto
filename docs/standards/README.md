# ce-net standards (CES)

Numbered, versioned standards for cells: what a cell must declare and do so that many of them, written by
anyone, can share machines and a mesh. Each has RFC 2119 words, a conformance section naming its checks, and
vectors any implementation can run. The process is CES-0.

| No. | Standard | Version | Vectors | Reference checkers |
|---|---|---|---|---|
| [CES-0](CES-0-process.md) | Process: numbering, versions, vectors, check ids | v0.1 | - | - |
| [CES-1](CES-1-budget.md) | Cell resource budget | v0.1 draft | [`tests/ces1/`](../../tests/ces1) | Rust `ces1`, CLI `ces-check` |
| [CES-2](CES-2-lifecycle.md) | Cell lifecycle (on-demand start, idle stop, leases on live systems) | v0.1 draft | [`tests/ces2/`](../../tests/ces2) | Rust `ces2`, CLI `ces-check lifecycle`, `ces-check system` |
| [CES-3](CES-3-observability.md) | Cell observability (measured from outside, `node.budget@1`, trace and hops) | v0.1 draft | [`tests/ces3/`](../../tests/ces3) | Rust `ces3` |
| [CES-4](CES-4-container.md) | Cell container (isolation classes chosen by signer, fail closed, typed boundary) | v0.1 draft | [`tests/ces4/`](../../tests/ces4) | Rust `ces4` |
| [CES-5](CES-5-run-records.md) | Run records and metering receipts (canonical hash, Ed25519, chained) | v0.1 draft | [`tests/ces5/`](../../tests/ces5) | Rust `ces5`; golden hash from Python `json` + `hashlib` |
| [CES-6](CES-6-market.md) | Offers, orders and settlement in internal units (spend as a capability) | v0.1 draft | [`tests/ces6/`](../../tests/ces6) | Rust `ces6` |
| [CES-7](CES-7-wrapped.md) | Wrapped software (detect, plan, up; rights from verbs; budget from the run) | v0.1 draft | [`tests/ces7/`](../../tests/ces7) | Rust `ces7` |
| [CES-8](CES-8-nesting.md) | Nested cells and recursive capabilities | v0.1 draft | [`tests/ces8/`](../../tests/ces8) | Rust `ces8` |

The capability token itself ([TOKEN-FORMAT.md](../TOKEN-FORMAT.md), [CAPABILITY-PROGRAMS.md](../CAPABILITY-PROGRAMS.md))
and CAL ([CAL.md](../CAL.md)) are referenced by these standards, not renumbered.

A guide for people and agents building cells to these standards: [docs/guide/BUILDING-CELLS.md](../guide/BUILDING-CELLS.md);
the agent skill: [skills/cell-build](../../skills/cell-build/SKILL.md).
