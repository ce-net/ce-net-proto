---
name: cell-build
description: Build a ce-net cell, a system of cells, a nested holder cell or a wrapped program so it stays small on a shared mesh - the CES-1 budget, CES-8 nesting, the patterns, the ten measured anti-patterns and the checks to run before saying done. Load before creating or editing any cell, cell.toml, heartbeat, retry loop, inter-cell call or live system.
---

# cell-build

Standards: [CES-1 budget](../../docs/standards/CES-1-budget.md), [CES-8 nesting](../../docs/standards/CES-8-nesting.md).
Long form with the measured cases: [BUILDING-CELLS.md](../../docs/guide/BUILDING-CELLS.md).

## Do

1. Start from the cell template (`cell-forge new-cell <name>` in ce-net): a typed `<name>-api` crate plus the cell crate.
2. Write `[budget]` in `cell.toml` first. Defaults: `idle_cpu_pct = 0.1`, `idle_wakeups_s = 1`, `mem_bytes = "128M"`, `pids = 16`.
   Write only keys that differ; a value above a default carries its reason as a comment on that line.
3. Declare every periodic wake-up as `[[budget.timer]]` with `idle_ms >= 1000`. Block on events (socket, store watch,
   channel) instead of polling. A heartbeat rides an open connection and slows to `idle_ms` when nothing changed.
4. Hold one typed client (one connection) per peer and reuse it. Never connect per call, never shell out to a CLI per call.
5. Retry with exponential backoff plus jitter (100 ms, x2, cap 30 s). Never retry a typed refusal.
6. Pass `hops_left` (decremented) and the deadline on every outbound call; refuse at 0 or past the deadline. Cap
   concurrent outbound calls at `fanout`.
7. Keep state in the state store, bound every cache and log.
8. Start a set of cells as a system with a `ttl_s` lease; write the proof, then stop it.
9. Holder cells (a box with an inner door): export only typed ops; give each crossing link `AllOf(box tags)` scope,
   an expiry, lower depth and only the rights declared for that op (`[box.export.<Op>] inner = [...]`).

## Do not (each was measured on the live system)

| # | Anti-pattern | Measured |
|---|---|---|
| F1 | sub-second sleep or heartbeat while idle | 7 processes, 39% of a core, 2091 wake-ups/s, no reader |
| F2 | new TCP connection per call or heartbeat | 7046 sockets in TIME-WAIT, 2933 to one door |
| F3 | `ce cell call` (a process) per call in a loop | 18 threads started per call |
| F4 | a helper process per cell | 333 supervisors, 27% of the process table |
| F5 | a proof system left running | 72 processes on 9 of 16 cores for 7.5 h |
| F6 | no `[budget]` | nothing to enforce |
| F7/F8 | unbounded cache or log | 2 GB resident; disk at 97% |
| F9 | a thread per connection | 340 threads in one door |
| F10 | fan-out with no hop limit | one system, 72 processes |

## Before reporting done

```sh
cell-check conform .                # rules budget, tight-timer, conn-per-call plus the architecture rules
ces-check manifest cell.toml       # CES-1 manifest check alone (cargo install --git https://github.com/ce-net/ce-net-proto ce-net-proto)
cell-audit idle --secs 60           # after install: your cell must not appear above budget
```

Then stop anything you started as a proof.
