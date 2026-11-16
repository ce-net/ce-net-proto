# Building cells that stay small

For people and agents writing ce-net cells. The rules are in [CES-1](../standards/CES-1-budget.md) and
[CES-8](../standards/CES-8-nesting.md); this guide is the why and the how. The agent version is
[skills/cell-build](../../skills/cell-build/SKILL.md).

## The cost model

A cell that is idle should cost nothing: no CPU, no wake-ups, no sockets beyond one listener. A machine hosts
hundreds of cells, and a mesh many machines, so a cell that wakes 10 times a second costs a core across a few
hundred instances. The budget numbers in CES-1 are set so that 1000 idle cells use about one core in total.

## Patterns

**Declare first.** Write the `[budget]` table before the code. If you need more than a default, the comment you
must write on that line is the design review.

**Block, do not poll.** Every loop waits on something that wakes it with work: an accepted connection, a store
watch, a channel. A timer is for work that is truly periodic, and it is declared:

```toml
[[budget.timer]]
name = "replog-heartbeat"
idle_ms = 1000   # nothing to replicate: once a second
busy_ms = 100    # writes in flight: ten times a second
```

**Adaptive heartbeat.** A replica that sends a heartbeat every 100 ms forever burns 10 wake-ups a second per peer
while nobody writes. Send at `busy_ms` while writes flow, back off to `idle_ms` when the log is unchanged, and
scale the leader timeout with the period actually used.

**One connection per peer.** Open it once, multiplex calls over it, close it after 300 s unused. A connection per
call leaves a socket in TIME-WAIT for a minute after each call, and a thread per connection on the server.

**Typed client, not a CLI.** Calling another cell by starting `ce cell call` in a loop pays a process start, a
lookup and a connection every time. Hold the typed client from the other cell's `-api` crate.

**Back off, do not hammer.** `100 ms * 2^n` with jitter, capped at 30 s. A typed refusal is an answer, not a
failure: do not retry it.

**Bound the tree.** Every call carries `hops_left` and a deadline; pass them on. This is what stops a nested or
recursive network from looping.

**Systems end.** A proof starts its cells as a system with a `ttl_s` and stops when the proof is written. A
system that should stay public names an owner and an end date.

## Nested cells

A holder cell runs a box with an inner door and inner cells; any inner cell may hold a box of its own. The holder
exports typed ops only. For each op it declares the abilities the inside needs, and the link it adds for the
inner door is scoped to that box instance, expires no later than its own, and can delegate one level less. So a
capability can only shrink on the way in, however deep the nesting, and stopping the holder ends everything in it.

## Checks

- `cell-check conform <repo>`: static rules `budget` (C1.1, C1.2), `tight-timer` (a sleep or interval under 1 s
  in code), `conn-per-call` (a raw connect or a CLI call to another cell in code), plus the architecture rules.
- `ces-check manifest cell.toml` (from ce-net-proto): the CES-1 manifest check alone.
- `cell-audit idle`: samples every running process on a node for CPU, wake-ups, threads, memory and connections
  opened, groups them by service, ranks them against the CES-1 defaults and names the failure class.
