# CES-2: cell lifecycle (v0.1 draft)

A cell runs only while someone needs it. It starts on its first call, stops when idle, and a set of cells
started together for a proof ends on its own. Nothing starts at boot unless it says why.

Why: on one node of the live system (2026-11-16) 13 units of one shop system, a 7-unit wiki and four demo
systems ran for hours with no caller; one earlier demo held 72 processes on 9 of 16 cores for 7.5 h. Each was
started as a plain unit with no lease, no owner and no budget for the whole set.

## 1. The `[lifecycle]` table

```toml
[lifecycle]                   # CES-2 v0.1. Every key has the default shown; write only what differs.
idle_stop_s      = 300        # stop after this long idle (CES-1 rule 1 defines idle); 30..=86400
start_timeout_ms = 2000       # first health answer after start; hard limit 30000
drain_ms         = 10000      # stop: in-flight calls get this long after SIGTERM; 0..=10000
keep             = false      # true: started at boot and never idle-stopped
keep_reason      = ""         # MUST be non-empty when keep = true
```

An unknown key is an error. A cell with no `[lifecycle]` table gets the defaults.

## 2. States

`installed`, `starting`, `live`, `idle`, `stopped`, `frozen`, `failed`. The runtime moves between them only on
these events, and each move is one typed event line (CES-3 rule 2):

| From | Event | To |
|---|---|---|
| installed, stopped | `call` | starting |
| starting | `healthy` | live |
| starting | `start_timeout` | failed |
| live | `calls_done` | idle |
| idle | `call` | live |
| idle | `idle_for(s)`, `s >= idle_stop_s`, `keep = false` | stopped |
| live, idle | `over_budget(3)` (CES-1 rule 8: three idle windows in a row) | frozen |
| frozen | `thaw` (owner) | idle |
| live, idle, frozen, starting | `stop` | stopped |
| live, idle, starting | `crash` | failed |
| failed | `call` | starting (after the restart backoff) |
| live, idle, frozen | `lease_expired` (its system's) | stopped |

Any other pair is refused (`bad_transition`) and the state does not change. `idle_for(s)` below `idle_stop_s`,
or with `keep = true`, leaves the cell idle. `over_budget(n)` with `n < 3` leaves it where it is.

## 3. Rules

1. **On-demand start.** A cell MUST be startable by its first call and SHOULD answer health within 2 s; past
   `start_timeout_ms` it is `failed`.
2. **Nothing at boot.** The runtime MUST NOT start a cell at boot unless `keep = true` with a `keep_reason`.
3. **Idle stop.** The runtime MUST stop a cell after `idle_stop_s` idle. This is the default on every node, not
   a per-machine switch. A kept cell is listed by the audit (CES-3 rule 3) with its reason.
4. **Stop.** SIGTERM, drain in-flight calls up to `drain_ms`, then the runtime kills the cell's cgroup, so no
   child survives.
5. **Never frozen.** The node's state store and the runtime itself are exempt from freeze and idle stop; a
   runtime MUST NOT freeze or stop a store replica another node's gate reads.
6. **Systems.** Cells started together are a system, described by `system.toml` (section 4), started through
   the runtime (never as hand-made units) so its lease and budget apply. A live system has a lease of `ttl_s`
   (default 3600, at most 86400); a real call to one of its cells or its owner renews it; at expiry the
   runtime stops every cell of the system. One that stays public declares `keep_until` (a date) and `owner`.
7. **Parents.** Stopping a cell stops everything it started (CES-8: this is how a nested network ends).

## 4. `system.toml`

```toml
[system]
name       = "shop-proof"
owner      = "person:test-shop-1"
ttl_s      = 3600             # 60..=86400; ignored when keep_until is set
keep_until = "2026-12-31"     # optional; needs owner
cells      = ["shop.orders", "shop.inventory"]
[system.budget]               # for the whole set
procs        = 32
idle_cpu_pct = 0.3
mem_bytes    = "512M"
```

The members' CES-1 budgets MUST fit the system's: the sum of their `pids` is at most `procs`, of their
`idle_cpu_pct` at most the system's, of their `mem_bytes` at most the system's.

## 5. Checks

| Check | Rule | Fails when |
|---|---|---|
| C2.0 | 1-3 | `[lifecycle]` is not a table, a key is unknown or out of range, `keep = true` without `keep_reason` |
| C2.1 | 1 | the first call does not start the cell, or health comes later than `start_timeout_ms` (later than 2000 ms is a warning) |
| C2.2 | 3 | an idle, not-kept cell is still running `idle_stop_s + 60` s after its last call |
| C2.3 | 4 | a process is left in the cell's cgroup after stop |
| C2.4 | 6 | a system is still running past its lease; or its members' budgets do not fit (static) |
| C2.5 | 2 | a cell without `keep` was running before its first call after boot |

## 6. Conformance and vectors

The Rust crate reproduces every vector (`ce_net_proto::ces2`, `cargo test --test ces2`; CLI
`ces-check lifecycle <cell.toml>` and `ces-check system <system.toml>`).

- `tests/ces2/manifests.json`: `{name, toml, expect}`, `expect` `"valid"` or `{"fail": "C2.0", "line": n}`.
- `tests/ces2/transitions.json`: `{name, lifecycle, from, event, expect}`, `expect` a state or `"refused"`.
- `tests/ces2/systems.json`: `{name, system, members, now_s, started_s, renewed_s, expect}`; `members` are CES-1
  `[budget]` texts; `expect` maps `C2.4` to `pass` or `fail` and `due` to whether the lease has ended.
- `tests/ces2/runs.json`: `{name, lifecycle, run, expect}`: a recorded run (start latency, last call, stop
  time, processes left) and the outcome of C2.1, C2.2, C2.3 and C2.5.
