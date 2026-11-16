# CES-1: cell resource budget (v0.1 draft)

A cell declares what it may use in its `cell.toml`. The runtime enforces it and measures it. A cell that
declares nothing gets the defaults, which are small on purpose: thousands of idle cells on one machine must
cost close to nothing.

Why: on one 16-core node of the live system (2026-11-16, one 20 s sample) one idle system of 7 processes used
39% of a core at 2091 wake-ups per second with no reader; 7046 sockets sat in TIME-WAIT because callers opened a
connection per call; 333 per-cell supervisor processes were 27% of the process table. None of it was declared,
enforced or measured.

## 1. The `[budget]` table

```toml
[budget]                      # CES-1 v0.1. Every key has the default shown; write only what differs.
idle_cpu_pct   = 0.1          # % of one core, averaged over >= 60 s with no call in flight
idle_wakeups_s = 1            # voluntary context switches per second, all threads, idle
cpu_max_pct    = 100          # ceiling under load (cgroup cpu.max)
mem_bytes      = "128M"       # cgroup memory.max
pids           = 16           # processes and threads (cgroup pids.max)
conns          = 64           # open sockets
fanout         = 16           # concurrent outbound calls
hops           = 8            # most cells deep one inbound call may reach through this one (1..64)
log_bytes      = "16M"        # rotated by the runtime
[[budget.timer]]              # every periodic wake-up is declared
name    = "replog-heartbeat"
idle_ms = 1000                # period with no work; MUST be >= 1000
busy_ms = 100                 # period while work is in flight; MUST be >= 50 and <= idle_ms
```

Sizes are a positive integer of bytes or a string with `K`, `M` or `G` (powers of 1024). An unknown key is an
error, so a typo cannot silently fall back to a default.

## 2. Rules

1. **Idle.** A cell is idle when no call is in flight and none ended in the last 10 s. Idle, it MUST stay within
   `idle_cpu_pct` and `idle_wakeups_s`. Hard limits: `idle_cpu_pct <= 0.5`, `idle_wakeups_s <= 10`. A value
   above the default MUST carry its reason in a comment on the same line.
2. **Timers.** A cell MUST NOT wake on a period shorter than 1 s while idle, and MUST block on an event (a
   socket, a store watch, a channel) in place of polling. A heartbeat MUST ride an open connection and slow to
   `idle_ms` when there is nothing to send. The sum of `1000 / idle_ms` over declared timers MUST be at most
   `idle_wakeups_s`.
3. **Connections.** Calls to the same peer MUST reuse one connection. A cell MUST NOT open a connection per call
   or per heartbeat. An unused connection SHOULD close after 300 s. Same-machine calls SHOULD use a unix socket.
4. **Retry.** Retries MUST back off exponentially with jitter (first wait >= 100 ms, factor 2, ceiling >= 30 s).
   A typed refusal (denied, no such cell, a schema error) MUST NOT be retried.
5. **Processes.** One instance is one process tree within `pids`. A cell MUST NOT call another cell by starting
   a CLI process per call; it holds a typed client.
6. **Fan-out and depth.** Every call carries `hops_left` and an absolute deadline. A cell decrements `hops_left`,
   passes the deadline on, and MUST refuse at 0 or past the deadline. Outbound calls above `fanout` queue.
7. **Memory and disk.** `mem_bytes` and `log_bytes` are hard. A cell SHOULD return to within 1.2 times its
   start-up resident size after 60 s idle.
8. **Enforcement.** The runtime MUST place each instance in its own cgroup v2 leaf with `memory.max`,
   `pids.max` and `cpu.max` set from the budget, and judges rules 1 and 2 from `cpu.stat` and the threads'
   context-switch counters, not from anything the cell reports. Over an idle rule for 3 windows in a row: the
   typed event `budget.exceeded`, then the instance is frozen and its owner told. Over a hard rule: stop, then
   restart with backoff.
9. **Supervisors.** Runtime helpers count against the node, not the cell. A node SHOULD run one supervisor per
   machine, not one per cell.

## 3. Static checks

| Check | Rule | Fails when |
|---|---|---|
| C1.1 | 1, 2, sizes | `[budget]` is not a table; a key is unknown; a value is not of its type or outside its hard limit; a value above its default has no reason comment; a timer has no name, a duplicate name, `idle_ms < 1000`, `busy_ms < 50` or `busy_ms > idle_ms` |
| C1.2 | 2 | declared timers wake more often than `idle_wakeups_s` |

A manifest with no `[budget]` table is not a violation in v0.1: checkers report it as a warning until their
stated date (CES-0 rule 7), then as C1.1.

## 4. Dynamic checks

Measured by the runtime or a checker on a running instance (CES-3 names the counters):

| Check | Must | Input |
|---|---|---|
| C1.3 | idle CPU <= `idle_cpu_pct` | `cpu_usec` over an idle window of at least 60 s |
| C1.4 | idle wake-ups <= `idle_wakeups_s` | voluntary context switches, all threads, same window |
| C1.5 | 100 calls from one peer open at most 2 connections | `calls`, `conns_opened` |
| C1.6 | a typed refusal is not retried | `refusals`, `refusal_retries` |
| C1.7 | resident after idle <= `mem_bytes` (MUST) and <= 1.2 x start-up (SHOULD, warn) | `rss_start`, `rss_after_idle` |

A window shorter than 60 s, or one with a call in flight, is not judged (`skip`): a checker never fails a cell
on a busy or too-short sample.

## 5. Conformance

- A manifest conforms when C1.1 and C1.2 pass.
- An instance conforms when C1.3 to C1.6 pass and C1.7 does not fail, over a sample taken as in section 4.
- A checker conforms when it reproduces every verdict in `tests/ces1/manifests.json` (verdict and line) and
  `tests/ces1/samples.json` (outcome of each check). The Rust crate does (`ce_net_proto::ces1`,
  `cargo test --test ces1`; CLI `ces-check manifest <cell.toml>`). A second, independent checker is needed
  before v1 (CES-0 rule 6).

## 6. Vectors

`tests/ces1/manifests.json`: `{name, toml, expect}` with `expect` one of `"absent"`, `"valid"` or
`{"fail": "C1.x", "line": n}` (some violation of that check on that 1-based line).
`tests/ces1/samples.json`: `{name, budget, sample, expect}` with `sample` the fields of section 4 plus
`window_s` and `busy`, and `expect` mapping each of C1.3 to C1.7 to `pass`, `warn`, `fail` or `skip`.
