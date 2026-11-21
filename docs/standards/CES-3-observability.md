# CES-3: cell observability (v0.1 draft)

What a cell costs is measured by the node, from outside, never reported by the cell: a stranger's cell cannot
misreport, and a cell needs no code to be measured. Leif 2026-11-21: "not each cell reports its usage. this
must be more plug and play than each cell."

## 1. What the node measures

For every running instance, from its cgroup leaf (CES-1 rule 8) or, where there are no cgroups, from the
process table (`/proc` on Linux, `proc_pid_rusage` on macOS):

```
CellStat {
  cell: String, node: String, owner: String,      // owner: the person: ref holding the install
  state: State,                                   // CES-2
  window_s: f64,                                  // the sample window
  busy: bool,                                     // a call in flight or ended < 10 s ago in the window
  cpu_usec: u64, wakeups: u64,                    // deltas over the window, all threads
  rss_bytes: u64, pids: u32,
  conns_open: u32, conns_opened: u32,             // sockets now, connections accepted in the window
  disk_bytes: u64, calls: u64, last_call_s: u64,
  keep: bool,
  budget: Budget,                                 // CES-1, defaults filled in
}
```

A cell MAY also provide the capability `resource.usage@1` to report inner numbers (queue depth, cache size);
it is optional and never replaces the node's numbers.

## 2. Rules

1. **Outside.** A runtime MUST derive `cpu_usec`, `wakeups`, `rss_bytes` and `pids` from the kernel, not from
   the cell. A cell MUST NOT be required to link any code to be measured.
2. **Events.** Lifecycle and budget events are typed, one JSON line each. At most 10 per second per cell are
   kept; the rest in that second are counted and dropped, and the count is the next kept line's `dropped`.
3. **Node budget.** A node provides `node.budget@1`: `Idle { secs, top }` answers one row per instance with its
   excess (section 3), sorted by excess, highest first, and lists every kept cell with its reason.
4. **Filtered on the server.** A caller gets only rows it may read: all rows with `node.budget:read` on that
   node; otherwise only rows whose `owner` is the caller or whose cell it holds `<cell>:read` on. The node
   filters before answering; a client never receives a row and hides it.
5. **Trace.** Every call carries a trace id, `hops_left` and an absolute deadline (CES-1 rule 6). A cell passes
   the same trace id on, with `hops_left - 1` and the same deadline, so one fan-out is one tree. A call with
   `hops_left = 0`, or arriving past its deadline, is refused (`hops` or `deadline`) and not run.

## 3. Excess

For an idle row (not `busy`, `window_s >= 60`):

```
cpu  = (cpu_usec / (window_s * 1e6) * 100) / budget.idle_cpu_pct
wake = (wakeups / window_s) / budget.idle_wakeups_s
mem  = rss_bytes / budget.mem_bytes
pids = pids / budget.pids
excess = max(cpu, wake, mem, pids)
```

A busy or short-window row has excess `max(mem, pids)` only. `over` is the list of the four names whose ratio is
above 1, in that order. Ties sort by cell name.

## 4. Checks

| Check | Rule | Fails when |
|---|---|---|
| C3.1 | 3 | rows are not sorted by excess, or an excess or `over` differs from section 3 |
| C3.2 | 4 | a row the caller may not read is in the answer, or one it may read is missing |
| C3.3 | 2 | more than 10 lines kept in one second for one cell, or `dropped` miscounted |
| C3.4 | 5 | `hops_left` not decremented, the deadline changed, the trace id changed, or a call at 0 or past its deadline was run |

## 5. Conformance and vectors

The Rust crate reproduces every vector (`ce_net_proto::ces3`, `cargo test --test ces3`).

- `tests/ces3/rows.json`: `{name, rows, expect}`: `expect` the cell names in order with each excess (to 3
  decimals) and `over`.
- `tests/ces3/filter.json`: `{name, caller, rights, rows, expect}`: the cell names the caller receives.
- `tests/ces3/events.json`: `{name, times_ms, expect}`: for each line kept, its time and `dropped`.
- `tests/ces3/hops.json`: `{name, trace, now_ms, expect}`: the trace passed on, or the refusal.
