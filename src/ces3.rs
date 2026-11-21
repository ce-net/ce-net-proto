//! CES-3 v0.1, cell observability (docs/standards/CES-3-observability.md).
//!
//! What the node measures about a cell, from outside, and the pure rules over it:
//! - [`excess`] and [`rank`]: section 3 and C3.1.
//! - [`filter_rows`]: rule 4 and C3.2, the server-side filter by the caller's rights.
//! - [`gate_events`]: rule 2 and C3.3, at most 10 lines per second per cell.
//! - [`pass_on`]: rule 5 and C3.4, the trace with `hops_left` and the deadline.
use crate::ces1::{Budget, MIN_WINDOW_S};
use crate::ces2::State;
use serde::{Deserialize, Serialize};

/// Rule 2: lines kept per cell per second.
pub const EVENTS_PER_S: usize = 10;

/// One instance as the node measured it (section 1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CellStat {
    pub cell: String,
    pub node: String,
    pub owner: String,
    pub state: State,
    pub window_s: f64,
    pub busy: bool,
    pub cpu_usec: u64,
    pub wakeups: u64,
    pub rss_bytes: u64,
    pub pids: u32,
    pub conns_open: u32,
    pub conns_opened: u32,
    pub disk_bytes: u64,
    pub calls: u64,
    pub last_call_s: u64,
    pub keep: bool,
    pub budget: Budget,
}

impl Default for CellStat {
    fn default() -> Self {
        CellStat {
            cell: String::new(),
            node: String::new(),
            owner: String::new(),
            state: State::Live,
            window_s: 0.0,
            busy: false,
            cpu_usec: 0,
            wakeups: 0,
            rss_bytes: 0,
            pids: 0,
            conns_open: 0,
            conns_opened: 0,
            disk_bytes: 0,
            calls: 0,
            last_call_s: 0,
            keep: false,
            budget: Budget::default(),
        }
    }
}

/// Section 3: the excess and the names over budget, in the order cpu, wake, mem, pids.
pub fn excess(s: &CellStat) -> (f64, Vec<&'static str>) {
    let b = &s.budget;
    let idle = !s.busy && s.window_s >= MIN_WINDOW_S;
    let mut parts: Vec<(&'static str, f64)> = vec![];
    if idle {
        parts.push(("cpu", (s.cpu_usec as f64 / (s.window_s * 1e6) * 100.0) / b.idle_cpu_pct));
        parts.push(("wake", (s.wakeups as f64 / s.window_s) / b.idle_wakeups_s));
    }
    parts.push(("mem", s.rss_bytes as f64 / b.mem_bytes.max(1) as f64));
    parts.push(("pids", s.pids as f64 / b.pids.max(1) as f64));
    let x = parts.iter().map(|p| p.1).fold(0.0, f64::max);
    (x, parts.iter().filter(|p| p.1 > 1.0 + 1e-9).map(|p| p.0).collect())
}

/// One answered row of `node.budget@1 Idle`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ranked {
    pub cell: String,
    pub excess: f64,
    pub over: Vec<String>,
}

/// Rule 3 and C3.1: highest excess first, ties by cell name.
pub fn rank(rows: &[CellStat]) -> Vec<Ranked> {
    let mut out: Vec<Ranked> = rows
        .iter()
        .map(|s| {
            let (x, o) = excess(s);
            Ranked { cell: s.cell.clone(), excess: x, over: o.into_iter().map(str::to_string).collect() }
        })
        .collect();
    out.sort_by(|a, b| b.excess.partial_cmp(&a.excess).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.cell.cmp(&b.cell)));
    out
}

/// Rule 4 and C3.2: the rows a caller may read. `rights` are abilities the caller's chain grants on this
/// node: `node.budget:read` reads all; `<cell>:read` reads that cell's row; a caller reads rows it owns.
pub fn filter_rows<'a>(caller: &str, rights: &[String], rows: &'a [CellStat]) -> Vec<&'a CellStat> {
    let all = rights.iter().any(|r| r == "node.budget:read");
    rows.iter().filter(|s| all || s.owner == caller || rights.iter().any(|r| r.strip_suffix(":read") == Some(s.cell.as_str()))).collect()
}

/// Rule 2 and C3.3: given the times (ms) of one cell's event lines in order, the lines kept as
/// `(time_ms, dropped)`: `dropped` counts lines dropped since the previous kept line.
pub fn gate_events(times_ms: &[u64]) -> Vec<(u64, u64)> {
    let mut out = vec![];
    let (mut sec, mut n, mut dropped) = (u64::MAX, 0usize, 0u64);
    for &t in times_ms {
        let s = t / 1000;
        if s != sec {
            sec = s;
            n = 0;
        }
        if n < EVENTS_PER_S {
            out.push((t, dropped));
            dropped = 0;
            n += 1;
        } else {
            dropped += 1;
        }
    }
    out
}

/// What every call carries (rule 5; CES-1 rule 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trace {
    pub id: String,
    pub hops_left: u8,
    /// Absolute, milliseconds since the Unix epoch.
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HopRefusal {
    Hops,
    Deadline,
}

/// Rule 5: the trace a cell passes on for an outbound call made at `now_ms` while serving `t`.
/// Also the inbound check: a call whose trace is refused here MUST NOT be run.
pub fn pass_on(t: &Trace, now_ms: u64) -> Result<Trace, HopRefusal> {
    if t.hops_left == 0 {
        return Err(HopRefusal::Hops);
    }
    if now_ms >= t.deadline_ms {
        return Err(HopRefusal::Deadline);
    }
    Ok(Trace { id: t.id.clone(), hops_left: t.hops_left - 1, deadline_ms: t.deadline_ms })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_keeps_ten_a_second() {
        let t: Vec<u64> = (0..15).map(|i| i * 10).chain([1500]).collect();
        let k = gate_events(&t);
        assert_eq!(k.len(), 11);
        assert_eq!(k[10], (1500, 5));
    }

    #[test]
    fn hops_stop_at_zero() {
        let mut t = Trace { id: "a".into(), hops_left: 2, deadline_ms: 10 };
        t = pass_on(&t, 0).unwrap();
        t = pass_on(&t, 0).unwrap();
        assert_eq!(pass_on(&t, 0), Err(HopRefusal::Hops));
    }
}
