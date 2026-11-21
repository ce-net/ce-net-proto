//! CES-2 v0.1, the cell lifecycle (docs/standards/CES-2-lifecycle.md).
//!
//! Pure functions any runtime or checker can call:
//! - [`check_lifecycle`]: C2.0 over the `[lifecycle]` table of a `cell.toml`.
//! - [`step`]: the state machine of section 2.
//! - [`check_system`]: the static half of C2.4 (members' budgets fit the system's) and [`lease_due`].
//! - [`judge_run`]: C2.1, C2.2, C2.3 and C2.5 over one recorded [`Run`].
use crate::ces1::{self, Budget, Outcome, Verdict, Violation};
use serde::{Deserialize, Serialize};

pub const DEFAULT_IDLE_STOP_S: u64 = 300;
pub const MIN_IDLE_STOP_S: u64 = 30;
pub const MAX_IDLE_STOP_S: u64 = 86_400;
pub const DEFAULT_START_TIMEOUT_MS: u64 = 2000;
pub const MAX_START_TIMEOUT_MS: u64 = 30_000;
pub const MAX_DRAIN_MS: u64 = 10_000;
pub const DEFAULT_TTL_S: u64 = 3600;
pub const MIN_TTL_S: u64 = 60;
pub const MAX_TTL_S: u64 = 86_400;
/// C2.2 grace past `idle_stop_s`.
pub const C22_GRACE_S: u64 = 60;
/// CES-1 rule 8: idle windows over budget in a row before a freeze.
pub const FREEZE_AFTER: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Lifecycle {
    pub idle_stop_s: u64,
    pub start_timeout_ms: u64,
    pub drain_ms: u64,
    pub keep: bool,
    pub keep_reason: String,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle { idle_stop_s: DEFAULT_IDLE_STOP_S, start_timeout_ms: DEFAULT_START_TIMEOUT_MS, drain_ms: MAX_DRAIN_MS, keep: false, keep_reason: String::new() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Installed,
    Starting,
    Live,
    Idle,
    Stopped,
    Frozen,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Call,
    Healthy,
    StartTimeout,
    CallsDone,
    IdleFor(u64),
    OverBudget(u32),
    Thaw,
    Stop,
    Crash,
    LeaseExpired,
}

fn line_in(text: &str, table: &str, key: &str) -> usize {
    let mut inside = false;
    for (i, l) in text.lines().enumerate() {
        let t = l.trim_start();
        if t.starts_with('[') {
            inside = t.starts_with(&format!("[{table}]"));
            if key.is_empty() && inside {
                return i + 1;
            }
            continue;
        }
        if inside && !key.is_empty() && t.strip_prefix(key).is_some_and(|r| r.trim_start().starts_with('=')) {
            return i + 1;
        }
    }
    1
}

/// C2.0 over a whole `cell.toml`. A manifest with no `[lifecycle]` table gets the defaults.
pub fn check_lifecycle(text: &str) -> Result<Lifecycle, Vec<Violation>> {
    let bad = |line, msg: String| Violation { check: "C2.0".into(), line, msg };
    let tab = text.parse::<toml::Table>().map_err(|e| vec![bad(1, format!("not valid TOML: {}", e.message()))])?;
    let mut r = Lifecycle::default();
    let Some(l) = tab.get("lifecycle") else { return Ok(r) };
    let Some(l) = l.as_table() else { return Err(vec![bad(line_in(text, "lifecycle", ""), "lifecycle is not a table".into())]) };
    let mut out = vec![];
    for (k, v) in l {
        let line = line_in(text, "lifecycle", k);
        let int = |lo: u64, hi: u64| v.as_integer().filter(|n| *n >= lo as i64 && *n <= hi as i64).map(|n| n as u64);
        match k.as_str() {
            "idle_stop_s" => match int(MIN_IDLE_STOP_S, MAX_IDLE_STOP_S) {
                Some(n) => r.idle_stop_s = n,
                None => out.push(bad(line, format!("idle_stop_s must be an integer in {MIN_IDLE_STOP_S}..={MAX_IDLE_STOP_S}"))),
            },
            "start_timeout_ms" => match int(1, MAX_START_TIMEOUT_MS) {
                Some(n) => r.start_timeout_ms = n,
                None => out.push(bad(line, format!("start_timeout_ms must be an integer in 1..={MAX_START_TIMEOUT_MS}"))),
            },
            "drain_ms" => match int(0, MAX_DRAIN_MS) {
                Some(n) => r.drain_ms = n,
                None => out.push(bad(line, format!("drain_ms must be an integer in 0..={MAX_DRAIN_MS}"))),
            },
            "keep" => match v.as_bool() {
                Some(b) => r.keep = b,
                None => out.push(bad(line, "keep must be true or false".into())),
            },
            "keep_reason" => match v.as_str() {
                Some(s) => r.keep_reason = s.trim().to_string(),
                None => out.push(bad(line, "keep_reason must be a string".into())),
            },
            other => out.push(bad(line, format!("unknown key {other}"))),
        }
    }
    if r.keep && r.keep_reason.is_empty() && out.is_empty() {
        out.push(bad(line_in(text, "lifecycle", "keep"), "keep = true needs a keep_reason".into()));
    }
    out.sort_by_key(|v| v.line);
    if out.is_empty() { Ok(r) } else { Err(out) }
}

/// Section 2: the next state, or `Err` (bad_transition) and the state stays.
pub fn step(lc: &Lifecycle, from: State, ev: &Event) -> Result<State, String> {
    use Event as E;
    use State as S;
    let to = match (from, ev) {
        (S::Installed | S::Stopped, E::Call) => S::Starting,
        (S::Failed, E::Call) => S::Starting,
        (S::Starting, E::Healthy) => S::Live,
        (S::Starting, E::StartTimeout) => S::Failed,
        (S::Live, E::CallsDone) => S::Idle,
        (S::Idle, E::Call) => S::Live,
        (S::Idle, E::IdleFor(s)) => {
            if !lc.keep && *s >= lc.idle_stop_s {
                S::Stopped
            } else {
                S::Idle
            }
        }
        (S::Live | S::Idle, E::OverBudget(n)) => {
            if *n >= FREEZE_AFTER {
                S::Frozen
            } else {
                from
            }
        }
        (S::Frozen, E::Thaw) => S::Idle,
        (S::Live | S::Idle | S::Frozen | S::Starting, E::Stop) => S::Stopped,
        (S::Live | S::Idle | S::Starting, E::Crash) => S::Failed,
        (S::Live | S::Idle | S::Frozen, E::LeaseExpired) => S::Stopped,
        _ => return Err(format!("bad_transition: {ev:?} in {from:?}")),
    };
    Ok(to)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct System {
    pub name: String,
    pub owner: String,
    pub ttl_s: u64,
    pub keep_until: Option<String>,
    pub cells: Vec<String>,
    pub procs: u32,
    pub idle_cpu_pct: f64,
    pub mem_bytes: u64,
}

/// Parse a `system.toml` and check the members' CES-1 budgets fit (the static half of C2.4).
/// `members` are the members' `cell.toml` texts (a missing `[budget]` means the CES-1 defaults).
pub fn check_system(text: &str, members: &[&str]) -> Result<System, Vec<Violation>> {
    let bad = |msg: String| Violation { check: "C2.4".into(), line: 1, msg };
    let tab = text.parse::<toml::Table>().map_err(|e| vec![bad(format!("not valid TOML: {}", e.message()))])?;
    let s = tab.get("system").and_then(|v| v.as_table()).ok_or_else(|| vec![bad("no [system] table".into())])?;
    let mut out = vec![];
    let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if name.is_empty() {
        out.push(bad("system needs a name".into()));
    }
    let owner = s.get("owner").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let keep_until = s.get("keep_until").and_then(|v| v.as_str().map(str::to_string));
    if keep_until.is_some() && owner.is_empty() {
        out.push(bad("keep_until needs an owner".into()));
    }
    let ttl_s = match s.get("ttl_s") {
        None => DEFAULT_TTL_S,
        Some(v) => match v.as_integer().filter(|n| *n >= MIN_TTL_S as i64 && *n <= MAX_TTL_S as i64) {
            Some(n) => n as u64,
            None => {
                out.push(bad(format!("ttl_s must be in {MIN_TTL_S}..={MAX_TTL_S}")));
                DEFAULT_TTL_S
            }
        },
    };
    let cells: Vec<String> = s.get("cells").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let sb = s.get("budget").and_then(|v| v.as_table());
    let procs = sb.and_then(|b| b.get("procs")).and_then(|v| v.as_integer()).unwrap_or(32) as u32;
    let idle_cpu_pct = sb.and_then(|b| b.get("idle_cpu_pct")).and_then(|v| v.as_float().or(v.as_integer().map(|n| n as f64))).unwrap_or(0.3);
    let mem_bytes = sb.and_then(|b| b.get("mem_bytes")).and_then(ces1::parse_size).unwrap_or(512 << 20);
    let mut sum = (0u32, 0f64, 0u64);
    for (i, m) in members.iter().enumerate() {
        let b = match ces1::check_manifest(m) {
            Ok(b) => b.unwrap_or_default(),
            Err(_) => {
                out.push(bad(format!("member {i} has an invalid [budget] (CES-1 C1.1)")));
                Budget::default()
            }
        };
        sum.0 += b.pids;
        sum.1 += b.idle_cpu_pct;
        sum.2 += b.mem_bytes;
    }
    if sum.0 > procs {
        out.push(bad(format!("members' pids sum to {}, above procs {procs}", sum.0)));
    }
    if sum.1 > idle_cpu_pct + 1e-9 {
        out.push(bad(format!("members' idle_cpu_pct sum to {:.3}, above {idle_cpu_pct}", sum.1)));
    }
    if sum.2 > mem_bytes {
        out.push(bad(format!("members' mem_bytes sum to {}, above {mem_bytes}", sum.2)));
    }
    if out.is_empty() { Ok(System { name, owner, ttl_s, keep_until, cells, procs, idle_cpu_pct, mem_bytes }) } else { Err(out) }
}

/// Rule 6: has the lease ended? `renewed_s` is the last real call or owner renewal (or the start).
/// `today` is `YYYY-MM-DD`; a `keep_until` date compares as text, so it is due the day after.
pub fn lease_due(s: &System, renewed_s: u64, now_s: u64, today: &str) -> bool {
    match &s.keep_until {
        Some(d) => today > d.as_str(),
        None => now_s >= renewed_s.saturating_add(s.ttl_s),
    }
}

/// One recorded run of a cell, as a checker or the runtime saw it. Every field optional; absent is `Skip`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Run {
    /// C2.1: did the first call start it, and how long until health answered.
    pub started_by_call: Option<bool>,
    pub health_ms: Option<u64>,
    /// C2.2: seconds from the last call to the stop (None: still running at `observed_s` after the last call).
    pub stopped_after_s: Option<u64>,
    pub observed_s: Option<u64>,
    /// C2.3: processes in the cell's cgroup after stop.
    pub procs_after_stop: Option<u32>,
    /// C2.5: was it running before its first call after boot.
    pub ran_before_first_call: Option<bool>,
}

/// C2.1, C2.2, C2.3, C2.5 in that order.
pub fn judge_run(lc: &Lifecycle, r: &Run) -> Vec<Verdict> {
    let v = |check: &str, outcome, msg: String| Verdict { check: check.into(), outcome, msg };
    let mut out = vec![];
    out.push(match (r.started_by_call, r.health_ms) {
        (Some(false), _) => v("C2.1", Outcome::Fail, "the first call did not start the cell".into()),
        (Some(true), Some(ms)) if ms > lc.start_timeout_ms => v("C2.1", Outcome::Fail, format!("health after {ms} ms, past start_timeout_ms {}", lc.start_timeout_ms)),
        (Some(true), Some(ms)) if ms > DEFAULT_START_TIMEOUT_MS => v("C2.1", Outcome::Warn, format!("health after {ms} ms, SHOULD be within {DEFAULT_START_TIMEOUT_MS}")),
        (Some(true), Some(ms)) => v("C2.1", Outcome::Pass, format!("started by its first call, health after {ms} ms")),
        _ => v("C2.1", Outcome::Skip, "start not measured".into()),
    });
    let limit = lc.idle_stop_s + C22_GRACE_S;
    out.push(if lc.keep {
        v("C2.2", Outcome::Skip, format!("kept: {}", lc.keep_reason))
    } else {
        match (r.stopped_after_s, r.observed_s) {
            (Some(s), _) if s <= limit => v("C2.2", Outcome::Pass, format!("stopped {s} s after its last call (limit {limit})")),
            (Some(s), _) => v("C2.2", Outcome::Fail, format!("stopped {s} s after its last call, limit {limit}")),
            (None, Some(o)) if o > limit => v("C2.2", Outcome::Fail, format!("still running {o} s after its last call, limit {limit}")),
            _ => v("C2.2", Outcome::Skip, "idle stop not observed long enough".into()),
        }
    });
    out.push(match r.procs_after_stop {
        Some(0) => v("C2.3", Outcome::Pass, "no process left after stop".into()),
        Some(n) => v("C2.3", Outcome::Fail, format!("{n} processes left in the cgroup after stop")),
        None => v("C2.3", Outcome::Skip, "stop not observed".into()),
    });
    out.push(match (r.ran_before_first_call, lc.keep) {
        (Some(true), false) => v("C2.5", Outcome::Fail, "running at boot without keep".into()),
        (Some(_), _) => v("C2.5", Outcome::Pass, "boot start matches keep".into()),
        (None, _) => v("C2.5", Outcome::Skip, "boot not observed".into()),
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_stop_and_keep() {
        let lc = Lifecycle::default();
        assert_eq!(step(&lc, State::Idle, &Event::IdleFor(300)), Ok(State::Stopped));
        assert_eq!(step(&lc, State::Idle, &Event::IdleFor(299)), Ok(State::Idle));
        let k = Lifecycle { keep: true, keep_reason: "store".into(), ..lc };
        assert_eq!(step(&k, State::Idle, &Event::IdleFor(99_999)), Ok(State::Idle));
        assert!(step(&k, State::Stopped, &Event::Healthy).is_err());
    }

    #[test]
    fn keep_needs_reason() {
        let e = check_lifecycle("[cell]\napi = \"x\"\n[lifecycle]\nkeep = true\n").unwrap_err();
        assert_eq!(e[0].line, 4);
    }
}
