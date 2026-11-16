//! CES-1 v0.1, the cell resource budget (docs/standards/CES-1-budget.md).
//!
//! Two pure functions any runtime or checker can call:
//! - [`check_manifest`]: the static checks C1.1 (the `[budget]` table parses, every key is known, every
//!   value is within the hard limits, a value above the default carries its reason) and C1.2 (the
//!   declared timers fit the idle wake-up budget).
//! - [`judge_sample`]: the dynamic checks C1.3 to C1.7 over one measured [`Sample`], so two checkers
//!   given the same numbers give the same verdicts (vectors: `tests/ces1/`).
use serde::{Deserialize, Serialize};

/// The defaults of CES-1 v0.1. A cell writes only the keys that differ.
pub const DEFAULT_IDLE_CPU_PCT: f64 = 0.1;
pub const DEFAULT_IDLE_WAKEUPS_S: f64 = 1.0;
/// Hard limits: no manifest may declare more.
pub const MAX_IDLE_CPU_PCT: f64 = 0.5;
pub const MAX_IDLE_WAKEUPS_S: f64 = 10.0;
pub const MIN_TIMER_IDLE_MS: u64 = 1000;
pub const MIN_TIMER_BUSY_MS: u64 = 50;
/// The shortest window over which C1.3 and C1.4 are judged.
pub const MIN_WINDOW_S: f64 = 60.0;
/// C1.5: at most this many new connections for [`C15_CALLS`] calls to one peer.
pub const C15_CALLS: u32 = 100;
pub const C15_MAX_CONNS: u32 = 2;
/// C1.7: resident size after idle within this factor of the start-up size (SHOULD).
pub const C17_FACTOR: f64 = 1.2;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Timer {
    pub name: String,
    pub idle_ms: u64,
    pub busy_ms: u64,
}

/// A parsed, valid `[budget]` table with defaults filled in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Budget {
    pub idle_cpu_pct: f64,
    pub idle_wakeups_s: f64,
    pub cpu_max_pct: f64,
    pub mem_bytes: u64,
    pub pids: u32,
    pub conns: u32,
    pub fanout: u32,
    pub hops: u32,
    pub log_bytes: u64,
    pub timers: Vec<Timer>,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            idle_cpu_pct: DEFAULT_IDLE_CPU_PCT,
            idle_wakeups_s: DEFAULT_IDLE_WAKEUPS_S,
            cpu_max_pct: 100.0,
            mem_bytes: 128 << 20,
            pids: 16,
            conns: 64,
            fanout: 16,
            hops: 8,
            log_bytes: 16 << 20,
            timers: vec![],
        }
    }
}

/// One broken rule: the check id (`C1.1`, `C1.2`), the 1-based line in the manifest, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub check: String,
    pub line: usize,
    pub msg: String,
}

/// `"128M"`, `"2G"`, `"64K"` (powers of 1024) or a plain integer of bytes; must be above 0.
pub fn parse_size(v: &toml::Value) -> Option<u64> {
    match v {
        toml::Value::Integer(n) if *n > 0 => Some(*n as u64),
        toml::Value::String(s) => {
            let s = s.trim().replace('_', "");
            let last = s.chars().last()?.to_ascii_uppercase();
            let (num, mul) = match last {
                'K' => (&s[..s.len() - 1], 1u64 << 10),
                'M' => (&s[..s.len() - 1], 1 << 20),
                'G' => (&s[..s.len() - 1], 1 << 30),
                _ => (s.as_str(), 1),
            };
            num.trim().parse::<u64>().ok().and_then(|n| n.checked_mul(mul)).filter(|n| *n > 0)
        }
        _ => None,
    }
}

fn num(v: &toml::Value) -> Option<f64> {
    match v {
        toml::Value::Integer(n) => Some(*n as f64),
        toml::Value::Float(f) if f.is_finite() => Some(*f),
        _ => None,
    }
}

fn line_of(text: &str, key: &str) -> usize {
    let mut in_budget = false;
    for (i, l) in text.lines().enumerate() {
        let t = l.trim_start();
        if t.starts_with('[') {
            in_budget = t.starts_with("[budget]") || t.starts_with("[[budget.timer]]");
            if key == "[budget]" && t.starts_with("[budget]") {
                return i + 1;
            }
            continue;
        }
        if in_budget && t.strip_prefix(key).is_some_and(|r| r.trim_start().starts_with('=')) {
            return i + 1;
        }
    }
    1
}

fn has_comment(text: &str, line: usize) -> bool {
    text.lines().nth(line.saturating_sub(1)).and_then(|l| l.split_once('#')).is_some_and(|(_, c)| !c.trim().is_empty())
}

/// C1.1 and C1.2 over a whole `cell.toml` text. `Ok(None)`: the manifest has no `[budget]` table (a
/// checker reports that per its own warn date, CES-1 section 5). `Ok(Some(b))`: valid. `Err`: every
/// violation found, in line order.
pub fn check_manifest(text: &str) -> Result<Option<Budget>, Vec<Violation>> {
    let tab = match text.parse::<toml::Table>() {
        Ok(t) => t,
        Err(e) => return Err(vec![Violation { check: "C1.1".into(), line: 1, msg: format!("not valid TOML: {}", e.message()) }]),
    };
    let Some(b) = tab.get("budget") else { return Ok(None) };
    let mut out = vec![];
    let mut bad = |key: &str, msg: String| out.push(Violation { check: "C1.1".into(), line: line_of(text, key), msg });
    let Some(b) = b.as_table() else {
        bad("[budget]", "budget is not a table".into());
        return Err(out);
    };
    let mut r = Budget::default();
    for (k, v) in b {
        let k = k.as_str();
        match k {
            "idle_cpu_pct" | "idle_wakeups_s" | "cpu_max_pct" => {
                let Some(x) = num(v).filter(|x| *x >= 0.0) else {
                    bad(k, format!("{k} is not a number >= 0"));
                    continue;
                };
                let (max, default) = match k {
                    "idle_cpu_pct" => (MAX_IDLE_CPU_PCT, DEFAULT_IDLE_CPU_PCT),
                    "idle_wakeups_s" => (MAX_IDLE_WAKEUPS_S, DEFAULT_IDLE_WAKEUPS_S),
                    _ => (f64::MAX, f64::MAX),
                };
                if x > max {
                    bad(k, format!("{k} = {x} is above the hard limit {max}"));
                } else if x > default && !has_comment(text, line_of(text, k)) {
                    bad(k, format!("{k} = {x} is above the default {default}: state the reason in a comment on that line"));
                }
                if k == "cpu_max_pct" && x == 0.0 {
                    bad(k, "cpu_max_pct must be above 0".into());
                }
                match k {
                    "idle_cpu_pct" => r.idle_cpu_pct = x,
                    "idle_wakeups_s" => r.idle_wakeups_s = x,
                    _ => r.cpu_max_pct = x,
                }
            }
            "mem_bytes" | "log_bytes" => match parse_size(v) {
                Some(n) if k == "mem_bytes" => r.mem_bytes = n,
                Some(n) => r.log_bytes = n,
                None => bad(k, format!("{k} is not a size (bytes, or \"128M\" / \"2G\")")),
            },
            "pids" | "conns" | "fanout" | "hops" => match v.as_integer() {
                Some(n) if (1..=65535).contains(&n) && !(k == "hops" && n > 64) => {
                    let n = n as u32;
                    match k {
                        "pids" => r.pids = n,
                        "conns" => r.conns = n,
                        "fanout" => r.fanout = n,
                        _ => r.hops = n,
                    }
                }
                _ => bad(k, format!("{k} must be an integer from 1 to {}", if k == "hops" { 64 } else { 65535 })),
            },
            "timer" => {
                let Some(arr) = v.as_array() else {
                    bad("[budget]", "budget.timer must be an array of tables ([[budget.timer]])".into());
                    continue;
                };
                for t in arr {
                    let Some(t) = t.as_table() else {
                        bad("[budget]", "a budget.timer entry is not a table".into());
                        continue;
                    };
                    let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                    let idle = t.get("idle_ms").and_then(|x| x.as_integer()).filter(|x| *x > 0).map(|x| x as u64);
                    let busy = t.get("busy_ms").and_then(|x| x.as_integer()).filter(|x| *x > 0).map(|x| x as u64);
                    let at = if name.is_empty() { "name".to_string() } else { "idle_ms".to_string() };
                    if name.is_empty() {
                        bad(&at, "a budget.timer has no name".into());
                    }
                    if let Some(extra) = t.keys().find(|k| !["name", "idle_ms", "busy_ms"].contains(&k.as_str())) {
                        bad(extra, format!("unknown key budget.timer.{extra}"));
                    }
                    let Some(idle) = idle else {
                        bad(&at, format!("timer {name:?}: idle_ms missing or not a positive integer"));
                        continue;
                    };
                    let busy = busy.unwrap_or(idle);
                    if idle < MIN_TIMER_IDLE_MS {
                        bad("idle_ms", format!("timer {name:?}: idle_ms = {idle} is under {MIN_TIMER_IDLE_MS}: an idle cell never wakes faster than once a second"));
                    }
                    if busy < MIN_TIMER_BUSY_MS {
                        bad("busy_ms", format!("timer {name:?}: busy_ms = {busy} is under {MIN_TIMER_BUSY_MS}"));
                    }
                    if busy > idle {
                        bad("busy_ms", format!("timer {name:?}: busy_ms = {busy} is above idle_ms = {idle}"));
                    }
                    if r.timers.iter().any(|x| x.name == name) {
                        bad("name", format!("timer {name:?} is declared twice"));
                    }
                    r.timers.push(Timer { name, idle_ms: idle, busy_ms: busy });
                }
            }
            other => bad(other, format!("unknown key budget.{other} (CES-1 v0.1 keys: idle_cpu_pct, idle_wakeups_s, cpu_max_pct, mem_bytes, pids, conns, fanout, hops, log_bytes, timer)")),
        }
    }
    let rate: f64 = r.timers.iter().map(|t| 1000.0 / t.idle_ms as f64).sum();
    if rate > r.idle_wakeups_s + 1e-9 {
        out.push(Violation {
            check: "C1.2".into(),
            line: line_of(text, "[budget]"),
            msg: format!("declared timers wake {rate:.2} times a second when idle, above idle_wakeups_s = {}", r.idle_wakeups_s),
        });
    }
    out.sort_by_key(|v| v.line);
    if out.is_empty() { Ok(Some(r)) } else { Err(out) }
}

/// One measurement of a running instance. Every field is optional: a check whose inputs are absent
/// is `Skip`. Counters are deltas over the window, measured by the runtime (CES-3), not the cell.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sample {
    /// Length of the idle window, seconds.
    pub window_s: Option<f64>,
    /// Calls in flight or ended in the last 10 s at any point in the window: then it is not idle.
    pub busy: Option<bool>,
    /// CPU time (user + system, all threads) used in the window, microseconds.
    pub cpu_usec: Option<u64>,
    /// Voluntary context switches, all threads, in the window.
    pub wakeups: Option<u64>,
    /// C1.5: calls made to the instance from one peer, and the connections the instance accepted for them.
    pub calls: Option<u32>,
    pub conns_opened: Option<u32>,
    /// C1.6: typed refusals the instance got from a peer, and how many of them it retried.
    pub refusals: Option<u32>,
    pub refusal_retries: Option<u32>,
    /// C1.7: resident bytes 10 s after start, and after 60 s idle following a load.
    pub rss_start: Option<u64>,
    pub rss_after_idle: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Pass,
    /// A SHOULD is broken.
    Warn,
    /// A MUST is broken.
    Fail,
    /// Not measured, or not judgeable from this sample.
    Skip,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub check: String,
    pub outcome: Outcome,
    pub msg: String,
}

/// C1.3 to C1.7 for one sample against one budget, always in that order.
pub fn judge_sample(b: &Budget, s: &Sample) -> Vec<Verdict> {
    let v = |check: &str, outcome, msg: String| Verdict { check: check.into(), outcome, msg };
    let mut out = vec![];
    let idle_window = match (s.window_s, s.busy) {
        (_, Some(true)) => Err("not idle: a call was in flight in the window".to_string()),
        (Some(w), _) if w >= MIN_WINDOW_S => Ok(w),
        (Some(w), _) => Err(format!("window {w} s is shorter than {MIN_WINDOW_S} s")),
        (None, _) => Err("no window".to_string()),
    };
    match (&idle_window, s.cpu_usec) {
        (Ok(w), Some(c)) => {
            let pct = c as f64 / (w * 1e6) * 100.0;
            let o = if pct <= b.idle_cpu_pct + 1e-9 { Outcome::Pass } else { Outcome::Fail };
            out.push(v("C1.3", o, format!("idle CPU {pct:.3}% of a core, budget {}%", b.idle_cpu_pct)));
        }
        (Err(e), _) => out.push(v("C1.3", Outcome::Skip, e.clone())),
        (_, None) => out.push(v("C1.3", Outcome::Skip, "cpu_usec not measured".into())),
    }
    match (&idle_window, s.wakeups) {
        (Ok(w), Some(n)) => {
            let rate = n as f64 / w;
            let o = if rate <= b.idle_wakeups_s + 1e-9 { Outcome::Pass } else { Outcome::Fail };
            out.push(v("C1.4", o, format!("idle wake-ups {rate:.2}/s, budget {}/s", b.idle_wakeups_s)));
        }
        (Err(e), _) => out.push(v("C1.4", Outcome::Skip, e.clone())),
        (_, None) => out.push(v("C1.4", Outcome::Skip, "wakeups not measured".into())),
    }
    match (s.calls, s.conns_opened) {
        (Some(c), Some(n)) if c >= C15_CALLS => {
            let o = if n <= C15_MAX_CONNS { Outcome::Pass } else { Outcome::Fail };
            out.push(v("C1.5", o, format!("{c} calls opened {n} connections (at most {C15_MAX_CONNS})")));
        }
        (Some(c), Some(_)) => out.push(v("C1.5", Outcome::Skip, format!("{c} calls, fewer than {C15_CALLS}"))),
        _ => out.push(v("C1.5", Outcome::Skip, "calls or conns_opened not measured".into())),
    }
    match (s.refusals, s.refusal_retries) {
        (Some(r), Some(n)) if r > 0 => {
            let o = if n == 0 { Outcome::Pass } else { Outcome::Fail };
            out.push(v("C1.6", o, format!("{n} retries of {r} typed refusals")));
        }
        _ => out.push(v("C1.6", Outcome::Skip, "no refusal measured".into())),
    }
    match (s.rss_start, s.rss_after_idle) {
        (Some(a), Some(z)) => {
            let (o, msg) = if z > b.mem_bytes {
                (Outcome::Fail, format!("resident {z} bytes is above mem_bytes {}", b.mem_bytes))
            } else if z as f64 > a as f64 * C17_FACTOR {
                (Outcome::Warn, format!("resident {z} bytes after idle, more than {C17_FACTOR} x start-up {a}"))
            } else {
                (Outcome::Pass, format!("resident {z} bytes after idle, start-up {a}"))
            };
            out.push(v("C1.7", o, msg));
        }
        _ => out.push(v("C1.7", Outcome::Skip, "rss_start or rss_after_idle not measured".into())),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_absent_table() {
        assert_eq!(check_manifest("[cell]\napi = \"x.y\"\n").unwrap(), None);
        assert_eq!(check_manifest("[budget]\n").unwrap(), Some(Budget::default()));
    }

    #[test]
    fn a_fast_timer_is_c1_1_and_line_is_right() {
        let t = "[cell]\napi = \"x\"\n[budget]\n[[budget.timer]]\nname = \"hb\"\nidle_ms = 100\n";
        let e = check_manifest(t).unwrap_err();
        assert!(e.iter().any(|v| v.check == "C1.1" && v.line == 6), "{e:?}");
        assert!(e.iter().any(|v| v.check == "C1.2"));
    }
}
