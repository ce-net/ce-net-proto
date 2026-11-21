//! CES-7 v0.1, wrapped software (docs/standards/CES-7-wrapped.md).
//!
//! [`plan`]: a detect record (`wrap.toml`) to the planned ops (name, right) and `[budget]`: rules 1, 2 and 5.
use serde::{Deserialize, Serialize};

pub const READ_COMMANDS: &[&str] = &["list", "ls", "show", "get", "status", "info", "version", "help", "search", "cat", "describe"];
pub const READ_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

/// One surface the detect run found: an HTTP route (`method` and `path`) or a CLI command (`command`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Surface {
    pub method: Option<String>,
    pub path: Option<String>,
    pub command: Option<String>,
}

/// The measured idle numbers of the detect run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Measured {
    pub idle_cpu_pct: f64,
    pub idle_wakeups_s: f64,
    pub rss_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Detect {
    pub api: String,
    pub surfaces: Vec<Surface>,
    pub measured: Measured,
    pub egress: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedOp {
    pub name: String,
    pub right: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    pub ops: Vec<PlannedOp>,
    /// The `[budget]` table text (CES-1), each line above the default with its reason.
    pub budget: String,
    /// Egress the owner must grant; the plan grants none (rule 3).
    pub egress_to_grant: Vec<String>,
}

fn camel(words: impl Iterator<Item = String>) -> String {
    words
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + &c.as_str().to_ascii_lowercase(),
                None => String::new(),
            }
        })
        .collect()
}

fn split(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split(|c: char| !c.is_ascii_alphanumeric()).map(str::to_string)
}

/// Rule 5 and rule 1 for one surface.
pub fn op_of(api: &str, s: &Surface) -> PlannedOp {
    let (name, read) = match (&s.method, &s.path, &s.command) {
        (Some(m), Some(p), _) => (camel(split(m).chain(split(p))), READ_METHODS.contains(&m.to_ascii_uppercase().as_str())),
        (_, _, Some(c)) => (camel(split(c)), c.split_whitespace().last().is_some_and(|w| READ_COMMANDS.contains(&w))),
        _ => ("Op".to_string(), false),
    };
    PlannedOp { name, right: format!("{api}:{}", if read { "read" } else { "write" }) }
}

fn step_up(v: f64, steps: &[f64]) -> Option<f64> {
    steps.iter().copied().find(|s| v <= *s + 1e-12)
}

/// Rule 2: the measured value rounded up to the next CES-1 step; None when above the hard limits.
pub fn budget_of(m: &Measured) -> Option<String> {
    let cpu = step_up(m.idle_cpu_pct, &[0.1, 0.2, 0.5])?;
    let wake = step_up(m.idle_wakeups_s, &[1.0, 2.0, 5.0, 10.0])?;
    let mut mb = 64u64;
    while (mb << 20) < m.rss_bytes {
        mb *= 2;
    }
    let why = " # measured by ce-wrap detect";
    let mut t = String::from("[budget]\n");
    if cpu > 0.1 {
        t += &format!("idle_cpu_pct = {cpu}{why}\n");
    }
    if wake > 1.0 {
        t += &format!("idle_wakeups_s = {}{why}\n", wake as u64);
    }
    if mb > 128 {
        t += &format!("mem_bytes = \"{mb}M\"{why}\n");
    }
    Some(t)
}

/// Rules 1 to 3 and 5. `Err` when the measured run is above the hard limits (rule 2).
pub fn plan(d: &Detect) -> Result<Plan, String> {
    let mut ops: Vec<PlannedOp> = vec![];
    for s in &d.surfaces {
        let mut o = op_of(&d.api, s);
        let base = o.name.clone();
        let mut n = 1;
        while ops.iter().any(|x| x.name == o.name) {
            n += 1;
            o.name = format!("{base}_{n}");
        }
        ops.push(o);
    }
    let budget = budget_of(&d.measured).ok_or_else(|| format!("measured idle {}% CPU, {}/s wake-ups: above CES-1 hard limits, not wrapped as idle-stoppable", d.measured.idle_cpu_pct, d.measured.idle_wakeups_s))?;
    Ok(Plan { ops, budget, egress_to_grant: d.egress.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_rights() {
        let s = Surface { method: Some("GET".into()), path: Some("/users/{id}".into()), command: None };
        assert_eq!(op_of("x.y", &s), PlannedOp { name: "GetUsersId".into(), right: "x.y:read".into() });
        let c = Surface { command: Some("remote add".into()), ..Surface::default() };
        assert_eq!(op_of("x.y", &c).right, "x.y:write");
        let b = budget_of(&Measured { idle_cpu_pct: 0.15, idle_wakeups_s: 0.2, rss_bytes: 300 << 20 }).unwrap();
        assert!(crate::ces1::check_manifest(&b).unwrap().is_some(), "{b}");
    }
}
