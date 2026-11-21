//! CES-4 v0.1, the cell container (docs/standards/CES-4-container.md).
//!
//! - [`choose`]: rules 1 to 3, 7 and 8: the isolation class a launch runs at, failing closed.
//! - [`check_answer`]: rule 6, the typed boundary on every answer.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Class {
    W,
    I1,
    I2,
    I3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageKind {
    Wasm,
    Native,
}

/// Strikes at which an image is refused node-wide (rule 7).
pub const STRIKES_REFUSED: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub classes: Vec<Class>,
    pub strangers: bool,
    pub cpu_share_pct: u32,
    pub mem_share_pct: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { classes: vec![Class::W, Class::I1, Class::I2, Class::I3], strangers: false, cpu_share_pct: 25, mem_share_pct: 25 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Launch {
    pub kind: Option<ImageKind>,
    /// The signer holds a grant from the node owner (rule 1).
    pub granted_author: bool,
    /// A stronger class the caller asks for; never a weaker one.
    pub wanted: Option<Class>,
    pub has_spend: bool,
    pub strikes: u32,
}

impl Default for Launch {
    fn default() -> Self {
        Launch { kind: Some(ImageKind::Wasm), granted_author: false, wanted: None, has_spend: true, strikes: 0 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxError {
    NoIsolationClass { wanted: Vec<Class>, node_has: Vec<Class> },
    PolicyRefused(String),
    ImageRefused(u32),
    OverBudget(String),
    OffContract { op: u32, why: String },
    NoSpend,
    Expired,
    Guard(String),
}

impl BoxError {
    /// The error's kind as the vectors name it.
    pub fn kind(&self) -> &'static str {
        match self {
            BoxError::NoIsolationClass { .. } => "no_isolation_class",
            BoxError::PolicyRefused(_) => "policy_refused",
            BoxError::ImageRefused(_) => "image_refused",
            BoxError::OverBudget(_) => "over_budget",
            BoxError::OffContract { .. } => "off_contract",
            BoxError::NoSpend => "no_spend",
            BoxError::Expired => "expired",
            BoxError::Guard(_) => "guard",
        }
    }
}

/// The classes the signer rule allows for this launch, weakest first (rule 1, with the caller's stronger ask).
pub fn allowed(l: &Launch) -> Vec<Class> {
    let base = match (l.kind, l.granted_author) {
        (Some(ImageKind::Wasm) | None, _) => vec![Class::W],
        (Some(ImageKind::Native), true) => vec![Class::I1, Class::I2, Class::I3],
        (Some(ImageKind::Native), false) => vec![Class::I2, Class::I3],
    };
    match l.wanted {
        // W is its own kind: asking for W on a native image allows nothing; asking a native class on wasm neither
        Some(w) => base.into_iter().filter(|c| strength(*c) >= strength(w) && (w == Class::W) == (*c == Class::W)).collect(),
        None => base,
    }
}

fn strength(c: Class) -> u8 {
    match c {
        Class::W | Class::I1 => 1,
        Class::I2 => 2,
        Class::I3 => 3,
    }
}

/// Rules 1 to 3, 7, 8 in the order of section 3: `no_spend`, `image_refused`, `policy_refused`,
/// `no_isolation_class`. `node_has`: the classes this node can run.
pub fn choose(l: &Launch, node_has: &[Class], p: &Policy) -> Result<Class, BoxError> {
    let stranger = !l.granted_author;
    if stranger && !l.has_spend {
        return Err(BoxError::NoSpend);
    }
    if l.strikes >= STRIKES_REFUSED {
        return Err(BoxError::ImageRefused(l.strikes));
    }
    if stranger && !p.strangers {
        return Err(BoxError::PolicyRefused("this node runs no strangers' code".into()));
    }
    let want = allowed(l);
    let by_policy: Vec<Class> = want.iter().copied().filter(|c| p.classes.contains(c)).collect();
    if by_policy.is_empty() {
        return Err(BoxError::PolicyRefused(format!("the policy allows {:?}, the launch needs one of {want:?}", p.classes)));
    }
    by_policy.iter().copied().find(|c| node_has.contains(c)).ok_or(BoxError::NoIsolationClass { wanted: by_policy, node_has: node_has.to_vec() })
}

/// The limits on one op's answer (rule 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerLimits {
    pub max_bytes: u64,
    pub deadline_ms: u64,
}

/// One answer as it reached the boundary: its size, when it arrived, and whether it decoded as the op's type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub op: u32,
    pub bytes: u64,
    pub at_ms: u64,
    pub schema_ok: bool,
}

/// Rule 6: the answer crosses, or the call fails typed.
pub fn check_answer(lim: &AnswerLimits, a: &Answer) -> Result<(), BoxError> {
    if a.at_ms > lim.deadline_ms {
        return Err(BoxError::Expired);
    }
    if !a.schema_ok {
        return Err(BoxError::OffContract { op: a.op, why: "the answer does not decode as the op's type".into() });
    }
    if a.bytes > lim.max_bytes {
        return Err(BoxError::OffContract { op: a.op, why: format!("{} bytes, above the op's {}", a.bytes, lim.max_bytes) });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stranger_native_on_a_node_without_gvisor_is_refused_never_run_lower() {
        let l = Launch { kind: Some(ImageKind::Native), ..Launch::default() };
        let p = Policy { strangers: true, ..Policy::default() };
        let e = choose(&l, &[Class::W, Class::I1], &p).unwrap_err();
        assert_eq!(e.kind(), "no_isolation_class");
    }
}
