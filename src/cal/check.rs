//! `ce-cal check` (`docs/CAL.md` section 7): run the verifier of `docs/CAPABILITY-PROGRAMS.md`
//! section 5.2 for one request, as the executing node would, and say in plain English why it is
//! refused. Nothing here decides anything itself: the verdict is `authorize_v3` /
//! `authorize_use_v3`'s; this module only adds the explanation.
//!
//! It is a dry run against a fresh node: no counter is spent and no request id is recorded (a real
//! node that has seen earlier uses may still refuse with `capability used up` or
//! `request replayed`). With the content of a file, it also does what the executor does before
//! acting: check the bytes against the hash the program pins ([`check_content`]).

use sha2::{Digest, Sha256};

use super::Labels;
use super::explain::{self, key, node, program_name, requirement, resource, why_child};
use crate::program::{self, Exe, Hash, NodeKey, Step};
use crate::v3::verify::{Node, OwnerRoot, Presented, Request, Roots, authorize_use_v3, authorize_v3, verify_chain_v3};
use crate::v3::{CapabilityV3, Caveat, Key, Link, Party, Proof, TokenV3, UseRequest};

/// What is asked for.
#[derive(Debug, Clone)]
pub enum Action {
    /// A plain call: the most specific ability the cell checks.
    Call(String),
    /// Step `step` of program `program`, execution `run`.
    Step { program: Hash, run: u32, step: u32 },
}

/// One request at one node.
pub struct CheckRequest<'a> {
    pub node: NodeKey,
    /// The node's short hostname (needed for an `InstallCell` step).
    pub host: Option<String>,
    pub tags: Vec<String>,
    pub requester: Key,
    pub action: Action,
    pub now: u64,
    /// Root keys the node accepts (owner roots: P-256 keys need no `rp_id` here).
    pub roots: Vec<Key>,
    /// Keys the node trusts per cell party (`<api>@<major>`).
    pub cell_keys: &'a dyn Fn(&str) -> Vec<Key>,
    /// The use's exact request, its proofs and the body bytes the node received.
    pub presented: Option<(UseRequest, Vec<Proof>, Vec<u8>)>,
    /// The bytes of the file the step installs or runs, to check against its pinned hash.
    pub content: Option<Vec<u8>>,
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub allowed: bool,
    /// The verifier's own refusal text (`None` when allowed).
    pub reason: Option<String>,
    /// Plain-English explanation, one sentence per line.
    pub why: Vec<String>,
}

impl Verdict {
    pub fn text(&self) -> String {
        let mut s = if self.allowed { "ALLOWED\n".to_string() } else { format!("REFUSED: {}\n", self.reason.as_deref().unwrap_or("")) };
        for w in &self.why {
            s.push_str(&format!("  {w}\n"));
        }
        s
    }
}

/// What the executor checks before acting on an `Install` or a `Run` of a file: the bytes are
/// exactly the ones the program pins (hash, and size for an install).
pub fn check_content(step: &Step, steps: &[Step], bytes: &[u8]) -> Result<(), String> {
    let got = hex::encode(Sha256::digest(bytes));
    let (want, size) = match step {
        Step::Install { sha256, size, .. } => (*sha256, Some(*size)),
        Step::Run { exe: Exe::Path { sha256, .. }, .. } => (*sha256, None),
        Step::Run { exe: Exe::Output(j), .. } => match steps.get(*j as usize) {
            Some(Step::Install { sha256, size, .. }) => (*sha256, Some(*size)),
            _ => return Err("the step runs no file".into()),
        },
        _ => return Err("this step names no file content".into()),
    };
    if got != hex::encode(want) || size.is_some_and(|s| s != bytes.len() as u64) {
        return Err(format!(
            "content hash mismatch: the bytes are sha256:{got} ({} bytes), the grant pins sha256:{}{}",
            bytes.len(),
            hex::encode(want),
            size.map(|s| format!(" ({s} bytes)")).unwrap_or_default()
        ));
    }
    Ok(())
}

fn caps(t: &TokenV3) -> Vec<Option<&CapabilityV3>> {
    t.links.iter().map(|l| if let Link::V3 { cap, .. } = l { Some(cap) } else { None }).collect()
}

/// Run the verifier for `req` on `t` and explain the outcome.
pub fn check(t: &TokenV3, req: &CheckRequest, l: &Labels) -> Verdict {
    let owners: Vec<OwnerRoot> = req.roots.iter().map(|k| OwnerRoot { key: *k, rp_id: None, not_before: 0, not_after: 0 }).collect();
    let roots = Roots { keys: &req.roots, owners: &owners };
    let no_revocations = |_: &Key, _: u64| false;
    let refused = |reason: String, why: Vec<String>| Verdict { allowed: false, reason: Some(reason), why };
    // The chain alone first, so a chain-level refusal is explained as such.
    if let Err(e) = verify_chain_v3(t, &roots, req.now, &no_revocations) {
        return refused(e.clone(), chain_why(t, &e, req, l));
    }
    let mut steps: Vec<Step> = Vec::new();
    let program_step = match &req.action {
        Action::Call(_) => None,
        Action::Step { program, step, .. } => {
            let body = match program::find(program, &t.programs).and_then(|p| program::expand(p, &t.programs)) {
                Ok(s) => s,
                Err(e) => return refused(e, vec![format!("The token does not carry a usable body for {}.", program_name(program, l))]),
            };
            steps = body;
            match steps.get(*step as usize) {
                Some(s) => Some(s.clone()),
                None => return refused(format!("program has no step {step}"), vec![format!("{} has {} steps.", program_name(program, l), steps.len())]),
            }
        }
    };
    let request = match (&req.action, &program_step) {
        (Action::Call(a), _) => Request::Call(a),
        (Action::Step { program, run, step }, Some(s)) => Request::Execute { program: *program, run: *run, step: *step, req: s },
        _ => unreachable!(),
    };
    let at_node = Node { id: req.node, tags: &req.tags, host: req.host.as_deref() };
    let mut burn = |_: &crate::v3::verify::Charge| Ok(());
    let result = match &req.presented {
        None => authorize_v3(&at_node, &roots, req.now, &req.requester, &request, t, &no_revocations, &mut burn),
        Some((r, proofs, body)) => {
            let mut first = |_: &Hash, _: u64| Ok(());
            let mut used = Presented { request: r, proofs, body: Sha256::digest(body).into(), cell_keys: req.cell_keys, first_use: &mut first };
            authorize_use_v3(&at_node, &roots, req.now, &req.requester, &request, t, &mut used, &no_revocations, &mut burn)
        }
    };
    match result {
        Err(e) => {
            let why = use_why(t, &e, req, l);
            refused(e, why)
        }
        Ok(v) => {
            if let (Some(bytes), Some(s)) = (&req.content, &program_step) {
                if let Err(e) = check_content(s, &steps, bytes) {
                    return refused(e, vec!["The executor hashes the bytes before acting and refuses any that differ from the pinned hash: the chain is valid, these bytes are not the ones it allows.".into()]);
                }
            }
            let mut why = vec![format!("The chain roots at {} and every link verifies.", key(&v.root, l))];
            why.push(match &req.action {
                Action::Call(a) => format!("{} may '{a}' at {}.", key(&req.requester, l), node(&req.node, l)),
                Action::Step { program, run, step } => format!("{} may run step {step} of {}, run {run}, at {}.", key(&req.requester, l), program_name(program, l), node(&req.node, l)),
            });
            if req.content.is_some() {
                why.push("The file's bytes hash to the pinned sha256.".into());
            }
            if !v.conditions.is_empty() {
                why.push("Every condition of every link is met by the proofs presented.".into());
            }
            if !v.counted.is_empty() {
                why.push("Counters were not charged: this is a dry run against a node with no earlier uses.".into());
            }
            Verdict { allowed: true, reason: None, why }
        }
    }
}

/// `link i: <msg>` -> (i, msg).
fn at_link(e: &str) -> Option<(usize, &str)> {
    let rest = e.strip_prefix("link ")?;
    let (i, msg) = rest.split_once(": ")?;
    Some((i.parse().ok()?, msg))
}

fn chain_why(t: &TokenV3, e: &str, req: &CheckRequest, l: &Labels) -> Vec<String> {
    let cs = caps(t);
    if e.contains("does not root at an accepted authority") {
        let issuer = cs.first().copied().flatten().map(|c| key(&c.issuer, l)).unwrap_or_else(|| "a v1 key".into());
        let accepted = if req.roots.is_empty() { "none".to_string() } else { req.roots.iter().map(|k| key(k, l)).collect::<Vec<_>>().join("; ") };
        return vec![format!("Link 0 is signed by {issuer}, which this node does not accept as a root."), format!("Accepted roots: {accepted}.")];
    }
    let Some((i, msg)) = at_link(e) else { return vec![format!("The token itself is refused: {e}.")] };
    let c = cs.get(i).copied().flatten();
    let who = c.map(|c| format!("{} -> {}", explain_short(&c.issuer, l), explain_short(&c.audience, l))).unwrap_or_default();
    let mut v = Vec::new();
    match msg {
        "invalid signature" => v.push(format!("Link {i} ({who}) is not signed by its issuer's key over its exact bytes: it was changed after signing, or signed by someone else.")),
        "capability has expired" => v.push(format!("Link {i} ({who}) expired at {}; now is {}.", c.map(|c| super::units::say_time(c.caveats.not_after)).unwrap_or_default(), super::units::say_time(req.now))),
        "capability not yet valid" => v.push(format!("Link {i} ({who}) is not valid before {}.", c.map(|c| super::units::say_time(c.caveats.not_before)).unwrap_or_default())),
        "capability revoked" => v.push(format!("Link {i} ({who}) has been revoked by its issuer.")),
        _ => {
            if let (Some(child), Some(parent)) = (c, i.checked_sub(1).and_then(|p| cs.get(p).copied().flatten())) {
                let d = why_child(child, parent, l);
                if !d.is_empty() {
                    v.push(format!("Link {i} ({who}) is not inside what link {} lets {} grant: {d}.", i - 1, explain_short(&parent.audience, l)));
                }
            }
            if v.is_empty() {
                v.push(format!("Link {i} ({who}) is refused: {msg}."));
            }
        }
    }
    v.push("No node accepts this chain, whatever is asked.".into());
    v
}

fn explain_short(k: &Key, l: &Labels) -> String {
    l.key(k).map(str::to_string).unwrap_or_else(|| super::refs::fmt_key(k))
}

fn use_why(t: &TokenV3, e: &str, req: &CheckRequest, l: &Labels) -> Vec<String> {
    let cs: Vec<&CapabilityV3> = caps(t).into_iter().flatten().collect();
    let Some(leaf) = cs.last() else { return vec![e.to_string()] };
    let mut v = Vec::new();
    if e == "leaf capability is not held by the request sender" {
        v.push(format!("The chain is held by {}; the request comes from {}. Only the leaf's audience may use a chain.", key(&leaf.audience, l), key(&req.requester, l)));
    } else if let Some(a) = e.strip_prefix("capability does not grant '").and_then(|x| x.strip_suffix('\'')) {
        if leaf.abilities.is_empty() {
            v.push(format!("The leaf lets {} grant, not act: it has no abilities of its own, so '{a}' is refused.", explain_short(&leaf.audience, l)));
        } else {
            v.push(format!("The leaf grants {}; none of them covers '{a}'.", leaf.abilities.iter().map(|x| format!("'{x}'")).collect::<Vec<_>>().join(", ")));
        }
    } else if e == "capability is bound to a program" {
        v.push("The chain may only execute its bound programs, step by step; a plain call is refused.".into());
    } else if e == "program is not the one granted" {
        let bound = leaf.ext.iter().find_map(|c| if let Caveat::Programs(ids) = c { Some(ids.clone()) } else { None }).unwrap_or_default();
        v.push(format!("The chain is bound to {}; the request names another program.", bound.iter().map(|i| program_name(i, l)).collect::<Vec<_>>().join(", or ")));
    } else if let Some((i, "resource does not match this node")) = at_link(e) {
        v.push(format!("Link {i} applies {}; this request is at {}.", cs.get(i).map(|c| resource(&c.resource, l)).unwrap_or_default(), node(&req.node, l)));
    } else if let Some(rest) = e.strip_prefix("program step ") {
        v.push(format!("The program does not type under the leaf: step {rest}. The leaf allows only {}.", if leaf.abilities.is_empty() { "nothing of its own".to_string() } else { leaf.abilities.join(", ") }));
    } else if e.starts_with("condition not met: ") {
        let kind = &e["condition not met: ".len()..];
        for c in leaf.ext.iter() {
            match (kind, c) {
                ("requires", Caveat::Requires(rs)) => {
                    for r in rs {
                        v.push(format!("Every use needs proof that {}; this use did not present a valid one.", requirement(r, l)));
                    }
                }
                ("cosign", Caveat::CoSign(cs)) => {
                    for c in cs {
                        v.push(format!("Every use must be co-signed by {} over its exact request; this use was not.", key(&c.by, l)));
                    }
                }
                ("via", Caveat::Via(ps)) => {
                    for p in ps {
                        let note = match p {
                            Party::Cell(api) if (req.cell_keys)(api).is_empty() => " (this node knows no key for that cell, so nothing can meet it here)",
                            _ => "",
                        };
                        v.push(format!("Every use must come through {}{note}; this use carries no valid approval of its exact request.", explain::party(p, l)));
                    }
                }
                _ => {}
            }
        }
        if req.presented.is_none() {
            v.push("No use request and proofs were presented (pass --request and --proofs).".into());
        }
    } else if e == "capability used up" {
        v.push("A counter of this chain is spent at this node.".into());
    } else if e.starts_with("use request is not this use") {
        v.push("The presented use request names another leaf, node, requester, action or body than this use: signatures over it approve nothing here.".into());
    } else if e.starts_with("use request is outside") {
        v.push("The use request is more than 300 s away from now: approvals expire with their request.".into());
    } else if e.starts_with("the request is not program step") || e.ends_with("is not for this node") {
        v.push("The step asked for is not exactly the program's step at this node.".into());
    }
    if v.is_empty() {
        v.push(format!("The verifier refused: {e}."));
    }
    v
}
