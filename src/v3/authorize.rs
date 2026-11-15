//! Authorizing one request at one node (`docs/CAPABILITY-PROGRAMS.md` section 5.2): the chain
//! walk of [`super::verify`] with this node's resource check, then the leaf against the request,
//! then the conditions of section 4.1 against the proofs of this use ([`super::verify_cond`]),
//! and last the counters (section 7).
//!
//! Two entry points. [`authorize_v3`] is handed no proofs, so it refuses every chain that carries
//! a condition. [`authorize_use_v3`] is handed the [`Presented`] request and proofs of one use.
//! Nothing is recorded (request id, counters) before every check has passed.

use super::verify::{Counted, Node, Roots, VerifiedV3, walk};
use super::verify_cond::{Presented, check_use};
use super::{Caveat, Key, TokenV3};
use crate::program::{self, Hash, NodeKey, Scope, Step};

/// What is asked for.
#[derive(Debug, Clone, Copy)]
pub enum Request<'a> {
    /// A plain call: the most specific ability the cell checks.
    Call(&'a str),
    /// Step `step` of program `program`, execution `run`; `req` is the concrete step asked for.
    Execute { program: Hash, run: u32, step: u32, req: &'a Step },
}

/// What [`authorize_v3`] hands `burn` once every check has passed (section 7).
#[derive(Debug, Clone)]
pub struct Charge<'a> {
    pub leaf: Hash,
    /// Every counted link of the chain, root first; all are charged or none.
    pub counted: &'a [Counted],
    /// The charged action (`scope` of a `per: Action` counter).
    pub action: String,
    /// `(program_id, run)` for a program step. With `leaf` it names the run: `per: Link` is
    /// charged once per `(leaf, program, run)` at this node (6.4).
    pub program: Option<(Hash, u32)>,
}

/// Section 5.2: may `requester` (the key proved in the transport handshake) make `req` at `node`?
///
/// As [`super::verify::verify_chain_v3`], plus: every link's resource matches `node`; the leaf's
/// audience is `requester`; a leaf ability covers the action (never `delegate.abilities`); a chain
/// bound to programs authorizes only a step of one of them; a step is typed under the leaf and is
/// exactly the step asked for, on this node.
///
/// No proofs are presented here, so a chain in which any link carries a condition (`Requires`,
/// `CoSign`, `Via`) is refused with `"condition not met: ..."`: use [`authorize_use_v3`].
///
/// After every check has passed, and only then, `burn` is called once if the chain has counted
/// links. It must charge every one atomically or return the refusal (`"capability used up"`,
/// `"clock went backwards"`), which is returned as is. A cell that keeps a run log checks it
/// inside `burn` before charging: [`Charge`] carries the leaf and the `(program, run)`, and a
/// step runs at most once per `(leaf, program, run)`. On success the verified chain is returned;
/// its `caveats`, `ext` and `counted` are what the cell enforces.
#[allow(clippy::too_many_arguments)]
pub fn authorize_v3(
    node: &Node,
    roots: &Roots,
    now: u64,
    requester: &Key,
    req: &Request,
    t: &TokenV3,
    is_revoked: &dyn Fn(&Key, u64) -> bool,
    burn: &mut dyn FnMut(&Charge) -> Result<(), String>,
) -> Result<VerifiedV3, String> {
    authorize(node, roots, now, requester, req, t, None, is_revoked, burn)
}

/// [`authorize_v3`] for a use that presents its exact request and proofs (section 4.1).
///
/// On top of [`authorize_v3`]: `used.request` must be this use (this leaf, node, requester,
/// charged action, the body hash the node computed, made within 300 s of `now`), and every
/// condition of every link must be met by a proof in `used.proofs`. Then `used.first_use` is
/// asked to record the request id (it refuses one it has seen: a replay), and only then `burn`
/// runs. The node holds one lock over both callbacks. A use refused by `burn` has spent its
/// request id; the requester retries with a new `nonce`.
///
/// The charged action a co-signer and a broker sign is the action of a [`Request::Call`], and for
/// a program step that step's most specific ability (6.4 rule 5).
#[allow(clippy::too_many_arguments)]
pub fn authorize_use_v3(
    node: &Node,
    roots: &Roots,
    now: u64,
    requester: &Key,
    req: &Request,
    t: &TokenV3,
    used: &mut Presented,
    is_revoked: &dyn Fn(&Key, u64) -> bool,
    burn: &mut dyn FnMut(&Charge) -> Result<(), String>,
) -> Result<VerifiedV3, String> {
    authorize(node, roots, now, requester, req, t, Some(used), is_revoked, burn)
}

#[allow(clippy::too_many_arguments)]
fn authorize(
    node: &Node,
    roots: &Roots,
    now: u64,
    requester: &Key,
    req: &Request,
    t: &TokenV3,
    used: Option<&mut Presented>,
    is_revoked: &dyn Fn(&Key, u64) -> bool,
    burn: &mut dyn FnMut(&Charge) -> Result<(), String>,
) -> Result<VerifiedV3, String> {
    let v = walk(t, roots, Some(node), now, is_revoked)?;
    if &v.holder != requester {
        return Err("leaf capability is not held by the request sender".into());
    }
    let (action, program) = match *req {
        Request::Call(action) => {
            if !v.grants(action) {
                return Err(format!("capability does not grant '{action}'"));
            }
            if v.programs().is_some() {
                return Err("capability is bound to a program".into());
            }
            (action.to_string(), None)
        }
        Request::Execute { program, run, step, req } => (execute(node, &v, t, program, step, req)?, Some((program, run))),
    };
    // 4.1: the conditions of every link, against this exact use. Last before anything is recorded.
    check_use(&v, &node.id, &action, roots, now, used)?;
    if !v.counted.is_empty() {
        burn(&Charge { leaf: v.leaf(), counted: &v.counted, action, program })?;
    }
    Ok(v)
}

/// Section 6.4 rules 2 to 4 for one step; answers the charged action (rule 5).
fn execute(node: &Node, v: &VerifiedV3, t: &TokenV3, id: Hash, index: u32, req: &Step) -> Result<String, String> {
    // Rule 2. The bodies in the token are unsigned: one is read only once the signed chain names it.
    if v.programs().is_some_and(|ids| !ids.contains(&id)) {
        return Err("program is not the one granted".into());
    }
    // Rule 3: the body hashes to the id, and the whole program is well-typed under the leaf.
    let steps = program::expand(program::find(&id, &t.programs)?, &t.programs)?;
    let ext = |pick: fn(&Caveat) -> bool| v.ext.iter().find(|c| pick(c));
    let scope = Scope {
        abilities: &v.abilities,
        resource: &v.resource,
        path_prefix: v.caveats.path_prefix.as_deref(),
        max_cpu: v.caveats.max_cpu,
        max_mem_mb: v.caveats.max_mem_mb,
        egress: match ext(|c| matches!(c, Caveat::Egress(_))) {
            Some(Caveat::Egress(rules)) => Some(rules.as_slice()),
            _ => None,
        },
        limits: match ext(|c| matches!(c, Caveat::Limits(_))) {
            Some(Caveat::Limits(ls)) => ls.as_slice(),
            _ => &[],
        },
    };
    let host_of = |n: &NodeKey| if n == &node.id { node.host.map(str::to_string) } else { None };
    program::type_check(&steps, &scope, &host_of)?;
    // Rule 4, the part that needs no run log: the step is for this node and is the one asked for.
    let s = program::check_request(&steps, index, &node.id, req)?;
    if matches!(s, Step::InstallCell { .. }) && node.host.is_none() {
        return Err("this node's hostname is needed to check an InstallCell step".into());
    }
    // Rule 1: the leaf grants every ability of this step, the exact `@host` one included.
    let needed = program::abilities_for(s, node.host);
    if let Some(a) = needed.iter().find(|a| !v.grants(a)) {
        return Err(format!("capability does not grant '{a}'"));
    }
    needed.last().cloned().ok_or_else(|| format!("program step {index} needs no ability and cannot be executed"))
}
