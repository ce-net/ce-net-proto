//! Conditions at use (`docs/CAPABILITY-PROGRAMS.md` section 4.1): does one request, with the
//! proofs it presents, meet every `Requires`, `CoSign` and `Via` of every link of a verified chain?
//!
//! The chain walk has already held the conditions to their canonical form and to narrowing (a
//! child that drops or loosens one is refused there). What is decided here, per use:
//!
//! - the [`UseRequest`] is this use and no other: this leaf, node, requester and action, the hash
//!   of the body the node received, made within [`USE_WINDOW_S`] of now;
//! - every presented proof is well-formed; each one's signature is checked once, and a proof that
//!   does not verify counts for nothing (it is never an error that could be mistaken for approval);
//! - `Requires`: a witness the entry names attests the claim of the requester, not in the future
//!   and fresh enough;
//! - `CoSign`: the named key signed `cosign_bytes` of this request;
//! - `Via`: a broker the entry names signed `via_bytes` of this request;
//! - last, the request id is recorded, and one seen before is refused.
//!
//! No proofs at all (`None`) meets no condition. A `Party::Cell` the node cannot resolve to keys
//! meets nothing. Each refusal names the kind of condition, never which proof came close.

use super::cond::{
    AttestationBody, CoSigner, MAX_PROOFS, Party, Proof, Requirement, UseRequest, attest_bytes, cosign_bytes, request_id,
    via_bytes,
};
use super::verify::{Roots, VerifiedV3, check_sig_bytes};
use super::{Caveat, Key};
use crate::program::{Hash, NodeKey};

/// A `UseRequest` is accepted only if made at most this many seconds before or after `now`.
pub const USE_WINDOW_S: u64 = 300;

/// What one use presents beside its token, and what the node knows about it.
pub struct Presented<'a> {
    /// The exact request the requester, each co-signer and each broker signed off.
    pub request: &'a UseRequest,
    /// The proofs of this use, strictly decoded ([`super::cond::decode_proofs`]).
    pub proofs: &'a [Proof],
    /// SHA-256 of the request body **as this node received it**, computed by the node. Never
    /// copied from `request`: the comparison is what binds the signatures to the body.
    pub body: Hash,
    /// The keys this node trusts for a cell api (`Party::Cell`); empty when it knows none.
    pub cell_keys: &'a dyn Fn(&str) -> Vec<Key>,
    /// The node's replay log: `first_use(request_id, forget_after)` records the id and answers
    /// `Err` (e.g. `"request replayed"`) for one already recorded. The id may be dropped once
    /// `now > forget_after`: from then on the time window refuses the request by itself.
    pub first_use: &'a mut dyn FnMut(&Hash, u64) -> Result<(), String>,
}

/// The proofs of one use whose signatures verified.
struct Valid<'a> {
    attested: Vec<&'a AttestationBody>,
    cosigned: Vec<&'a Key>,
    brokered: Vec<&'a Key>,
}

fn valid<'a>(proofs: &'a [Proof], r: &UseRequest, roots: &Roots, now: u64) -> Valid<'a> {
    let mut out = Valid { attested: Vec::new(), cosigned: Vec::new(), brokered: Vec::new() };
    let (cosign, via) = (cosign_bytes(r), via_bytes(r));
    for p in proofs {
        match p {
            Proof::Attested(a) => {
                if check_sig_bytes(&a.body.witness, &attest_bytes(&a.body), &a.sig, roots, now).is_ok() {
                    out.attested.push(&a.body);
                }
            }
            Proof::CoSigned { by, sig } => {
                if check_sig_bytes(by, &cosign, sig, roots, now).is_ok() {
                    out.cosigned.push(by);
                }
            }
            Proof::Brokered { broker, sig } => {
                if check_sig_bytes(broker, &via, sig, roots, now).is_ok() {
                    out.brokered.push(broker);
                }
            }
        }
    }
    out
}

/// The keys that may speak for `party` at this node.
fn keys_of(party: &Party, cell_keys: &dyn Fn(&str) -> Vec<Key>) -> Vec<Key> {
    match party {
        Party::Key(k) => vec![*k],
        Party::Cell(api) => cell_keys(api),
    }
}

fn requirement_met(r: &Requirement, v: &Valid, requester: &Key, now: u64, cell_keys: &dyn Fn(&str) -> Vec<Key>) -> bool {
    let witnesses = keys_of(&r.witness, cell_keys);
    v.attested.iter().any(|a| {
        witnesses.contains(&a.witness)
            && &a.subject == requester
            && r.claim.proved_by(&a.claim)
            && a.at <= now
            && r.fresh_within_s.is_none_or(|n| now - a.at <= n)
    })
}

fn cosigned(c: &CoSigner, v: &Valid) -> bool {
    v.cosigned.contains(&&c.by)
}

fn brokered(b: &Party, v: &Valid, cell_keys: &dyn Fn(&str) -> Vec<Key>) -> bool {
    let brokers = keys_of(b, cell_keys);
    v.brokered.iter().any(|k| brokers.contains(k))
}

/// The refusal for an unmet entry of `c`.
fn not_met(c: &Caveat) -> String {
    let kind = match c {
        Caveat::Requires(_) => "requires",
        Caveat::CoSign(_) => "cosign",
        _ => "via",
    };
    format!("condition not met: {kind}")
}

/// Is `r` the use being authorized? Each field against what the node itself knows.
fn check_request(r: &UseRequest, v: &VerifiedV3, node: &NodeKey, action: &str, body: &Hash, now: u64) -> Result<(), String> {
    r.check().map_err(|why| format!("use request is malformed ({why})"))?;
    let wrong = |field: &str| Err(format!("use request is not this use ({field})"));
    if r.leaf != v.leaf() {
        return wrong("leaf");
    }
    if &r.node != node {
        return wrong("node");
    }
    if r.requester != v.holder {
        return wrong("requester");
    }
    if r.action != action {
        return wrong("action");
    }
    if &r.body != body {
        return wrong("body");
    }
    if now.abs_diff(r.at) > USE_WINDOW_S {
        return Err(format!("use request is outside the {USE_WINDOW_S} s window"));
    }
    Ok(())
}

/// Section 4.1 for one use of the verified chain `v` (whose holder is the requester) for `action`
/// at `node`. With `used` the request is checked and, once every condition is met, recorded as
/// used; without it only a chain free of conditions passes.
pub(super) fn check_use(
    v: &VerifiedV3,
    node: &NodeKey,
    action: &str,
    roots: &Roots,
    now: u64,
    used: Option<&mut Presented>,
) -> Result<(), String> {
    let Some(used) = used else {
        return v.conditions.first().map_or(Ok(()), |c| Err(not_met(c)));
    };
    if used.proofs.len() > MAX_PROOFS {
        return Err(format!("more than {MAX_PROOFS} proofs"));
    }
    for (i, p) in used.proofs.iter().enumerate() {
        p.check().map_err(|why| format!("proof {i}: not canonical ({why})"))?;
    }
    check_request(used.request, v, node, action, &used.body, now)?;
    let ok = valid(used.proofs, used.request, roots, now);
    for c in &v.conditions {
        let met = match c {
            Caveat::Requires(rs) => rs.iter().all(|r| requirement_met(r, &ok, &v.holder, now, used.cell_keys)),
            Caveat::CoSign(cs) => cs.iter().all(|c| cosigned(c, &ok)),
            Caveat::Via(bs) => bs.iter().all(|b| brokered(b, &ok, used.cell_keys)),
            // Not a condition: nothing to prove. (`conditions` holds only the three above.)
            Caveat::Uses { .. } | Caveat::Limits(_) | Caveat::Egress(_) | Caveat::Programs(_) => true,
        };
        if !met {
            return Err(not_met(c));
        }
    }
    (used.first_use)(&request_id(used.request), used.request.at.saturating_add(USE_WINDOW_S))
}
