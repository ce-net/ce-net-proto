//! The child-against-parent checks of `docs/CAPABILITY-PROGRAMS.md` section 5.1 step 3.4, as pure
//! predicates. The minter ([`super::mint`]) runs them before it signs (section 5.3); the verifier
//! runs the same ones on every link. Each refusal is the spec's message without the `"link i: "`
//! prefix, which the caller adds.
//!
//! Every predicate is conservative: a pair it cannot decide is "broader", so a false answer can
//! only refuse a narrowing, never grant authority.

use super::cond::Requirement;
use super::{Caveat, CapabilityV3, Delegate, Key, Link, cap_id};
use super::types::AudienceSet;
use crate::cap::{Caveats, Resource, abilities_subset};
use crate::program::{Hash, ResourceV3, egress_narrower};

/// What a child link is checked against: a V3 link as is, a V1 link as section 3.3 reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    /// The parent's id (`cap_id`, v1 or v3): the child's `parent` must equal it.
    pub id: Hash,
    /// Who may issue the child.
    pub audience: Key,
    pub resource: ResourceV3,
    pub caveats: Caveats,
    pub ext: Vec<Caveat>,
    /// `None`: nothing may be minted below the parent.
    pub delegate: Option<Delegate>,
}

/// Depth a v1 parent grants (section 3.3): v1 lets any holder re-delegate.
pub const V1_DEPTH: u8 = 255;

/// A v1 `Resource` as the same `ResourceV3` variant.
pub fn resource_from_v1(r: &Resource) -> ResourceV3 {
    match r {
        Resource::Any => ResourceV3::Any,
        Resource::Node(n) => ResourceV3::Node(*n),
        Resource::Tag(t) => ResourceV3::Tag(t.clone()),
        Resource::AllOf(ts) => ResourceV3::AllOf(ts.clone()),
    }
}

impl Parent {
    /// The parent view of `link` (section 3.3 for a V1 link).
    pub fn of(link: &Link) -> Parent {
        match link {
            Link::V1(s) => Parent {
                id: s.id(),
                audience: Key::Ed25519(s.cap.audience),
                resource: resource_from_v1(&s.cap.resource),
                caveats: s.cap.caveats.clone(),
                ext: Vec::new(),
                delegate: Some(Delegate {
                    abilities: s.cap.abilities.clone(),
                    audience: AudienceSet::Any,
                    depth: V1_DEPTH,
                }),
            },
            Link::V3 { cap, .. } => Parent {
                id: cap_id(cap),
                audience: cap.audience,
                resource: cap.resource.clone(),
                caveats: cap.caveats.clone(),
                ext: cap.ext.clone(),
                delegate: cap.delegate.clone(),
            },
        }
    }
}

/// Is `k` one of the keys `set` admits?
pub fn audience_in(k: &Key, set: &AudienceSet) -> bool {
    match set {
        AudienceSet::Any => true,
        AudienceSet::Keys(ks) => ks.contains(k),
    }
}

/// Is `child` no broader than `parent`? `Any` only under `Any`.
pub fn audience_subset(child: &AudienceSet, parent: &AudienceSet) -> bool {
    match (child, parent) {
        (_, AudienceSet::Any) => true,
        (AudienceSet::Keys(c), AudienceSet::Keys(p)) => c.iter().all(|k| p.contains(k)),
        (AudienceSet::Any, AudienceSet::Keys(_)) => false,
    }
}

/// Is the freshness bound `child` no looser than `parent`? `None` (any age) is looser than every
/// `Some`.
pub fn fresh_no_looser(child: Option<u64>, parent: Option<u64>) -> bool {
    match (child, parent) {
        (_, None) => true,
        (Some(c), Some(p)) => c <= p,
        (None, Some(_)) => false,
    }
}

/// Does `child` still demand what `p` demands: the same witness and claim, no staler?
fn requirement_kept(child: &[Requirement], p: &Requirement) -> bool {
    child.iter().any(|c| c.witness == p.witness && c.claim == p.claim && fresh_no_looser(c.fresh_within_s, p.fresh_within_s))
}

/// One caveat variant of the section 4 table: is `c` no looser than `p` (same variant)? The three
/// conditions are conjunctions, so there the child must keep every entry of the parent (a longer
/// list is narrower); a claim or party is kept only if it is equal, never "implied".
fn caveat_narrower(c: &Caveat, p: &Caveat) -> bool {
    match (c, p) {
        (Caveat::Uses { max: cm, per: cp }, Caveat::Uses { max: pm, per: pp }) => cm <= pm && cp == pp,
        (Caveat::Limits(cl), Caveat::Limits(pl)) => {
            pl.iter().all(|p| cl.iter().any(|c| c.name == p.name && c.max <= p.max))
        }
        (Caveat::Egress(ce), Caveat::Egress(pe)) => egress_narrower(ce, pe),
        (Caveat::Programs(ci), Caveat::Programs(pi)) => ci.iter().all(|id| pi.contains(id)),
        (Caveat::Requires(cr), Caveat::Requires(pr)) => pr.iter().all(|p| requirement_kept(cr, p)),
        (Caveat::CoSign(cs), Caveat::CoSign(ps)) => ps.iter().all(|p| cs.contains(p)),
        (Caveat::Via(cb), Caveat::Via(pb)) => pb.iter().all(|p| cb.contains(p)),
        _ => false,
    }
}

/// `ext_narrower_or_equal(child, parent)`: for every variant the parent carries, the child
/// carries the same variant and is no looser. The child may add variants.
pub fn ext_narrower_or_equal(child: &[Caveat], parent: &[Caveat]) -> bool {
    parent.iter().all(|p| child.iter().any(|c| c.index() == p.index() && caveat_narrower(c, p)))
}

/// The section 5.1 step 3.4 checks of `child` against `parent`, in the spec's order.
pub fn check_child(child: &CapabilityV3, parent: &Parent) -> Result<(), String> {
    if child.issuer != parent.audience {
        return Err("issuer is not the parent's audience".into());
    }
    if child.parent != Some(parent.id) {
        return Err("parent hash does not match the chain".into());
    }
    let Some(d) = &parent.delegate else {
        return Err("the parent may not delegate".into());
    };
    if !audience_in(&child.audience, &d.audience) {
        return Err("audience is outside the parent's grant".into());
    }
    if !abilities_subset(&child.abilities, &d.abilities) {
        return Err("abilities exceed the parent's grant".into());
    }
    if let Some(e) = &child.delegate {
        if d.depth < 2 || e.depth > d.depth - 1 {
            return Err("delegation depth exceeds the parent".into());
        }
        if !abilities_subset(&e.abilities, &d.abilities) {
            return Err("grantable abilities exceed the parent".into());
        }
        if !audience_subset(&e.audience, &d.audience) {
            return Err("grantable audience exceeds the parent".into());
        }
    }
    if !child.resource.is_subset_of(&parent.resource) {
        return Err("resource is broader than the parent".into());
    }
    if !child.caveats.is_narrower_or_equal(&parent.caveats) || !ext_narrower_or_equal(&child.ext, &parent.ext) {
        return Err("caveats are broader than the parent".into());
    }
    Ok(())
}
