//! Carrying conditions down a chain at mint (`docs/CAPABILITY-PROGRAMS.md` sections 4 and 4.1).
//!
//! A child link must repeat every `Requires`, `CoSign` and `Via` entry of its parent, or the minter
//! and every verifier refuse it. [`inherit_conditions`] writes the parent's entries into the `ext`
//! of a grant, so a holder who only wants to add a condition, or none, cannot drop one by
//! forgetting it. It only ever adds entries or tightens a freshness bound; the result still goes
//! through the same checks as a hand-written grant.

use serde::Serialize;

use super::cond::Requirement;
use super::narrow::{Parent, fresh_no_looser};
use super::{Caveat, Link};

/// Sort by bincode encoding and drop exact duplicates: the canonical order of section 3.4.
fn canonical_order<T: Serialize>(v: &mut Vec<T>) {
    let enc = |x: &T| bincode::serialize(x).expect("bincode of a condition entry to a Vec is infallible");
    v.sort_by_cached_key(enc);
    v.dedup_by(|a, b| enc(a) == enc(b));
}

/// `mine` with every entry of `theirs` added.
fn union<T: Serialize + Clone + PartialEq>(mine: &mut Vec<T>, theirs: &[T]) {
    for t in theirs {
        if !mine.contains(t) {
            mine.push(t.clone());
        }
    }
    canonical_order(mine);
}

/// `mine` with every requirement of `theirs`: one entry per witness and claim, with the tighter
/// freshness of the two.
fn union_requires(mine: &mut Vec<Requirement>, theirs: &[Requirement]) {
    for t in theirs {
        match mine.iter_mut().find(|m| m.witness == t.witness && m.claim == t.claim) {
            Some(m) if fresh_no_looser(m.fresh_within_s, t.fresh_within_s) => {}
            Some(m) => m.fresh_within_s = t.fresh_within_s,
            None => mine.push(t.clone()),
        }
    }
    canonical_order(mine);
}

/// `ext` with every condition of `parent` added: what a child of `parent` must carry at least.
///
/// Entries already in `ext` are kept (a child may add conditions); a `Requires` entry the parent
/// also has takes the tighter freshness. Caveats that are not conditions are left as given; the
/// result is ordered by variant. A V1 parent carries no conditions, so `ext` comes back as given.
pub fn inherit_conditions(parent: &Link, mut ext: Vec<Caveat>) -> Vec<Caveat> {
    for p in Parent::of(parent).ext.iter().filter(|c| c.is_condition()) {
        match (ext.iter_mut().find(|c| c.index() == p.index()), p) {
            (Some(Caveat::Requires(mine)), Caveat::Requires(theirs)) => union_requires(mine, theirs),
            (Some(Caveat::CoSign(mine)), Caveat::CoSign(theirs)) => union(mine, theirs),
            (Some(Caveat::Via(mine)), Caveat::Via(theirs)) => union(mine, theirs),
            _ => ext.push(p.clone()),
        }
    }
    ext.sort_by_key(Caveat::index);
    ext
}
