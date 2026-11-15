//! Canonical form of a v3 token (`docs/CAPABILITY-PROGRAMS.md` sections 3.4 and 7). A link that
//! fails is refused with `"link i: not canonical"`; the reason follows for diagnostics.
//!
//! These are structural rules on one link at a time. Chain rules (continuity, narrowing, the
//! v1-before-v3 order, signature type against issuer key) belong to the verifier.

use super::{Caveat, CapabilityV3, Delegate, Link, MAX_ABILITIES, MAX_LINKS, MAX_PROGRAMS, TokenV3, UsePer};
use super::types::AudienceSet;
use crate::program::{CUMULATIVE_LIMITS, egress_canonical, sorted_unique, sorted_unique_by_encoding};
use crate::{Error, Result};

/// Size bounds of the token and the canonical form of every V3 link.
pub fn check_token(t: &TokenV3) -> Result<()> {
    if t.links.len() > MAX_LINKS {
        return Err(Error(format!("capability chain has more than {MAX_LINKS} links")));
    }
    if t.programs.len() > MAX_PROGRAMS {
        return Err(Error(format!("token carries more than {MAX_PROGRAMS} programs")));
    }
    for (i, l) in t.links.iter().enumerate() {
        check_link(l).map_err(|why| Error(format!("link {i}: not canonical ({why})")))?;
    }
    Ok(())
}

/// One link. A V1 link is canonical by the v1 rules (its bincode is canonical already).
pub fn check_link(l: &Link) -> Result<(), String> {
    match l {
        Link::V1(_) => Ok(()),
        Link::V3 { cap, sig } => {
            if !sig.canonical() {
                return Err("P-256 signature is not low-S".into());
            }
            check_cap(cap)
        }
    }
}

/// The section 3.4 and section 7 rules for one statement.
pub fn check_cap(c: &CapabilityV3) -> Result<(), String> {
    if c.v != 3 {
        return Err("v must be 3".into());
    }
    if !c.issuer.canonical() || !c.audience.canonical() {
        return Err("malformed key".into());
    }
    if c.abilities.len() > MAX_ABILITIES {
        return Err(format!("more than {MAX_ABILITIES} abilities"));
    }
    if !c.resource.canonical() {
        return Err("resource lists must be sorted, unique, non-empty".into());
    }
    if let Some(d) = &c.delegate {
        check_delegate(d)?;
    }
    if !c.ext.windows(2).all(|w| w[0].index() < w[1].index()) {
        return Err("ext must hold at most one caveat per variant, ascending".into());
    }
    for cv in &c.ext {
        check_caveat(cv)?;
    }
    check_counted(c)
}

fn check_delegate(d: &Delegate) -> Result<(), String> {
    if d.depth < 1 {
        return Err("delegate.depth must be >= 1".into());
    }
    if d.abilities.is_empty() || d.abilities.len() > MAX_ABILITIES {
        return Err(format!("delegate.abilities must hold 1..={MAX_ABILITIES} entries"));
    }
    match &d.audience {
        AudienceSet::Any => Ok(()),
        AudienceSet::Keys(ks) => {
            if ks.is_empty() || !sorted_unique_by_encoding(ks) || !ks.iter().all(|k| k.canonical()) {
                Err("delegate.audience keys must be sorted by encoding, unique, non-empty".into())
            } else {
                Ok(())
            }
        }
    }
}

fn check_caveat(c: &Caveat) -> Result<(), String> {
    match c {
        Caveat::Uses { max, .. } if *max < 1 => Err("Uses.max must be >= 1".into()),
        Caveat::Uses { .. } => Ok(()),
        Caveat::Limits(ls) => {
            let names: Vec<&str> = ls.iter().map(|l| l.name.as_str()).collect();
            if sorted_unique(&names) { Ok(()) } else { Err("Limits must be sorted by name, unique".into()) }
        }
        Caveat::Egress(rules) => {
            if egress_canonical(rules) { Ok(()) } else { Err("Egress rules must be canonical, sorted, unique".into()) }
        }
        Caveat::Programs(ids) => {
            if !ids.is_empty() && sorted_unique(ids) { Ok(()) } else { Err("Programs must be sorted, unique, non-empty".into()) }
        }
    }
}

/// Section 7: a counted link (it carries `Uses` or a cumulative limit) expires and names a finite
/// set of nodes; with `per: Action` its reachable abilities hold no wildcard.
fn check_counted(c: &CapabilityV3) -> Result<(), String> {
    let uses = c.ext.iter().find_map(|cv| match cv {
        Caveat::Uses { per, .. } => Some(*per),
        _ => None,
    });
    let cumulative = c.ext.iter().any(|cv| match cv {
        Caveat::Limits(ls) => ls.iter().any(|l| CUMULATIVE_LIMITS.contains(&l.name.as_str())),
        _ => false,
    });
    if uses.is_none() && !cumulative {
        return Ok(());
    }
    if c.caveats.not_after == 0 {
        return Err("a counted link must set caveats.not_after".into());
    }
    if !c.resource.is_finite() {
        return Err("a counted link must name a finite resource (Node or Nodes)".into());
    }
    if uses == Some(UsePer::Action) {
        let reach = c.abilities.iter().chain(c.delegate.iter().flat_map(|d| d.abilities.iter()));
        if reach.into_iter().any(|a| a.contains('*')) {
            return Err("Uses per Action needs abilities without wildcards".into());
        }
    }
    Ok(())
}
