//! Canonical form of a v3 token (`docs/CAPABILITY-PROGRAMS.md` sections 3.4 and 7). A link that
//! fails is refused with `"link i: not canonical"`; the reason follows for diagnostics.
//!
//! These are structural rules on one link at a time. Chain rules (continuity, narrowing, the
//! v1-before-v3 order, signature type against issuer key) belong to the verifier.

use super::{Caveat, CapabilityV3, Delegate, Link, MAX_ABILITIES, MAX_LINKS, MAX_PROGRAMS, TokenV3};
use super::types::AudienceSet;
use crate::program::{egress_canonical, sorted_unique, sorted_unique_by_encoding};
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

/// One link. A V1 link is canonical by the v1 rules (the token's re-encoding check already holds
/// its bytes to one form); the per-list ability bound of section 3.4 is token-wide, so it applies.
pub fn check_link(l: &Link) -> Result<(), String> {
    match l {
        Link::V1(s) if s.cap.abilities.len() > MAX_ABILITIES => Err(format!("more than {MAX_ABILITIES} abilities")),
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
    super::uses::check_counted(c)
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
