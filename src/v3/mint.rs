//! Minting v3 links (`docs/CAPABILITY-PROGRAMS.md` section 5.3): a root link, and a child
//! attenuated from a parent the signer holds.
//!
//! The minter refuses to sign anything that would not verify: the new statement must be canonical
//! (section 3.4, [`canon::check_cap`]) and, below a parent, pass every check of section 5.1 step
//! 3.4 ([`check_child`]): the signer is the parent's audience, the parent may delegate, the child's
//! audience and abilities are inside the parent's grant, a re-delegation right drops the depth by
//! at least one and grants no more abilities or audience, the resource is no broader, and the
//! caveats are no looser (expiry, v1 ceilings, `Uses`, `Limits`, `Egress`, `Programs`). This is a
//! courtesy to the holder; safety rests on the verifier, which runs the same predicates.
//!
//! The nonce is the caller's: it must be random (it names the link for revocation), and this crate
//! has no RNG.

use super::canon;
use super::narrow::{Parent, check_child};
use super::sign::{Signer, verify_sig};
use super::{Caveat, CapabilityV3, Delegate, Key, Link, MAX_LINKS, TokenV3};
use crate::cap::Caveats;
use crate::program::{Hash, ResourceV3};
use crate::{Error, Result};

/// What a new link grants. The issuer is the signer and the parent is the link minted under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub audience: Key,
    /// What the audience may itself do; may be empty.
    pub abilities: Vec<String>,
    pub resource: ResourceV3,
    pub caveats: Caveats,
    pub ext: Vec<Caveat>,
    /// `None`: the new link is final.
    pub delegate: Option<Delegate>,
    /// Random, unique per issuer.
    pub nonce: u64,
}

impl Grant {
    fn statement(self, issuer: Key, parent: Option<Hash>) -> CapabilityV3 {
        CapabilityV3 {
            v: 3,
            issuer,
            audience: self.audience,
            abilities: self.abilities,
            resource: self.resource,
            caveats: self.caveats,
            ext: self.ext,
            delegate: self.delegate,
            nonce: self.nonce,
            parent,
        }
    }
}

fn refuse(why: impl std::fmt::Display) -> Error {
    Error(format!("refusing to mint: {why}"))
}

/// Canonical check, sign, and check the signature just made.
fn seal(signer: &Signer, cap: CapabilityV3) -> Result<Link> {
    canon::check_cap(&cap).map_err(|why| refuse(format!("not canonical ({why})")))?;
    let sig = signer.sign(&cap);
    verify_sig(&cap, &sig).map_err(refuse)?;
    Ok(Link::V3 { cap, sig })
}

/// A root link (`parent: None`) signed by `signer`. Whether its issuer is an accepted root is the
/// verifying node's decision (section 9), not the minter's.
pub fn mint_root(signer: &Signer, grant: Grant) -> Result<Link> {
    seal(signer, grant.statement(signer.key(), None))
}

/// A child of `parent` signed by `signer`, refused unless it is no wider than `parent` allows.
pub fn attenuate(signer: &Signer, parent: &Link, grant: Grant) -> Result<Link> {
    let p = Parent::of(parent);
    let cap = grant.statement(signer.key(), Some(p.id));
    check_child(&cap, &p).map_err(refuse)?;
    seal(signer, cap)
}

/// A one-link token holding a fresh root.
pub fn root_token(signer: &Signer, grant: Grant) -> Result<TokenV3> {
    Ok(TokenV3 { links: vec![mint_root(signer, grant)?], programs: Vec::new() })
}

/// `token` with a child of its leaf appended; the program bodies are kept.
pub fn extend(token: &TokenV3, signer: &Signer, grant: Grant) -> Result<TokenV3> {
    let Some(leaf) = token.links.last() else {
        return Err(refuse("the token has no links"));
    };
    if token.links.len() >= MAX_LINKS {
        return Err(refuse(format!("a chain holds at most {MAX_LINKS} links")));
    }
    let mut out = token.clone();
    out.links.push(attenuate(signer, leaf, grant)?);
    Ok(out)
}
