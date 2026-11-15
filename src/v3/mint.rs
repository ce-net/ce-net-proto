//! Minting v3 links (`docs/CAPABILITY-PROGRAMS.md` section 5.3): a root link, and a child
//! attenuated from a parent the signer holds.
//!
//! The minter refuses to sign a link that would not verify. Before any signature is made:
//!
//! - the new statement is canonical (sections 3.4 and 7, [`canon::check_cap`]);
//! - below a parent it passes every check of section 5.1 step 3.4 ([`check_child`], the same
//!   function the verifier runs): the signer is the parent's audience, the parent may delegate,
//!   the audience and abilities are inside the parent's grant, a re-delegation right drops the
//!   depth by at least one and grants no more abilities or audience, the resource is no broader,
//!   and no caveat is looser (expiry, v1 ceilings, `Uses`, `Limits`, `Egress`, `Programs`), and
//!   no condition of section 4.1 is dropped: every `Requires`, `CoSign` and `Via` entry of the
//!   parent is in the child (a `Requires` entry no staler); the child may add entries;
//! - the parent is itself a link a verifier could accept: canonical, and correctly signed where
//!   that can be checked offline (a `WebAuthn` parent needs the node's `rp_id`, so only its form
//!   is checked);
//! - the link can be valid at some time (`not_before <= not_after`), every P-256 key it names
//!   (audiences, and the witnesses, co-signers and brokers of its conditions, whose signature
//!   every use needs) is a point on the curve, and it does not reuse the `(issuer, nonce)` of a
//!   link above it, which would make one revocation name two links.
//!
//! After signing, the signature is verified against the statement's issuer. All of this is a
//! courtesy to the holder; safety rests on the verifier alone.
//!
//! A child does not inherit a condition silently: the grant must spell out every entry of the
//! parent, or the mint is refused. [`inherit_conditions`] writes them into a grant's `ext`.
//!
//! The nonce is the caller's: it must be random and unique per issuer (it names the link for
//! revocation), and this crate has no RNG.

use super::canon;
use super::cond::Party;
pub use super::mint_cond::inherit_conditions;
use super::narrow::{Parent, check_child};
use super::sign::{Signer, verify_sig};
use super::types::AudienceSet;
use super::{Caveat, CapabilityV3, Delegate, Key, Link, MAX_LINKS, MAX_TOKEN, Sig, TokenV3};
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

/// A P-256 key must decode to a curve point: nobody can sign as, or verify, one that does not.
fn key_usable(k: &Key) -> bool {
    match k {
        Key::Ed25519(_) => true,
        Key::P256(p) => p256::ecdsa::VerifyingKey::from_sec1_bytes(p).is_ok(),
    }
}

/// Checks on the statement alone, parent or not.
fn check_statement(cap: &CapabilityV3) -> Result<()> {
    canon::check_cap(cap).map_err(|why| refuse(format!("not canonical ({why})")))?;
    let c = &cap.caveats;
    if c.not_after != 0 && c.not_before > c.not_after {
        return Err(refuse("not_before is after not_after: the link would never be valid"));
    }
    let granted = match &cap.delegate {
        Some(Delegate { audience: AudienceSet::Keys(ks), .. }) => ks.as_slice(),
        _ => &[],
    };
    if !std::iter::once(&cap.audience).chain(granted).all(key_usable) {
        return Err(refuse("an audience key is not a P-256 point"));
    }
    if !cap.ext.iter().flat_map(condition_keys).all(key_usable) {
        return Err(refuse("a condition names a key that is not a P-256 point: no use could satisfy it"));
    }
    Ok(())
}

/// The fixed keys whose signature a condition demands at every use.
fn condition_keys(c: &Caveat) -> Vec<&Key> {
    fn fixed(p: &Party) -> Option<&Key> {
        match p {
            Party::Key(k) => Some(k),
            Party::Cell(_) => None,
        }
    }
    match c {
        Caveat::Requires(rs) => rs.iter().filter_map(|r| fixed(&r.witness)).collect(),
        Caveat::CoSign(cs) => cs.iter().map(|c| &c.by).collect(),
        Caveat::Via(bs) => bs.iter().filter_map(fixed).collect(),
        _ => Vec::new(),
    }
}

/// `(issuer, nonce)`: what a revocation names.
fn revocation_name(l: &Link) -> (Key, u64) {
    match l {
        Link::V1(s) => (Key::Ed25519(s.cap.issuer), s.cap.nonce),
        Link::V3 { cap, .. } => (cap.issuer, cap.nonce),
    }
}

/// Is `parent` a link a verifier could accept? Canonical form, and the signature where it can be
/// checked without the node's owner roots.
fn check_parent(parent: &Link) -> Result<()> {
    canon::check_link(parent).map_err(|why| refuse(format!("the parent is not canonical ({why})")))?;
    let signed = match parent {
        Link::V1(s) => s.verify_sig().is_ok(),
        Link::V3 { cap, sig: Sig::WebAuthn { .. } } => matches!(cap.issuer, Key::P256(_)),
        Link::V3 { cap, sig } => verify_sig(cap, sig).is_ok(),
    };
    if !signed {
        return Err(refuse("the parent's signature is invalid"));
    }
    Ok(())
}

/// Sign a checked statement, then verify the signature just made against its issuer.
fn seal(signer: &Signer, cap: CapabilityV3) -> Result<Link> {
    if cap.issuer != signer.key() {
        return Err(refuse("the issuer is not the signing key"));
    }
    let sig = signer.sign(&cap);
    verify_sig(&cap, &sig).map_err(refuse)?;
    Ok(Link::V3 { cap, sig })
}

/// A root link (`parent: None`) signed by `signer`. Whether its issuer is an accepted root is the
/// verifying node's decision (section 9), not the minter's.
pub fn mint_root(signer: &Signer, grant: Grant) -> Result<Link> {
    let cap = grant.statement(signer.key(), None);
    check_statement(&cap)?;
    seal(signer, cap)
}

/// A child of `parent` signed by `signer`, refused unless it is no wider than `parent` allows on
/// every axis. `parent` must be the link whose audience is `signer`.
pub fn attenuate(signer: &Signer, parent: &Link, grant: Grant) -> Result<Link> {
    check_parent(parent)?;
    let p = Parent::of(parent);
    let cap = grant.statement(signer.key(), Some(p.id));
    check_child(&cap, &p).map_err(refuse)?;
    check_statement(&cap)?;
    if revocation_name(parent) == (cap.issuer, cap.nonce) {
        return Err(refuse("the nonce is the parent's: one revocation would name both links"));
    }
    seal(signer, cap)
}

/// A one-link token holding a fresh root.
pub fn root_token(signer: &Signer, grant: Grant) -> Result<TokenV3> {
    decodable(TokenV3 { links: vec![mint_root(signer, grant)?], programs: Vec::new() })
}

/// `t`, if a strict decoder accepts its bytes (size, link and program counts, canonical form).
fn decodable(t: TokenV3) -> Result<TokenV3> {
    let bytes = t.encode();
    if bytes.len() > MAX_TOKEN {
        return Err(refuse(format!("the token would exceed {MAX_TOKEN} bytes")));
    }
    TokenV3::decode(&bytes).map_err(refuse)?;
    Ok(t)
}

/// The chain rules a verifier applies to the links already in `token`, without roots, clock or
/// revocations: V1 links only at the head (section 3.3), and each V3 link inside its parent.
fn check_chain(links: &[Link]) -> Result<()> {
    for (i, pair) in links.windows(2).enumerate() {
        let at = |why: String| refuse(format!("the token is already invalid (link {}: {why})", i + 1));
        match (&pair[0], &pair[1]) {
            (Link::V3 { .. }, Link::V1(_)) => return Err(at("a v1 link cannot follow a v3 link".into())),
            (Link::V1(p), Link::V1(c)) if c.cap.parent != Some(p.id()) || c.cap.issuer != p.cap.audience => {
                return Err(at("parent hash does not match the chain".into()));
            }
            (Link::V1(_), Link::V1(_)) => {}
            (p, Link::V3 { cap, .. }) => check_child(cap, &Parent::of(p)).map_err(at)?,
        }
    }
    Ok(())
}

/// `token` with a child of its leaf appended; the program bodies are kept. Refused when the chain
/// above the new link is already broken, when the new link reuses an `(issuer, nonce)` of the
/// chain, or when the result would not decode (link count, size, canonical form).
pub fn extend(token: &TokenV3, signer: &Signer, grant: Grant) -> Result<TokenV3> {
    let Some(leaf) = token.links.last() else {
        return Err(refuse("the token has no links"));
    };
    if token.links.len() >= MAX_LINKS {
        return Err(refuse(format!("a chain holds at most {MAX_LINKS} links")));
    }
    check_chain(&token.links)?;
    let name = (signer.key(), grant.nonce);
    if token.links.iter().any(|l| revocation_name(l) == name) {
        return Err(refuse("the nonce is already used by this issuer in the chain"));
    }
    let mut out = token.clone();
    out.links.push(attenuate(signer, leaf, grant)?);
    decodable(out)
}
