//! # ce-net-proto
//!
//! The open, offline-verifiable capability token of ce-net. Anyone holding a chain token and a root
//! public key can decide whether the chain is valid without talking to any node, chain, or service.
//!
//! This crate is a standalone, byte-for-byte compatible extraction of `ce-cap` (verification +
//! attenuating delegation) plus a minimal Ed25519 identity. Dependencies are only `serde`,
//! `bincode` 1.x, `ed25519-dalek` 2.x, `sha2` and `hex`. The exact signed byte layout is documented
//! in `docs/TOKEN-FORMAT.md`; `tests/vectors.json` holds golden vectors for other implementations.
//!
//! - [`cap`]: the [`Capability`] statement, signing, chain encoding, revocation, [`authorize`].
//! - [`delegate`]: mint an attenuated child link from a held chain.
//! - [`identity`]: [`NodeId`], [`Identity`], [`verify`](identity::verify).
//! - [`program`]: capability programs (typed steps, ids, typing), CAPABILITY-PROGRAMS.md section 6.
//! - [`v3`]: token format v3 types and strict canonical encoding (CAPABILITY-PROGRAMS.md).
//! - [`verify_chain`]: node-independent offline check of a chain against one root key (what the
//!   `ce-cap-verify` CLI runs).

pub mod cap;
pub mod delegate;
pub mod identity;
pub mod program;
pub mod v3;

pub use cap::*;
pub use identity::{Identity, NodeId};

/// The crate's error: a human-readable reason (safe to log or return to a caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Result alias with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// What [`verify_chain`] learned about a valid chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// Number of links.
    pub links: usize,
    /// The leaf holder (the key that may wield the chain).
    pub holder: NodeId,
    /// The leaf's abilities.
    pub abilities: Vec<String>,
    /// The leaf's resource set.
    pub resource: Resource,
    /// The leaf's caveats (already the tightest along the chain, by attenuation).
    pub caveats: Caveats,
    /// Every link's `CapId`, root first.
    pub ids: Vec<CapId>,
}

/// Node-independent offline verification of a root-first `chain` against one trusted `root` key.
///
/// Checks everything [`authorize`] checks *except* the two node-specific steps (step 4, "the
/// resource matches this node", and step 7, "the leaf is held by the requester and grants the
/// action"): root issuer == `root`, every signature, temporal validity at `now`, revocation via
/// `is_revoked(issuer, nonce)`, continuity (issuer == parent audience, parent hash), and attenuation
/// (abilities, resource, caveats). The same reasons as [`authorize`] are returned on failure.
pub fn verify_chain(
    chain: &[SignedCapability],
    root: &NodeId,
    now: u64,
    is_revoked: &dyn Fn(&NodeId, u64) -> bool,
) -> Result<Verified, String> {
    let Some(first) = chain.first() else {
        return Err("no capability presented".into());
    };
    if &first.cap.issuer != root {
        return Err("capability chain does not root at an accepted authority".into());
    }
    for (i, link) in chain.iter().enumerate() {
        let c = &link.cap;
        link.verify_sig().map_err(|_| format!("link {i}: invalid signature"))?;
        c.caveats.valid_at(now).map_err(|e| format!("link {i}: {e}"))?;
        if is_revoked(&c.issuer, c.nonce) {
            return Err(format!("link {i}: capability revoked"));
        }
        if i == 0 {
            if c.parent.is_some() {
                return Err("root capability must not name a parent".into());
            }
        } else {
            let parent = &chain[i - 1].cap;
            if c.issuer != parent.audience {
                return Err(format!("link {i}: issuer is not the parent's audience"));
            }
            match c.parent {
                Some(pid) if pid == cap_id(parent) => {}
                _ => return Err(format!("link {i}: parent hash does not match the chain")),
            }
            if !cap::abilities_subset(&c.abilities, &parent.abilities) {
                return Err(format!("link {i}: abilities exceed the parent"));
            }
            if !c.resource.is_subset_of(&parent.resource) {
                return Err(format!("link {i}: resource is broader than the parent"));
            }
            if !c.caveats.is_narrower_or_equal(&parent.caveats) {
                return Err(format!("link {i}: caveats are broader than the parent"));
            }
        }
    }
    let leaf = &chain[chain.len() - 1].cap;
    Ok(Verified {
        links: chain.len(),
        holder: leaf.audience,
        abilities: leaf.abilities.clone(),
        resource: leaf.resource.clone(),
        caveats: leaf.caveats.clone(),
        ids: chain.iter().map(|l| l.id()).collect(),
    })
}
