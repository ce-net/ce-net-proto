//! Verifying a v3 token (`docs/CAPABILITY-PROGRAMS.md` section 5): [`verify_chain_v3`] is the
//! node-independent part (5.1); [`authorize_v3`] adds what one node checks for one request (5.2,
//! and for a program step 6.4 rules 1 to 3, the "names this node" half of rule 4, and rule 5).
//!
//! The links are walked root first and the first failure is the answer. For every link: V1 links
//! only at the head (3.3); the signature (v1 rules for a V1 link, section 2 for V3, a WebAuthn
//! assertion against the `rp_id` of an owner root valid now); the time window; revocation; at a
//! node, the resource; and below the root, continuity and narrowing by the very predicates the
//! minter runs ([`check_child`]; the v1 rules between two V1 links). Nothing is trusted from a
//! link before its signature has verified, and no check is skipped for a link "because the
//! minter would have refused it": safety rests on this file alone (5.3).
//!
//! The canonical-form rules (3.4, 7) are re-run, so a token built in memory is held to them like
//! a decoded one. What stays with the caller: decoding (a byte string without the magic is a v1
//! chain and goes to the v1 verifier), the run log of 6.4 rule 4, and the burn log of section 7,
//! reached through the `burn` callback.
//!
//! Conditions (4.1: `Requires`, `CoSign`, `Via`) are held to their canonical form and to narrowing
//! here like every caveat, so a link that drops one its parent carries is refused, and they are
//! reported in [`VerifiedV3::conditions`]. Whether one use meets them is decided in
//! [`super::authorize`] with the proofs of that use ([`super::verify_cond`]).

use sha2::{Digest, Sha256};

pub use super::authorize::{Charge, Request, authorize_use_v3, authorize_v3};
use super::narrow::{Parent, check_child};
use super::sign::verify_bytes;
pub use super::verify_cond::Presented;
use super::{Caveat, CapabilityV3, Delegate, Key, Link, Sig, TokenV3, canon, cap_bytes, cap_id, webauthn};
use crate::cap::{self, Caveats, SignedCapability, abilities_subset, ability_covers};
use crate::program::{CUMULATIVE_LIMITS, Hash, Limit, NodeKey, ResourceV3};

/// An owner device key (section 9): a root for V3 links only, never the head of a v1 chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRoot {
    pub key: Key,
    /// WebAuthn relying-party id; `None`: this entry never verifies a `WebAuthn` signature.
    pub rp_id: Option<String>,
    /// Unix seconds; `0` = unbounded.
    pub not_before: u64,
    pub not_after: u64,
}

impl OwnerRoot {
    /// Is this the entry of `k`, inside its window at `now`? Outside it the entry does not exist:
    /// it roots nothing and lends its `rp_id` to no signature.
    fn is(&self, k: &Key, now: u64) -> bool {
        &self.key == k && (self.not_before == 0 || now >= self.not_before) && (self.not_after == 0 || now <= self.not_after)
    }
}

/// The `roots` of section 5: the keys ce-gate accepts for the api being called (they may head v1
/// and v3 chains), and the owner roots.
#[derive(Debug, Clone, Copy, Default)]
pub struct Roots<'a> {
    pub keys: &'a [Key],
    pub owners: &'a [OwnerRoot],
}

/// A link whose use is counted (section 7): it carries `Uses` or a cumulative limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counted {
    pub link: Hash,
    pub uses: Option<Caveat>,
    /// The link's limits named in [`CUMULATIVE_LIMITS`].
    pub cumulative: Vec<Limit>,
    pub not_after: u64,
}

/// What a valid chain says: the leaf, read as section 3.3 when it is a V1 link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedV3 {
    pub links: usize,
    /// The accepted root key the chain hangs from (section 11 logs it with every use).
    pub root: Key,
    /// The leaf's audience: the only key that may wield the chain.
    pub holder: Key,
    /// What the holder may itself do. `delegate.abilities` are not among them.
    pub abilities: Vec<String>,
    pub resource: ResourceV3,
    /// The effective caveats: the leaf's, by narrowing the tightest in the chain.
    pub caveats: Caveats,
    pub ext: Vec<Caveat>,
    /// What the holder may grant below the leaf.
    pub delegate: Option<Delegate>,
    /// Every link's id, root first; the last is the leaf id.
    pub ids: Vec<Hash>,
    /// Every counted link, root first.
    pub counted: Vec<Counted>,
    /// The condition caveats (section 4.1) of every link, root first. By narrowing the leaf's
    /// (in `ext`) include them all; a use is checked against each one all the same.
    pub conditions: Vec<Caveat>,
}

impl VerifiedV3 {
    pub fn leaf(&self) -> Hash {
        self.ids[self.ids.len() - 1]
    }

    /// The effective `Programs` caveat, if the chain binds programs.
    pub fn programs(&self) -> Option<&[Hash]> {
        self.ext.iter().find_map(|c| match c {
            Caveat::Programs(ids) => Some(ids.as_slice()),
            _ => None,
        })
    }

    /// Does a leaf ability cover `action`? The leaf's `delegate.abilities` never do.
    pub fn grants(&self, action: &str) -> bool {
        self.abilities.iter().any(|a| ability_covers(a, action))
    }
}

/// The node a request arrives at.
#[derive(Debug, Clone, Copy)]
pub struct Node<'a> {
    pub id: NodeKey,
    pub tags: &'a [String],
    /// Short hostname, needed to check an `InstallCell` step on this node.
    pub host: Option<&'a str>,
}

/// The fields every link has, V1 or V3: `(issuer, nonce, caveats, parent)`.
fn fields(l: &Link) -> (Key, u64, &Caveats, Option<Hash>) {
    match l {
        Link::V1(s) => (Key::Ed25519(s.cap.issuer), s.cap.nonce, &s.cap.caveats, s.cap.parent),
        Link::V3 { cap, .. } => (cap.issuer, cap.nonce, &cap.caveats, cap.parent),
    }
}

/// Section 2 for any signed bytes: the `Sig` variant must match the signer's `Key`, and then it
/// must verify over `msg`. A `WebAuthn` assertion verifies only against an owner-root entry of the
/// signer that is valid at `now` and records an `rp_id`; its challenge is `SHA-256(msg)`.
pub(super) fn check_sig_bytes(key: &Key, msg: &[u8], sig: &Sig, roots: &Roots, now: u64) -> Result<(), String> {
    let ok = match (key, sig) {
        (Key::Ed25519(_), Sig::Ed25519(_)) | (Key::P256(_), Sig::P256(_)) => verify_bytes(key, msg, sig).is_ok(),
        (Key::P256(k), Sig::WebAuthn { auth_data, client_data, sig: der }) => {
            let challenge: Hash = Sha256::digest(msg).into();
            roots
                .owners
                .iter()
                .filter(|o| o.is(key, now))
                .any(|o| webauthn::verify_challenge(&challenge, k, o.rp_id.as_deref(), auth_data, client_data, der).is_ok())
        }
        _ => return Err("signature type does not match the issuer key".into()),
    };
    if ok { Ok(()) } else { Err("invalid signature".into()) }
}

/// A link's signature: by `cap.issuer` over `cap_bytes(cap)` (so a WebAuthn challenge is `cap_id`).
fn check_sig(cap: &CapabilityV3, sig: &Sig, roots: &Roots, now: u64) -> Result<(), String> {
    check_sig_bytes(&cap.issuer, &cap_bytes(cap), sig, roots, now)
}

/// A V1 link under a V1 parent: continuity and attenuation exactly as v1 `verify_chain`.
fn check_v1_child(c: &SignedCapability, p: &SignedCapability) -> Result<(), String> {
    let (c, p) = (&c.cap, &p.cap);
    if c.issuer != p.audience {
        return Err("issuer is not the parent's audience".into());
    }
    if c.parent != Some(cap::cap_id(p)) {
        return Err("parent hash does not match the chain".into());
    }
    if !abilities_subset(&c.abilities, &p.abilities) {
        return Err("abilities exceed the parent".into());
    }
    if !c.resource.is_subset_of(&p.resource) {
        return Err("resource is broader than the parent".into());
    }
    if !c.caveats.is_narrower_or_equal(&p.caveats) {
        return Err("caveats are broader than the parent".into());
    }
    Ok(())
}

fn counted(cap: &CapabilityV3) -> Option<Counted> {
    let uses = cap.ext.iter().find(|c| matches!(c, Caveat::Uses { .. })).cloned();
    let cumulative: Vec<Limit> = cap
        .ext
        .iter()
        .flat_map(|c| match c {
            Caveat::Limits(ls) => ls.as_slice(),
            _ => &[],
        })
        .filter(|l| CUMULATIVE_LIMITS.contains(&l.name.as_str()))
        .cloned()
        .collect();
    (uses.is_some() || !cumulative.is_empty())
        .then(|| Counted { link: cap_id(cap), uses, cumulative, not_after: cap.caveats.not_after })
}

/// The chain walk behind both entry points. With `node` every link's resource must match it, and
/// the node's own key is an implicit root (as in v1 `authorize`; section 9 keeps that reach).
pub(super) fn walk(
    t: &TokenV3,
    roots: &Roots,
    node: Option<&Node>,
    now: u64,
    is_revoked: &dyn Fn(&Key, u64) -> bool,
) -> Result<VerifiedV3, String> {
    canon::check_token(t).map_err(|e| e.0)?;
    let Some(head) = t.links.first() else {
        return Err("no capability presented".into());
    };
    let (root, _, _, root_parent) = fields(head);
    let own = node.is_some_and(|n| root == Key::Ed25519(n.id));
    let owner = matches!(head, Link::V3 { .. }) && roots.owners.iter().any(|o| o.is(&root, now));
    if !(own || owner || roots.keys.contains(&root)) {
        return Err("capability chain does not root at an accepted authority".into());
    }
    if root_parent.is_some() {
        return Err("root capability must not name a parent".into());
    }
    let mut out_counted = Vec::new();
    let mut conditions = Vec::new();
    for (i, link) in t.links.iter().enumerate() {
        let at = |m: String| format!("link {i}: {m}");
        let prev = i.checked_sub(1).map(|j| &t.links[j]);
        // 3.3: a v1 link cannot carry a v3 parent's ext caveats or delegation right.
        if matches!((prev, link), (Some(Link::V3 { .. }), Link::V1(_))) {
            return Err(at("a v1 link cannot follow a v3 link".into()));
        }
        // Step 3.1: the signature, before anything the link says is believed.
        match link {
            Link::V1(s) => s.verify_sig().map_err(|_| at("invalid signature".into()))?,
            Link::V3 { cap, sig } => check_sig(cap, sig, roots, now).map_err(at)?,
        }
        // Steps 3.2 and 3.3: time window, revocation of (issuer, nonce).
        let (issuer, nonce, caveats, _) = fields(link);
        caveats.valid_at(now).map_err(at)?;
        if is_revoked(&issuer, nonce) {
            return Err(at("capability revoked".into()));
        }
        // 5.2: at a node, every link must apply to it.
        if let Some(n) = node {
            let here = match link {
                Link::V1(s) => s.cap.resource.matches(&n.id, n.tags),
                Link::V3 { cap, .. } => cap.resource.matches(&n.id, n.tags),
            };
            if !here {
                return Err(at("resource does not match this node".into()));
            }
        }
        // Step 3.4: continuity and narrowing against the link above.
        match (prev, link) {
            (None, _) => {}
            (Some(Link::V1(p)), Link::V1(c)) => check_v1_child(c, p).map_err(at)?,
            (Some(p), Link::V3 { cap, .. }) => check_child(cap, &Parent::of(p)).map_err(at)?,
            (Some(Link::V3 { .. }), Link::V1(_)) => return Err(at("a v1 link cannot follow a v3 link".into())),
        }
        if let Link::V3 { cap, .. } = link {
            out_counted.extend(counted(cap));
            conditions.extend(cap.ext.iter().filter(|c| c.is_condition()).cloned());
        }
    }
    let leaf = &t.links[t.links.len() - 1];
    let p = Parent::of(leaf);
    let abilities = match leaf {
        Link::V1(s) => s.cap.abilities.clone(),
        Link::V3 { cap, .. } => cap.abilities.clone(),
    };
    Ok(VerifiedV3 {
        links: t.links.len(),
        root,
        holder: p.audience,
        abilities,
        resource: p.resource,
        caveats: p.caveats,
        ext: p.ext,
        delegate: p.delegate,
        ids: t.links.iter().map(Link::id).collect(),
        counted: out_counted,
        conditions,
    })
}

/// Section 5.1: node-independent verification of `t` against `roots` at `now`.
/// `is_revoked(issuer, nonce)` is asked once per link, after its signature has verified (a V1
/// issuer as `Key::Ed25519`, so v1 revocations keep working for V1 links at the head).
///
/// A chain that carries conditions verifies here when they are canonical and no link drops or
/// loosens one of its parent's; that says nothing about any use. Only `authorize_use_v3` with the
/// proofs of a use decides that, so `Ok` from this function alone never authorizes a call.
pub fn verify_chain_v3(
    t: &TokenV3,
    roots: &Roots,
    now: u64,
    is_revoked: &dyn Fn(&Key, u64) -> bool,
) -> Result<VerifiedV3, String> {
    walk(t, roots, None, now, is_revoked)
}

