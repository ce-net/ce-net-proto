//! Verifying a v3 token (`docs/CAPABILITY-PROGRAMS.md` section 5): [`verify_chain_v3`] is the
//! node-independent part (5.1), [`authorize_v3`] adds what one node checks for one request (5.2,
//! and for a program step 6.4 rules 1 to 3, the step half of rule 4, and rule 5).
//!
//! Every link is checked in order and the first failure is the answer: the signature (v1 rules
//! for a V1 link, section 2 for V3, WebAuthn against the owner roots' `rp_id`), the time window,
//! revocation, and below the root continuity and narrowing by exactly the predicates the minter
//! runs ([`check_child`]). V1 links may only head the chain (section 3.3). The canonical-form
//! rules are re-run here, so a token built in memory is held to the same bar as a decoded one.
//!
//! What stays with the caller: decoding (a byte string without the magic is a v1 chain), the run
//! log of section 6.4 rule 4 (earlier steps of the same run completed here), and the burn log of
//! section 7, reached through the `burn` callback.

use super::narrow::{Parent, check_child};
use super::sign::verify_sig;
use super::{Caveat, CapabilityV3, Delegate, Key, Link, Sig, TokenV3, canon, webauthn};
use crate::cap::{Caveats, SignedCapability, abilities_subset, ability_covers};
use crate::program::{self, CUMULATIVE_LIMITS, Hash, Limit, NodeKey, ResourceV3, Scope, Step};

/// An owner device key (section 9): a root for V3 links only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRoot {
    pub key: Key,
    /// WebAuthn relying-party id; `None`: this key never verifies a `WebAuthn` signature.
    pub rp_id: Option<String>,
    /// Unix seconds; `0` = unbounded.
    pub not_before: u64,
    pub not_after: u64,
}

/// The `roots` of section 5: the keys ce-gate accepts for the api (they may head v1 and v3 chains),
/// and the owner roots.
#[derive(Debug, Clone, Copy, Default)]
pub struct Roots<'a> {
    pub keys: &'a [Key],
    pub owners: &'a [OwnerRoot],
}

impl Roots<'_> {
    fn owner(&self, k: &Key, now: u64) -> bool {
        self.owners.iter().any(|o| {
            &o.key == k && (o.not_before == 0 || now >= o.not_before) && (o.not_after == 0 || now <= o.not_after)
        })
    }

    fn rp_id(&self, k: &Key) -> Option<&str> {
        self.owners.iter().find(|o| &o.key == k).and_then(|o| o.rp_id.as_deref())
    }
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

/// What [`verify_chain_v3`] learned about a valid chain: the leaf, read as section 3.3 when V1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedV3 {
    pub links: usize,
    /// The leaf's audience: the key that may wield the chain.
    pub holder: Key,
    /// What the holder may itself do.
    pub abilities: Vec<String>,
    pub resource: ResourceV3,
    /// The effective caveats: the leaf's, by narrowing the tightest in the chain.
    pub caveats: Caveats,
    pub ext: Vec<Caveat>,
    /// What the holder may delegate.
    pub delegate: Option<Delegate>,
    /// Every link's id, root first; the last is the leaf id.
    pub ids: Vec<Hash>,
    /// Every counted link, root first.
    pub counted: Vec<Counted>,
}

impl VerifiedV3 {
    pub fn leaf(&self) -> Hash {
        self.ids[self.ids.len() - 1]
    }

    /// The leaf's `Programs` caveat, if the chain binds programs.
    pub fn programs(&self) -> Option<&[Hash]> {
        self.ext.iter().find_map(|c| match c {
            Caveat::Programs(ids) => Some(ids.as_slice()),
            _ => None,
        })
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
    /// Every counted link of the chain; all are charged or none.
    pub counted: &'a [Counted],
    /// The charged action (`scope` of a `per: Action` counter).
    pub action: String,
    /// `(program_id, run)` for a program step: `per: Link` is charged once per run at this node.
    pub program: Option<(Hash, u32)>,
}

fn issuer(l: &Link) -> Key {
    match l {
        Link::V1(s) => Key::Ed25519(s.cap.issuer),
        Link::V3 { cap, .. } => cap.issuer,
    }
}

/// Section 2: the `Sig` variant must match the issuer's `Key`, then it must verify.
fn check_sig(cap: &CapabilityV3, sig: &Sig, roots: &Roots) -> Result<(), String> {
    match (&cap.issuer, sig) {
        (Key::Ed25519(_), Sig::Ed25519(_)) | (Key::P256(_), Sig::P256(_)) => {
            verify_sig(cap, sig).map_err(|_| "invalid signature".to_string())
        }
        (Key::P256(k), Sig::WebAuthn { auth_data, client_data, sig: der }) => {
            webauthn::verify(cap, k, roots.rp_id(&cap.issuer), auth_data, client_data, der)
                .map_err(|_| "invalid signature".to_string())
        }
        _ => Err("signature type does not match the issuer key".into()),
    }
}

/// v1 attenuation of a V1 link under a V1 parent (TOKEN-FORMAT.md, as `verify_chain`).
fn check_v1_child(c: &SignedCapability, p: &SignedCapability) -> Result<(), String> {
    let (c, p) = (&c.cap, &p.cap);
    if c.issuer != p.audience {
        return Err("issuer is not the parent's audience".into());
    }
    if c.parent != Some(crate::cap::cap_id(p)) {
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
            Caveat::Limits(ls) => ls.iter().filter(|l| CUMULATIVE_LIMITS.contains(&l.name.as_str())).cloned().collect(),
            _ => Vec::new(),
        })
        .collect();
    (uses.is_some() || !cumulative.is_empty()).then(|| Counted { link: super::cap_id(cap), uses, cumulative, not_after: cap.caveats.not_after })
}

/// The chain walk shared by both entry points; `node` adds the per-link resource match and makes
/// the node's own key an implicit root (as v1 `authorize`).
fn walk(
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
    let root = issuer(head);
    let own = node.is_some_and(|n| root == Key::Ed25519(n.id));
    let accepted = own
        || roots.keys.contains(&root)
        || (matches!(head, Link::V3 { .. }) && roots.owner(&root, now));
    if !accepted {
        return Err("capability chain does not root at an accepted authority".into());
    }
    let no_parent = match head {
        Link::V1(s) => s.cap.parent.is_none(),
        Link::V3 { cap, .. } => cap.parent.is_none(),
    };
    if !no_parent {
        return Err("root capability must not name a parent".into());
    }
    let mut seen_v3 = false;
    let mut out_counted = Vec::new();
    for (i, link) in t.links.iter().enumerate() {
        let at = |m: String| format!("link {i}: {m}");
        let (caveats, nonce) = match link {
            Link::V1(s) => {
                if seen_v3 {
                    return Err(at("a v1 link cannot follow a v3 link".into()));
                }
                s.verify_sig().map_err(|_| at("invalid signature".into()))?;
                (&s.cap.caveats, s.cap.nonce)
            }
            Link::V3 { cap, sig } => {
                seen_v3 = true;
                check_sig(cap, sig, roots).map_err(at)?;
                (&cap.caveats, cap.nonce)
            }
        };
        caveats.valid_at(now).map_err(at)?;
        if is_revoked(&issuer(link), nonce) {
            return Err(at("capability revoked".into()));
        }
        if let Some(n) = node {
            let here = match link {
                Link::V1(s) => s.cap.resource.matches(&n.id, n.tags),
                Link::V3 { cap, .. } => cap.resource.matches(&n.id, n.tags),
            };
            if !here {
                return Err(at("resource does not match this node".into()));
            }
        }
        if i > 0 {
            let prev = &t.links[i - 1];
            match (link, prev) {
                (Link::V1(c), Link::V1(p)) => check_v1_child(c, p).map_err(at)?,
                (Link::V3 { cap, .. }, p) => check_child(cap, &Parent::of(p)).map_err(at)?,
                (Link::V1(_), Link::V3 { .. }) => return Err(at("a v1 link cannot follow a v3 link".into())),
            }
        }
        if let Link::V3 { cap, .. } = link {
            out_counted.extend(counted(cap));
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
        holder: p.audience,
        abilities,
        resource: p.resource,
        caveats: p.caveats,
        ext: p.ext,
        delegate: p.delegate,
        ids: t.links.iter().map(Link::id).collect(),
        counted: out_counted,
    })
}

/// Section 5.1: node-independent verification of `t` against `roots` at `now`.
/// `is_revoked(issuer, nonce)` is asked for every link (a V1 issuer as `Key::Ed25519`).
pub fn verify_chain_v3(
    t: &TokenV3,
    roots: &Roots,
    now: u64,
    is_revoked: &dyn Fn(&Key, u64) -> bool,
) -> Result<VerifiedV3, String> {
    walk(t, roots, None, now, is_revoked)
}

/// Section 5.2: may `requester` (the key proved in the transport handshake) make `req` at `node`?
///
/// After every check passes and only then, `burn` is called once if the chain has counted links;
/// it must charge every one atomically or return the refusal (`"capability used up"`, `"clock went
/// backwards"`), which is returned as is. On success the verified chain is returned: its
/// `caveats`, `ext` and `counted` are what the cell enforces.
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
    let v = walk(t, roots, Some(node), now, is_revoked)?;
    if &v.holder != requester {
        return Err("leaf capability is not held by the request sender".into());
    }
    let (action, program) = match *req {
        Request::Call(action) => {
            if v.programs().is_some() {
                return Err("capability is bound to a program".into());
            }
            if !v.abilities.iter().any(|a| ability_covers(a, action)) {
                return Err(format!("capability does not grant '{action}'"));
            }
            (action.to_string(), None)
        }
        Request::Execute { program, run, step, req } => (execute(node, &v, t, program, step, req)?, Some((program, run))),
    };
    if !v.counted.is_empty() {
        burn(&Charge { leaf: v.leaf(), counted: &v.counted, action, program })?;
    }
    Ok(v)
}

/// Section 6.4 rules 2 to 4 for one step; returns the charged action.
fn execute(node: &Node, v: &VerifiedV3, t: &TokenV3, id: Hash, index: u32, req: &Step) -> Result<String, String> {
    if v.programs().is_some_and(|ids| !ids.contains(&id)) {
        return Err("program is not the one granted".into());
    }
    let body = program::find(&id, &t.programs)?;
    let steps = program::expand(body, &t.programs)?;
    let limits = v.ext.iter().find_map(|c| match c {
        Caveat::Limits(ls) => Some(ls.as_slice()),
        _ => None,
    });
    let egress = v.ext.iter().find_map(|c| match c {
        Caveat::Egress(rs) => Some(rs.as_slice()),
        _ => None,
    });
    let scope = Scope {
        abilities: &v.abilities,
        resource: &v.resource,
        path_prefix: v.caveats.path_prefix.as_deref(),
        max_cpu: v.caveats.max_cpu,
        max_mem_mb: v.caveats.max_mem_mb,
        egress,
        limits: limits.unwrap_or(&[]),
    };
    let host_of = |n: &NodeKey| (n == &node.id).then(|| node.host.map(str::to_string)).flatten();
    program::type_check(&steps, &scope, &host_of)?;
    let s = program::check_request(&steps, index, &node.id, req)?;
    if matches!(s, Step::InstallCell { .. }) && node.host.is_none() {
        return Err("this node's hostname is needed to check an InstallCell step".into());
    }
    let needed = program::abilities_for(s, node.host);
    if let Some(a) = needed.iter().find(|a| !v.abilities.iter().any(|g| ability_covers(g, a))) {
        return Err(format!("capability does not grant '{a}'"));
    }
    Ok(program::charged_action(s, node.host))
}
