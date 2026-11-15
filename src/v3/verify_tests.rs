//! `verify_chain_v3` tests (section 5.1): a good chain, then every refusal of steps 2 and 3. The
//! links under test are signed directly, never through the minter, so the verifier alone has to
//! catch them. V1 heads, owner roots and WebAuthn are in `verify_roots_tests.rs`, section 5.2 in
//! `authorize_tests.rs`; both use the helpers here.

use std::cell::RefCell;

use super::mint::{Grant, mint_root};
use super::sign::Signer;
use super::types::AudienceSet;
use super::verify::{Roots, VerifiedV3, verify_chain_v3};
use super::*;
use crate::cap::Caveats;
use crate::program::{EgressRule, HostPat, Limit, Proto, ResourceV3};

pub(super) const T: u64 = 2_000_000_000;
pub(super) const NOW: u64 = T - 1000;
pub(super) const HERE: [u8; 32] = [1; 32];
pub(super) const THERE: [u8; 32] = [2; 32];

pub(super) fn ed(seed: u8) -> Signer {
    Signer::ed25519(&[seed; 32])
}

pub(super) fn p256(seed: u8) -> Signer {
    Signer::p256(&[seed; 32]).unwrap()
}

pub(super) fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

pub(super) fn delegate(abilities: &[&str], audience: AudienceSet, depth: u8) -> Option<Delegate> {
    Some(Delegate { abilities: strs(abilities), audience, depth })
}

/// What ed(1) grants at the root: nothing to use, two abilities to pass on, three links deep.
pub(super) fn root_grant(audience: Key) -> Grant {
    Grant {
        audience,
        abilities: vec![],
        resource: ResourceV3::Nodes(vec![HERE, THERE]),
        caveats: Caveats { not_after: T, path_prefix: Some("/opt/x".into()), ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 5, per: UsePer::Link }],
        delegate: delegate(&["cell.install:*", "talk:send"], AudienceSet::Any, 3),
        nonce: 1,
    }
}

/// A final statement under `parent`, inside what [`root_grant`] allows.
pub(super) fn leaf_cap(issuer: Key, audience: Key, parent: &Link) -> CapabilityV3 {
    CapabilityV3 {
        v: 3,
        issuer,
        audience,
        abilities: strs(&["talk:send", "cell.install:install-file"]),
        resource: ResourceV3::Node(HERE),
        caveats: Caveats { not_after: T - 10, path_prefix: Some("/opt/x/app".into()), ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 2, per: UsePer::Link }],
        delegate: None,
        nonce: 2,
        parent: Some(parent.id()),
    }
}

/// `cap` signed by `s` as it stands: no minter in the way.
pub(super) fn signed(s: &Signer, cap: CapabilityV3) -> Link {
    let sig = s.sign(&cap);
    Link::V3 { cap, sig }
}

pub(super) fn token(links: Vec<Link>) -> TokenV3 {
    TokenV3 { links, programs: vec![] }
}

/// root ed(1) -> p256(2) -> ed(3): the root grant changed by `g`, the leaf by `f`.
pub(super) fn chain2(g: impl FnOnce(&mut Grant), f: impl FnOnce(&mut CapabilityV3)) -> TokenV3 {
    let mut grant = root_grant(p256(2).key());
    g(&mut grant);
    let root = mint_root(&ed(1), grant).unwrap();
    let mut cap = leaf_cap(p256(2).key(), ed(3).key(), &root);
    f(&mut cap);
    token(vec![root, signed(&p256(2), cap)])
}

pub(super) fn chain(f: impl FnOnce(&mut CapabilityV3)) -> TokenV3 {
    chain2(|_| {}, f)
}

pub(super) fn never(_: &Key, _: u64) -> bool {
    false
}

/// Verify with ed(1) as the one accepted root, at `NOW`, nothing revoked.
pub(super) fn verify(t: &TokenV3) -> Result<VerifiedV3, String> {
    verify_chain_v3(t, &Roots { keys: &[ed(1).key()], owners: &[] }, NOW, &never)
}

fn refusal(f: impl FnOnce(&mut CapabilityV3)) -> String {
    verify(&chain(f)).unwrap_err()
}

#[test]
fn good_chain_verifies() {
    let t = chain(|_| {});
    let v = verify(&t).unwrap();
    assert_eq!((v.links, v.root, v.holder), (2, ed(1).key(), ed(3).key()));
    assert_eq!(v.abilities, strs(&["talk:send", "cell.install:install-file"]));
    assert_eq!(v.resource, ResourceV3::Node(HERE));
    assert_eq!(v.caveats.path_prefix.as_deref(), Some("/opt/x/app"));
    assert_eq!(v.delegate, None);
    assert_eq!(v.ids, t.links.iter().map(Link::id).collect::<Vec<_>>());
    assert_eq!(v.leaf(), t.links[1].id());
    assert_eq!(v.counted.iter().map(|c| c.link).collect::<Vec<_>>(), v.ids);
    assert_eq!(v.counted[1].uses, Some(Caveat::Uses { max: 2, per: UsePer::Link }));
    assert_eq!(v.counted[1].not_after, T - 10);
    assert_eq!(verify(&TokenV3::from_hex(&t.to_hex()).unwrap()), Ok(v));
}

#[test]
fn the_root_must_be_accepted_and_parentless() {
    let t = chain(|_| {});
    let not_root = "capability chain does not root at an accepted authority";
    let with = |t: &TokenV3, keys: &[Key]| verify_chain_v3(t, &Roots { keys, owners: &[] }, NOW, &never).map(|v| v.root);
    assert_eq!(with(&t, &[]).unwrap_err(), not_root);
    assert_eq!(with(&t, &[ed(9).key(), p256(2).key(), ed(3).key()]).unwrap_err(), not_root);
    assert_eq!(verify(&token(vec![])).unwrap_err(), "no capability presented");
    // the leaf without the link above it: its issuer is no root, and as a root it names a parent
    let alone = token(vec![t.links[1].clone()]);
    assert_eq!(verify(&alone).unwrap_err(), not_root);
    assert_eq!(with(&alone, &[p256(2).key()]).unwrap_err(), "root capability must not name a parent");
    // a P-256 key ce-gate accepts heads a chain like any other
    let p = token(vec![mint_root(&p256(7), root_grant(ed(3).key())).unwrap()]);
    assert_eq!(with(&p, &[p256(7).key()]), Ok(p256(7).key()));
}

#[test]
fn every_signature_is_checked() {
    let tampered = |i: usize| {
        let mut t = chain(|_| {});
        if let Link::V3 { cap, .. } = &mut t.links[i] {
            cap.caveats.not_after += 1;
        }
        verify(&t).unwrap_err()
    };
    assert_eq!(tampered(0), "link 0: invalid signature");
    assert_eq!(tampered(1), "link 1: invalid signature");
    // the statement is in order, but another key signed it
    let mut t = chain(|_| {});
    let Link::V3 { cap, .. } = t.links[1].clone() else { unreachable!() };
    t.links[1] = Link::V3 { sig: p256(5).sign(&cap), cap };
    assert_eq!(verify(&t).unwrap_err(), "link 1: invalid signature");
    let with_sig = |i: usize, s: Sig| {
        let mut t = chain(|_| {});
        if let Link::V3 { sig, .. } = &mut t.links[i] {
            *sig = s;
        }
        verify(&t).unwrap_err()
    };
    let mismatch = "signature type does not match the issuer key";
    assert_eq!(with_sig(1, Sig::Ed25519([0; 64])), format!("link 1: {mismatch}"));
    assert_eq!(with_sig(0, Sig::P256([0; 64])), format!("link 0: {mismatch}"));
    let webauthn = Sig::WebAuthn { auth_data: vec![], client_data: vec![], sig: vec![] };
    assert_eq!(with_sig(0, webauthn), format!("link 0: {mismatch}"));
    assert_eq!(with_sig(1, Sig::P256([0; 64])), "link 1: invalid signature");
}

#[test]
fn time_window_and_revocation_at_every_link() {
    let r = Roots { keys: &[ed(1).key()], owners: &[] };
    let t = chain(|_| {});
    assert_eq!(verify_chain_v3(&t, &r, T - 10, &never).map(|v| v.links), Ok(2));
    assert_eq!(verify_chain_v3(&t, &r, T - 9, &never).unwrap_err(), "link 1: capability has expired");
    assert_eq!(verify_chain_v3(&t, &r, T + 1, &never).unwrap_err(), "link 0: capability has expired");
    assert_eq!(refusal(|c| c.caveats.not_before = NOW + 1), "link 1: capability not yet valid");
    assert_eq!(verify(&chain2(|g| g.caveats.not_before = NOW + 1, |_| {})).unwrap_err(), "link 0: capability not yet valid");
    let revoked = |who: Key, nonce: u64| verify_chain_v3(&t, &r, NOW, &move |k: &Key, n: u64| (*k, n) == (who, nonce)).map(|v| v.links);
    assert_eq!(revoked(p256(2).key(), 2).unwrap_err(), "link 1: capability revoked");
    assert_eq!(revoked(ed(1).key(), 1).unwrap_err(), "link 0: capability revoked");
    // a revocation names (issuer, nonce): the same nonce by another issuer is another link
    assert_eq!(revoked(ed(1).key(), 2), Ok(2));
    assert_eq!(revoked(ed(3).key(), 2), Ok(2));
    // the revocation set is asked about a link only once its signature has verified
    let mut forged = t.clone();
    if let Link::V3 { cap, .. } = &mut forged.links[1] {
        cap.nonce = 77;
    }
    let asked = RefCell::new(vec![]);
    let log = |k: &Key, n: u64| {
        asked.borrow_mut().push((*k, n));
        false
    };
    assert_eq!(verify_chain_v3(&forged, &r, NOW, &log).unwrap_err(), "link 1: invalid signature");
    assert_eq!(*asked.borrow(), vec![(ed(1).key(), 1)]);
}

#[test]
fn continuity() {
    // issued (and properly signed) by someone who is not the parent's audience
    let root = mint_root(&ed(1), root_grant(p256(2).key())).unwrap();
    let cap = leaf_cap(ed(5).key(), ed(3).key(), &root);
    let t = token(vec![root.clone(), signed(&ed(5), cap)]);
    assert_eq!(verify(&t).unwrap_err(), "link 1: issuer is not the parent's audience");
    // the root issuing the second link itself is not the audience either
    let cap = leaf_cap(ed(1).key(), ed(3).key(), &root);
    assert_eq!(verify(&token(vec![root, signed(&ed(1), cap)])).unwrap_err(), "link 1: issuer is not the parent's audience");
    assert_eq!(refusal(|c| c.parent = Some([7; 32])), "link 1: parent hash does not match the chain");
    assert_eq!(refusal(|c| c.parent = None), "link 1: parent hash does not match the chain");
    // a link grafted under another root grant by the same issuer names the wrong parent
    let other = chain2(|g| g.nonce = 9, |_| {});
    let t = token(vec![chain(|_| {}).links[0].clone(), other.links[1].clone()]);
    assert_eq!(verify(&t).unwrap_err(), "link 1: parent hash does not match the chain");
}

#[test]
fn narrowing_of_grant_resource_and_v1_caveats() {
    let keys = |ks: &[Key]| {
        let mut ks = ks.to_vec();
        ks.sort_by_key(|k| bincode::serialize(k).unwrap());
        AudienceSet::Keys(ks)
    };
    assert_eq!(refusal(|c| c.abilities.push("proc.spawn:run".into())), "link 1: abilities exceed the parent's grant");
    assert_eq!(refusal(|c| c.abilities = strs(&["*"])), "link 1: abilities exceed the parent's grant");
    assert_eq!(refusal(|c| c.resource = ResourceV3::Nodes(vec![HERE, [3; 32]])), "link 1: resource is broader than the parent");
    assert_eq!(refusal(|c| c.caveats.not_after = T + 1), "link 1: caveats are broader than the parent");
    assert_eq!(refusal(|c| c.caveats.path_prefix = Some("/opt".into())), "link 1: caveats are broader than the parent");
    assert_eq!(refusal(|c| c.caveats.path_prefix = None), "link 1: caveats are broader than the parent");
    // the right to grant: depth drops, abilities and audience stay inside the parent's
    assert_eq!(refusal(|c| c.delegate = delegate(&["talk:send"], AudienceSet::Any, 3)), "link 1: delegation depth exceeds the parent");
    assert_eq!(refusal(|c| c.delegate = delegate(&["proc.spawn:run"], AudienceSet::Any, 2)), "link 1: grantable abilities exceed the parent");
    assert!(verify(&chain(|c| c.delegate = delegate(&["talk:send"], keys(&[ed(4).key()]), 2))).is_ok());
    let closed = |g: &mut Grant| g.delegate = delegate(&["talk:send"], keys(&[ed(3).key(), ed(4).key()]), 2);
    let under_closed = |f: fn(&mut CapabilityV3)| {
        verify(&chain2(closed, |c| {
            c.abilities = strs(&["talk:send"]);
            f(c);
        }))
        .map(|v| v.holder)
    };
    assert_eq!(under_closed(|_| {}), Ok(ed(3).key()));
    assert_eq!(under_closed(|c| c.audience = ed(5).key()).unwrap_err(), "link 1: audience is outside the parent's grant");
    assert_eq!(under_closed(|c| c.delegate = delegate(&["talk:send"], AudienceSet::Any, 1)).unwrap_err(), "link 1: grantable audience exceeds the parent");
    // held to the canonical form even when built in memory
    assert_eq!(refusal(|c| c.v = 4), "link 1: not canonical (v must be 3)");
    assert_eq!(refusal(|c| c.resource = ResourceV3::Any), "link 1: not canonical (a counted link must name a finite resource (Node or Nodes))");
}

#[test]
fn narrowing_of_ext_caveats() {
    let broader = "link 1: caveats are broader than the parent";
    assert_eq!(refusal(|c| c.ext = vec![Caveat::Uses { max: 6, per: UsePer::Link }]), broader);
    assert_eq!(refusal(|c| c.ext = vec![Caveat::Uses { max: 1, per: UsePer::Action }]), broader);
    assert_eq!(refusal(|c| c.ext.clear()), broader);
    let limit = |name: &str, max| Limit { name: name.into(), max };
    let rule = |host| EgressRule { host, ports: vec![443], proto: Proto::Tcp };
    let id = [8; 32];
    // the root also carries Limits, Egress and Programs; the leaf carries what `ext` says after Uses
    let under = |ext: Vec<Caveat>| {
        verify(&chain2(
            |g| {
                g.ext.push(Caveat::Limits(vec![limit("proc.spawn.procs", 4)]));
                g.ext.push(Caveat::Egress(vec![rule(HostPat::Suffix(".example.org".into()))]));
                g.ext.push(Caveat::Programs(vec![id]));
            },
            |c| c.ext.extend(ext),
        ))
        .map(|v| v.ext.len())
    };
    let limits = |max| Caveat::Limits(vec![limit("proc.spawn.procs", max)]);
    let egress = |host| Caveat::Egress(vec![rule(host)]);
    let api = || HostPat::Name("api.example.org".into());
    let programs = |ids: &[Hash]| Caveat::Programs(ids.to_vec());
    assert_eq!(under(vec![limits(4), egress(api()), programs(&[id])]), Ok(4));
    assert_eq!(under(vec![Caveat::Limits(vec![limit("a.b", 9), limit("proc.spawn.procs", 1)]), Caveat::Egress(vec![]), programs(&[id])]), Ok(4));
    // each variant dropped, then each widened by one step
    assert_eq!(under(vec![egress(api()), programs(&[id])]).unwrap_err(), broader);
    assert_eq!(under(vec![limits(4), programs(&[id])]).unwrap_err(), broader);
    assert_eq!(under(vec![limits(4), egress(api())]).unwrap_err(), broader);
    assert_eq!(under(vec![limits(5), egress(api()), programs(&[id])]).unwrap_err(), broader);
    assert_eq!(under(vec![Caveat::Limits(vec![limit("a.b", 1)]), egress(api()), programs(&[id])]).unwrap_err(), broader);
    assert_eq!(under(vec![limits(4), egress(HostPat::Name("example.org".into())), programs(&[id])]).unwrap_err(), broader);
    assert_eq!(under(vec![limits(4), egress(HostPat::Suffix(".org".into())), programs(&[id])]).unwrap_err(), broader);
    assert_eq!(under(vec![limits(4), egress(api()), programs(&[id, [9; 32]])]).unwrap_err(), broader);
    assert_eq!(under(vec![limits(4), egress(api()), programs(&[[9; 32]])]).unwrap_err(), broader);
}

/// A link below `parent`, equal to [`leaf_cap`] but for `f`.
fn below(signer: &Signer, audience: Key, parent: &Link, nonce: u64, f: impl FnOnce(&mut CapabilityV3)) -> Link {
    let mut cap = leaf_cap(signer.key(), audience, parent);
    cap.nonce = nonce;
    f(&mut cap);
    signed(signer, cap)
}

#[test]
fn every_link_is_narrowed_and_depth_runs_out() {
    let grant = |abilities: &'static [&'static str], depth| move |c: &mut CapabilityV3| c.delegate = delegate(abilities, AudienceSet::Any, depth);
    let send_only = |c: &mut CapabilityV3| c.abilities = strs(&["talk:send"]);
    let root = mint_root(&ed(1), root_grant(ed(11).key())).unwrap(); // depth 3
    let l1 = below(&ed(11), ed(12).key(), &root, 2, grant(&["talk:send", "cell.install:install-file"], 2));
    let l2 = below(&ed(12), ed(13).key(), &l1, 3, |c| {
        send_only(c);
        grant(&["talk:send"], 1)(c);
    });
    let l3 = below(&ed(13), ed(14).key(), &l2, 4, send_only);
    let head = || vec![root.clone(), l1.clone(), l2.clone()];
    let with = |more: Vec<Link>| verify(&token(head().into_iter().chain(more).collect()));
    let v = with(vec![l3.clone()]).unwrap();
    assert_eq!((v.links, v.holder, v.counted.len()), (4, ed(14).key(), 4));
    // nothing may be minted below a final link
    let l4 = below(&ed(14), ed(15).key(), &l3, 5, send_only);
    assert_eq!(with(vec![l3, l4]).unwrap_err(), "link 4: the parent may not delegate");
    // depth 1 allows one link below, but not one that may grant again
    let regrant = below(&ed(13), ed(14).key(), &l2, 4, |c| {
        send_only(c);
        grant(&["talk:send"], 1)(c);
    });
    assert_eq!(with(vec![regrant]).unwrap_err(), "link 3: delegation depth exceeds the parent");
    // l1 lets its holder grant install-file; l2 did not pass that on, so l2's holder cannot
    let dropped = below(&ed(13), ed(14).key(), &l2, 4, |_| {});
    assert_eq!(with(vec![dropped]).unwrap_err(), "link 3: abilities exceed the parent's grant");
    // a widened link in the middle is refused there, although the link below fits inside it
    let wide = below(&ed(11), ed(12).key(), &root, 2, |c| {
        c.abilities.push("proc.spawn:run".into());
        grant(&["proc.spawn:run", "talk:send"], 2)(c);
    });
    let under = below(&ed(12), ed(13).key(), &wide, 3, |c| c.abilities = strs(&["proc.spawn:run"]));
    assert_eq!(verify(&token(vec![root.clone(), wide, under])).unwrap_err(), "link 1: abilities exceed the parent's grant");
}
