//! Mint tests, second file: the boundary of every narrowing axis (equal is allowed, one more is
//! not), P-256 signing, and the guards the minter adds around section 5.1 step 3.4: a broken or
//! forged parent, an impossible time window, an unusable key, a reused revocation name, an
//! oversized token.

use super::mint::{Grant, attenuate, extend, mint_root, root_token};
use super::sign::{Signer, verify_sig};
use super::types::AudienceSet;
use super::*;
use crate::Identity;
use crate::cap::{Caveats, Resource, SignedCapability};
use crate::program::{EgressRule, HostPat, Proto, ResourceV3};

const T: u64 = 2_000_000_000;

fn ed(seed: u8) -> Signer {
    Signer::ed25519(&[seed; 32])
}

fn p256(seed: u8) -> Signer {
    Signer::p256(&[seed; 32]).unwrap()
}

fn egress(ports: &[u16]) -> Caveat {
    Caveat::Egress(vec![EgressRule { host: HostPat::Name("api.example.org".into()), ports: ports.to_vec(), proto: Proto::Tcp }])
}

fn may_grant(depth: u8) -> Option<Delegate> {
    Some(Delegate { abilities: vec!["proc.spawn:run".into()], audience: AudienceSet::Any, depth })
}

/// "may grant proc.spawn:run on nodes 1 and 2, depth <= 3, 5 uses, ports 80 and 443, programs 5
/// and 6, from T-1000 until T".
fn grant(audience: Key, nonce: u64) -> Grant {
    Grant {
        audience,
        abilities: vec!["proc.spawn:run".into()],
        resource: ResourceV3::Nodes(vec![[1; 32], [2; 32]]),
        caveats: Caveats { not_before: T - 1000, not_after: T, max_cpu: Some(4), ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 5, per: UsePer::Link }, egress(&[80, 443]), Caveat::Programs(vec![[5; 32], [6; 32]])],
        delegate: may_grant(3),
        nonce,
    }
}

/// Root by `a` (P-256) to `b`; `b` mints `grant` after `edit` to `c`, one level less deep.
fn child(edit: impl FnOnce(&mut Grant)) -> Result<Link> {
    let (a, b) = (p256(9), ed(2));
    let root = mint_root(&a, grant(b.key(), 1)).unwrap();
    let mut g = grant(ed(3).key(), 2);
    g.delegate = may_grant(2);
    edit(&mut g);
    attenuate(&b, &root, g)
}

fn refused(r: Result<impl std::fmt::Debug>, want: &str) {
    let e = r.expect_err(want).0;
    assert!(e.starts_with("refusing to mint: ") && e.contains(want), "{e:?} does not say {want:?}");
}

fn cap_of(l: &Link) -> &CapabilityV3 {
    match l {
        Link::V3 { cap, .. } => cap,
        Link::V1(_) => panic!("expected a v3 link"),
    }
}

/// `cap` signed as is, with no mint check: what a dishonest holder can produce.
fn forge(signer: &Signer, cap: CapabilityV3) -> Link {
    let sig = signer.sign(&cap);
    Link::V3 { cap, sig }
}

#[test]
fn a_child_equal_to_its_parent_on_every_axis_but_depth_is_minted() {
    let l = child(|_| {}).unwrap();
    assert_eq!(cap_of(&l).delegate.as_ref().unwrap().depth, 2);
}

#[test]
fn one_step_past_the_parent_is_refused_on_each_axis() {
    const W: &str = "caveats are broader than the parent";
    refused(child(|g| g.delegate = may_grant(3)), "delegation depth exceeds the parent");
    refused(child(|g| g.ext[0] = Caveat::Uses { max: 6, per: UsePer::Link }), W);
    refused(child(|g| g.caveats.not_after = T + 1), W);
    refused(child(|g| g.caveats.not_before = T - 1001), W);
    refused(child(|g| g.caveats.max_cpu = Some(5)), W);
    refused(child(|g| g.caveats.max_cpu = None), W);
    refused(child(|g| g.ext[1] = egress(&[80, 443, 8080])), W);
    refused(child(|g| g.ext[2] = Caveat::Programs(vec![[5; 32], [7; 32]])), W);
    refused(child(|g| g.resource = ResourceV3::Nodes(vec![[1; 32], [2; 32], [3; 32]])), "resource is broader than the parent");
    refused(child(|g| g.abilities.push("proc.spawn:kill".into())), "abilities exceed the parent's grant");
    // One step inside on each of the same axes is minted.
    child(|g| {
        g.delegate = may_grant(1);
        g.ext = vec![Caveat::Uses { max: 4, per: UsePer::Link }, egress(&[443]), Caveat::Programs(vec![[6; 32]])];
        g.caveats = Caveats { not_before: T - 999, not_after: T - 1, max_cpu: Some(3), ..Caveats::default() };
        g.resource = ResourceV3::Node([2; 32]);
        g.abilities.clear();
    })
    .unwrap();
}

#[test]
fn depth_runs_out() {
    let (a, b, c, d) = (ed(1), ed(2), ed(3), ed(4));
    let mut g = grant(b.key(), 1);
    g.delegate = may_grant(2);
    let t = root_token(&a, g).unwrap();
    let mut g = grant(c.key(), 2);
    g.delegate = may_grant(1);
    let t = extend(&t, &b, g).unwrap();
    // Under depth 1 a child may exist but may not carry any delegation right.
    refused(extend(&t, &c, Grant { delegate: may_grant(1), ..grant(d.key(), 3) }), "delegation depth exceeds the parent");
    let t = extend(&t, &c, Grant { delegate: None, ..grant(d.key(), 3) }).unwrap();
    refused(extend(&t, &d, Grant { delegate: None, ..grant(ed(5).key(), 4) }), "the parent may not delegate");
}

#[test]
fn counted_links_stay_bounded() {
    refused(child(|g| g.resource = ResourceV3::Any), "resource is broader");
    let (a, b) = (ed(1), ed(2));
    refused(mint_root(&a, Grant { resource: ResourceV3::Any, ..grant(b.key(), 1) }), "finite resource");
    refused(mint_root(&a, Grant { caveats: Caveats::default(), ..grant(b.key(), 1) }), "not_after");
    let mut g = grant(b.key(), 1);
    g.ext[0] = Caveat::Uses { max: 1, per: UsePer::Action };
    g.delegate.as_mut().unwrap().abilities = vec!["proc.spawn:*".into()];
    refused(mint_root(&a, g), "without wildcards");
}

#[test]
fn p256_signs_roots_and_children_low_s_and_deterministic() {
    let (a, b) = (p256(9), p256(10));
    assert_eq!(mint_root(&a, grant(b.key(), 1)).unwrap().id(), mint_root(&a, grant(b.key(), 1)).unwrap().id());
    let mut parent = mint_root(&a, grant(b.key(), 0)).unwrap();
    // A P-256 holder attenuates; every signature it emits is canonical, verifies and is RFC 6979.
    for nonce in 1..40u64 {
        let g = || Grant { delegate: may_grant(2), ..grant(ed(3).key(), nonce) };
        let l = attenuate(&b, &parent, g()).unwrap();
        let Link::V3 { cap, sig } = &l else { panic!() };
        assert!(matches!(sig, Sig::P256(_)) && sig.canonical() && cap.issuer == b.key());
        verify_sig(cap, sig).unwrap();
        let Link::V3 { sig: again, .. } = &attenuate(&b, &parent, g()).unwrap() else { panic!() };
        assert_eq!(sig, again);
    }
    // A link signed by one key never verifies as issued by another.
    let Link::V3 { cap, sig } = &mut parent else { panic!() };
    cap.issuer = b.key();
    assert!(verify_sig(cap, sig).is_err());
}

#[test]
fn a_forged_or_malformed_parent_is_refused() {
    let (a, b) = (p256(9), ed(2));
    let g = || Grant { delegate: may_grant(2), ..grant(ed(3).key(), 2) };
    // Widened after signing: 5 uses became 500.
    let mut parent = mint_root(&a, grant(b.key(), 1)).unwrap();
    let Link::V3 { cap, .. } = &mut parent else { panic!() };
    cap.ext[0] = Caveat::Uses { max: 500, per: UsePer::Link };
    let ext = cap.ext.clone();
    refused(attenuate(&b, &parent, Grant { ext, ..g() }), "the parent's signature is invalid");
    // Signature of the wrong type for the issuer key.
    let good = mint_root(&a, grant(b.key(), 1)).unwrap();
    let wrong = Link::V3 { cap: cap_of(&good).clone(), sig: Sig::Ed25519([7; 64]) };
    refused(attenuate(&b, &wrong, g()), "the parent's signature is invalid");
    // Correctly signed but not canonical (ext out of order): no verifier accepts it.
    let mut cap = cap_of(&good).clone();
    cap.ext.swap(0, 1);
    refused(attenuate(&b, &forge(&a, cap), g()), "the parent is not canonical");
    // A v1 parent with a broken signature.
    let Key::Ed25519(bid) = b.key() else { panic!() };
    let root = Identity::from_secret_bytes(&[1; 32]);
    let mut v1 = SignedCapability::issue(&root, bid, vec!["proc.spawn:run".into()], Resource::Node([1; 32]), Caveats { not_after: T, ..Caveats::default() }, 7, None);
    let under_v1 = || Grant { resource: ResourceV3::Node([1; 32]), caveats: Caveats { not_after: T, ..Caveats::default() }, ..g() };
    attenuate(&b, &Link::V1(v1.clone()), under_v1()).unwrap();
    v1.cap.caveats.not_after = T + 1;
    refused(attenuate(&b, &Link::V1(v1), Grant { caveats: Caveats { not_after: T + 1, ..Caveats::default() }, ..under_v1() }), "the parent's signature is invalid");
}

#[test]
fn a_link_that_could_never_be_used_is_refused() {
    refused(child(|g| g.caveats.not_before = T + 1), "would never be valid");
    assert!(child(|g| g.caveats.not_before = T).is_ok());
    // 02 || ff..ff: x is not below the field prime, so this is no curve point.
    let mut bad = [0xff; 33];
    bad[0] = 0x02;
    refused(child(|g| g.audience = Key::P256(bad)), "not a P-256 point");
    refused(mint_root(&ed(1), grant(Key::P256(bad), 1)), "not a P-256 point");
    let d = Delegate { audience: AudienceSet::Keys(vec![Key::P256(bad)]), ..may_grant(3).unwrap() };
    refused(mint_root(&ed(1), Grant { delegate: Some(d), ..grant(ed(2).key(), 1) }), "not a P-256 point");
    let mut odd = [0u8; 33];
    odd[0] = 0x04;
    refused(mint_root(&ed(1), grant(Key::P256(odd), 1)), "not canonical");
}

#[test]
fn a_revocation_name_is_not_reused_in_a_chain() {
    let (a, b, c) = (ed(1), ed(2), ed(3));
    // `a` mints to itself: the child must not take the parent's (issuer, nonce).
    let root = mint_root(&a, grant(a.key(), 1)).unwrap();
    refused(attenuate(&a, &root, Grant { delegate: may_grant(2), ..grant(b.key(), 1) }), "the nonce is the parent's");
    attenuate(&a, &root, Grant { delegate: may_grant(2), ..grant(b.key(), 2) }).unwrap();
    // b -> c -> b -> ...: b's second link may not reuse the nonce of its first.
    let t = root_token(&a, grant(b.key(), 1)).unwrap();
    let t = extend(&t, &b, Grant { delegate: may_grant(2), ..grant(c.key(), 2) }).unwrap();
    let t = extend(&t, &c, Grant { delegate: may_grant(1), ..grant(b.key(), 2) }).unwrap();
    refused(extend(&t, &b, Grant { delegate: None, ..grant(c.key(), 2) }), "already used by this issuer");
    assert_eq!(extend(&t, &b, Grant { delegate: None, ..grant(c.key(), 3) }).unwrap().links.len(), 4);
}

#[test]
fn extend_refuses_a_chain_that_is_already_broken() {
    let (a, b, c) = (ed(1), ed(2), ed(3));
    let t = root_token(&a, grant(b.key(), 1)).unwrap();
    let leaf = || Grant { delegate: None, ..grant(ed(4).key(), 3) };
    // b signs itself a wider link without the minter: 50 uses under 5.
    let mut wide = grant(c.key(), 2);
    wide.delegate = may_grant(2);
    wide.ext[0] = Caveat::Uses { max: 50, per: UsePer::Link };
    let mut cap = cap_of(&t.links[0]).clone();
    cap = CapabilityV3 { issuer: b.key(), audience: c.key(), ext: wide.ext, delegate: wide.delegate, nonce: 2, parent: Some(cap_id(&cap)), ..cap };
    let bad = TokenV3 { links: vec![t.links[0].clone(), forge(&b, cap)], programs: vec![] };
    refused(extend(&bad, &c, Grant { ext: cap_of(&bad.links[1]).ext.clone(), ..leaf() }), "link 1: caveats are broader than the parent");
    // A v1 link after a v3 link.
    let Key::Ed25519(cid) = c.key() else { panic!() };
    let v1 = SignedCapability::issue(&Identity::from_secret_bytes(&[2; 32]), cid, vec!["proc.spawn:run".into()], Resource::Node([1; 32]), Caveats { not_after: T, ..Caveats::default() }, 9, Some(t.links[0].id()));
    let bad = TokenV3 { links: vec![t.links[0].clone(), Link::V1(v1)], programs: vec![] };
    refused(extend(&bad, &c, leaf()), "link 1: a v1 link cannot follow a v3 link");
    refused(extend(&TokenV3 { links: vec![], programs: vec![] }, &c, leaf()), "the token has no links");
}

#[test]
fn a_token_no_decoder_accepts_is_not_minted() {
    let (a, b) = (ed(1), ed(2));
    let huge = "x".repeat(MAX_TOKEN);
    refused(root_token(&a, Grant { abilities: vec![huge.clone()], ..grant(b.key(), 1) }), "exceed");
    let t = root_token(&a, Grant { delegate: Some(Delegate { abilities: vec!["*".into()], ..may_grant(3).unwrap() }), ..grant(b.key(), 1) }).unwrap();
    refused(extend(&t, &b, Grant { abilities: vec![huge], delegate: None, ..grant(ed(3).key(), 2) }), "exceed");
}
