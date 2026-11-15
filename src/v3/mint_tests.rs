//! Mint tests: roots and children with Ed25519 and P-256, and a refusal for every way a child can
//! be wider than its parent.

use super::mint::{Grant, attenuate, extend, mint_root, root_token};
use super::narrow::{Parent, V1_DEPTH};
use super::sign::{Signer, verify_sig};
use super::types::AudienceSet;
use super::*;
use crate::cap::{Caveats, Resource, SignedCapability};
use crate::program::{EgressRule, HostPat, Limit, Proto, ResourceV3};
use crate::Identity;

const T: u64 = 2_000_000_000;

fn ed(seed: u8) -> Signer {
    Signer::ed25519(&[seed; 32])
}

fn p256(seed: u8) -> Signer {
    Signer::p256(&[seed; 32]).unwrap()
}

fn egress(host: HostPat) -> Caveat {
    Caveat::Egress(vec![EgressRule { host, ports: vec![443], proto: Proto::Tcp }])
}

fn limits(max: u64) -> Caveat {
    Caveat::Limits(vec![Limit { name: "net.egress.bytes_out".into(), max }])
}

fn delegate(abilities: &[&str], audience: AudienceSet, depth: u8) -> Option<Delegate> {
    Some(Delegate { abilities: abilities.iter().map(|s| s.to_string()).collect(), audience, depth })
}

/// "may grant net.egress:connect and proc.spawn:* on nodes 1..3, depth <= 3, 5 uses, until T".
fn root_grant(audience: Key) -> Grant {
    Grant {
        audience,
        abilities: vec![],
        resource: ResourceV3::Nodes(vec![[1; 32], [2; 32], [3; 32]]),
        caveats: Caveats { not_after: T, ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 5, per: UsePer::Link }, limits(500), egress(HostPat::Suffix(".example.org".into()))],
        delegate: delegate(&["net.egress:connect", "proc.spawn:*"], AudienceSet::Any, 3),
        nonce: 1,
    }
}

/// A child no wider than [`root_grant`] on any axis.
fn child_grant(audience: Key, next: Key) -> Grant {
    Grant {
        audience,
        abilities: vec!["net.egress:connect".into()],
        resource: ResourceV3::Nodes(vec![[1; 32], [2; 32]]),
        caveats: Caveats { not_after: T - 100, ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 2, per: UsePer::Link }, limits(100), egress(HostPat::Name("api.example.org".into()))],
        delegate: delegate(&["proc.spawn:run"], AudienceSet::Keys(vec![next]), 2),
        nonce: 2,
    }
}

/// Root by `a` to `b`; `b` then mints the child grant after `edit`, to `c`.
fn mint_child(edit: impl FnOnce(&mut Grant)) -> Result<Link> {
    let (a, b, c) = (p256(9), ed(2), ed(3));
    let root = mint_root(&a, root_grant(b.key())).unwrap();
    let mut g = child_grant(c.key(), ed(4).key());
    edit(&mut g);
    attenuate(&b, &root, g)
}

fn refused(edit: impl FnOnce(&mut Grant), want: &str) {
    let e = mint_child(edit).expect_err(want).0;
    assert!(e.starts_with("refusing to mint: ") && e.contains(want), "{e:?} does not say {want:?}");
}

fn parts(l: &Link) -> (&CapabilityV3, &Sig) {
    match l {
        Link::V3 { cap, sig } => (cap, sig),
        Link::V1(_) => panic!("expected a v3 link"),
    }
}

#[test]
fn ed25519_root_signs_and_round_trips() {
    let a = ed(1);
    let t = root_token(&a, root_grant(ed(2).key())).unwrap();
    let (cap, sig) = parts(&t.links[0]);
    assert_eq!(cap.issuer, a.key());
    assert_eq!(cap.parent, None);
    assert!(matches!(sig, Sig::Ed25519(_)));
    verify_sig(cap, sig).unwrap();
    let back = TokenV3::decode(&t.encode()).unwrap();
    assert_eq!(back.encode(), t.encode());
}

#[test]
fn p256_root_is_compressed_low_s_and_verifies() {
    let a = p256(9);
    let Key::P256(k) = a.key() else { panic!("P-256 key") };
    assert!(k[0] == 2 || k[0] == 3);
    let l = mint_root(&a, root_grant(ed(2).key())).unwrap();
    let (cap, sig) = parts(&l);
    assert!(matches!(sig, Sig::P256(_)) && sig.canonical());
    verify_sig(cap, sig).unwrap();
    // Deterministic (RFC 6979): the same statement signs to the same bytes.
    assert_eq!(&a.sign(cap), sig);
}

#[test]
fn p256_rejects_bad_secrets() {
    assert!(Signer::p256(&[0; 32]).is_err());
    assert!(Signer::p256(&[0xff; 32]).is_err());
}

#[test]
fn chain_of_three_links_verifies_and_decodes() {
    let (a, b, c) = (p256(9), ed(2), ed(3));
    let t = root_token(&a, root_grant(b.key())).unwrap();
    let t = extend(&t, &b, child_grant(c.key(), ed(4).key())).unwrap();
    let leaf = Grant {
        audience: ed(4).key(),
        abilities: vec![],
        resource: ResourceV3::Node([2; 32]),
        caveats: Caveats { not_after: T - 200, ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 1, per: UsePer::Link }, limits(10), egress(HostPat::Name("api.example.org".into())), Caveat::Programs(vec![[5; 32]])],
        delegate: delegate(&["proc.spawn:run"], AudienceSet::Keys(vec![ed(4).key()]), 1),
        nonce: 3,
    };
    let t = extend(&t, &c, leaf).unwrap();
    assert_eq!(t.links.len(), 3);
    for i in 1..3 {
        let (cap, sig) = parts(&t.links[i]);
        verify_sig(cap, sig).unwrap();
        assert_eq!(cap.parent, Some(t.links[i - 1].id()));
    }
    assert_eq!(TokenV3::decode(&t.encode()).unwrap().encode(), t.encode());
    // The leaf's delegate has depth 1: nothing below it may re-delegate.
    let mut g = child_grant(ed(4).key(), ed(5).key());
    g.abilities = vec![];
    g.resource = ResourceV3::Node([2; 32]);
    let e = extend(&t, &ed(4), g).unwrap_err().0;
    assert!(e.contains("delegation depth exceeds the parent"), "{e}");
}

#[test]
fn signer_must_be_the_parents_audience() {
    let root = mint_root(&p256(9), root_grant(ed(2).key())).unwrap();
    let e = attenuate(&ed(7), &root, child_grant(ed(3).key(), ed(4).key())).unwrap_err().0;
    assert!(e.contains("issuer is not the parent's audience"), "{e}");
}

#[test]
fn final_parent_may_not_delegate() {
    let mut g = root_grant(ed(2).key());
    g.delegate = None;
    let root = mint_root(&p256(9), g).unwrap();
    let e = attenuate(&ed(2), &root, child_grant(ed(3).key(), ed(4).key())).unwrap_err().0;
    assert!(e.contains("the parent may not delegate"), "{e}");
}

#[test]
fn audience_outside_grant() {
    let (a, b) = (p256(9), ed(2));
    let mut g = root_grant(b.key());
    g.delegate = delegate(&["net.egress:connect"], AudienceSet::Keys(vec![ed(3).key()]), 3);
    let root = mint_root(&a, g).unwrap();
    let e = attenuate(&b, &root, child_grant(ed(8).key(), ed(4).key())).unwrap_err().0;
    assert!(e.contains("audience is outside the parent's grant"), "{e}");
    // Grantable audience Any under Keys is wider, too.
    let mut c = child_grant(ed(3).key(), ed(4).key());
    c.delegate = delegate(&["net.egress:connect"], AudienceSet::Any, 2);
    let e = attenuate(&b, &root, c).unwrap_err().0;
    assert!(e.contains("grantable audience exceeds the parent"), "{e}");
}

#[test]
fn abilities_wider_than_the_grant() {
    refused(|g| g.abilities = vec!["net.egress:*".into()], "abilities exceed the parent's grant");
    refused(|g| g.abilities = vec!["cell.install:install-file".into()], "abilities exceed the parent's grant");
    refused(|g| g.abilities = vec!["*".into()], "abilities exceed the parent's grant");
    refused(|g| g.delegate = delegate(&["proc.*"], AudienceSet::Any, 2), "grantable abilities exceed the parent");
    refused(|g| g.delegate = delegate(&["cell.install:x"], AudienceSet::Any, 2), "grantable abilities exceed the parent");
}

#[test]
fn depth_must_drop_by_one() {
    refused(|g| g.delegate = delegate(&["proc.spawn:run"], AudienceSet::Any, 3), "delegation depth exceeds the parent");
    refused(|g| g.delegate = delegate(&["proc.spawn:run"], AudienceSet::Any, 255), "delegation depth exceeds the parent");
    assert!(mint_child(|g| g.delegate = None).is_ok());
}

#[test]
fn resource_broader() {
    refused(|g| g.resource = ResourceV3::Any, "resource is broader than the parent");
    refused(|g| g.resource = ResourceV3::Nodes(vec![[1; 32], [4; 32]]), "resource is broader than the parent");
    refused(|g| g.resource = ResourceV3::Tag("gpu".into()), "resource is broader than the parent");
    assert!(mint_child(|g| g.resource = ResourceV3::Node([3; 32])).is_ok());
}

#[test]
fn expiry_and_v1_caveats_no_looser() {
    const W: &str = "caveats are broader than the parent";
    refused(|g| g.caveats.not_after = T + 1, W);
    // Never expiring (0) under an expiring parent.
    refused(|g| g.caveats.not_after = 0, W);
    // A v1 ceiling: the parent confines paths, the child must stay inside.
    let (a, b) = (p256(9), ed(2));
    let mut r = root_grant(b.key());
    r.caveats.path_prefix = Some("/opt/x".into());
    let root = mint_root(&a, r).unwrap();
    let mut c = child_grant(ed(3).key(), ed(4).key());
    c.caveats.path_prefix = Some("/opt/xy".into());
    assert!(attenuate(&b, &root, c.clone()).unwrap_err().0.contains(W));
    c.caveats.path_prefix = None;
    assert!(attenuate(&b, &root, c.clone()).unwrap_err().0.contains(W));
    c.caveats.path_prefix = Some("/opt/x/sub".into());
    assert!(attenuate(&b, &root, c).is_ok());
}

#[test]
fn ext_caveats_no_looser() {
    const W: &str = "caveats are broader than the parent";
    refused(|g| g.ext[0] = Caveat::Uses { max: 6, per: UsePer::Link }, W);
    refused(|g| g.ext[0] = Caveat::Uses { max: 1, per: UsePer::Action }, W);
    refused(|g| g.ext[1] = limits(501), W);
    refused(|g| g.ext[1] = Caveat::Limits(vec![Limit { name: "net.egress.bytes_in".into(), max: 1 }]), W);
    refused(|g| g.ext[2] = egress(HostPat::Name("example.org".into())), W);
    refused(|g| g.ext[2] = egress(HostPat::Suffix(".org".into())), W);
    refused(|g| { g.ext.remove(2); }, W);
    refused(|g| { g.ext.remove(0); }, W);
    // A child may add a variant the parent lacks.
    assert!(mint_child(|g| g.ext.push(Caveat::Programs(vec![[5; 32]]))).is_ok());
}

#[test]
fn non_canonical_child_is_refused() {
    refused(|g| g.ext.swap(0, 1), "not canonical");
    refused(|g| g.delegate = delegate(&["proc.spawn:run"], AudienceSet::Any, 0), "not canonical");
    refused(|g| g.resource = ResourceV3::Nodes(vec![[2; 32], [1; 32]]), "not canonical");
}

#[test]
fn v1_parent_reads_as_section_3_3() {
    let (root, b) = (Identity::from_secret_bytes(&[1; 32]), ed(2));
    let Key::Ed25519(bid) = b.key() else { panic!() };
    let v1 = SignedCapability::issue(&root, bid, vec!["net.egress:*".into()], Resource::Node([1; 32]), Caveats { not_after: T, ..Caveats::default() }, 7, None);
    let link = Link::V1(v1.clone());
    let p = Parent::of(&link);
    assert_eq!((p.id, p.resource.clone(), p.delegate.as_ref().unwrap().depth), (v1.id(), ResourceV3::Node([1; 32]), V1_DEPTH));
    let mut g = child_grant(ed(3).key(), ed(4).key());
    g.resource = ResourceV3::Nodes(vec![[1; 32]]);
    g.delegate = delegate(&["net.egress:connect"], AudienceSet::Any, 254);
    let t = TokenV3 { links: vec![link], programs: vec![] };
    let t = extend(&t, &b, g.clone()).unwrap();
    assert_eq!(parts(&t.links[1]).0.parent, Some(v1.id()));
    g.delegate = delegate(&["net.egress:connect"], AudienceSet::Any, 255);
    assert!(extend(&TokenV3 { links: t.links[..1].to_vec(), programs: vec![] }, &b, g).is_err());
}

#[test]
fn verify_sig_refuses_tampering_high_s_and_mismatch() {
    let l = mint_root(&p256(9), root_grant(ed(2).key())).unwrap();
    let (cap, sig) = parts(&l);
    let mut other = cap.clone();
    other.nonce += 1;
    assert_eq!(verify_sig(&other, sig).unwrap_err(), "invalid signature");
    let Sig::P256(rs) = sig else { panic!() };
    let s = p256::ecdsa::Signature::from_slice(rs).unwrap();
    let high = p256::ecdsa::Signature::from_scalars(s.r().to_bytes(), (-*s.s()).to_bytes()).unwrap();
    let mut hb = [0u8; 64];
    hb.copy_from_slice(&high.to_bytes());
    assert!(verify_sig(cap, &Sig::P256(hb)).unwrap_err().contains("low-S"));
    assert!(verify_sig(cap, &Sig::Ed25519([0; 64])).unwrap_err().contains("does not match"));
}
