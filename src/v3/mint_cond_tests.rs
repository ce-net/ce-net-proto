//! Mint tests, third file: the conditions of section 4.1 (`Requires`, `CoSign`, `Via`) narrow only
//! one way. A child may add entries and tighten freshness; it may never drop, swap or loosen one.
//! The three chains are Leif's examples: read the wechat chat first, the system's guardian agent
//! signs and brokers every use, the 3D printer is reached only through its agent.

use super::mint::{Grant, attenuate, extend, inherit_conditions, mint_root, root_token};
use super::narrow::fresh_no_looser;
use super::sign::Signer;
use super::types::AudienceSet;
use super::*;
use crate::cap::Caveats;
use crate::program::ResourceV3;

fn ed(seed: u8) -> Signer {
    Signer::ed25519(&[seed; 32])
}

fn p256(seed: u8) -> Signer {
    Signer::p256(&[seed; 32]).unwrap()
}

/// "the wechat cell attests the requester read `thread` through its newest message".
fn read_wechat(thread: &str, fresh: Option<u64>) -> Requirement {
    let claim = Claim::ReadThrough { source: "wechat".into(), thread: thread.into(), upto_msg: None };
    Requirement { witness: Party::Cell("wechat.read".into()), claim, fresh_within_s: fresh }
}

fn cosign(by: &[Key]) -> Caveat {
    let mut v: Vec<CoSigner> = by.iter().map(|k| CoSigner { by: *k, per: CoSignPer::Use }).collect();
    v.sort_by_key(|c| bincode::serialize(c).unwrap());
    Caveat::CoSign(v)
}

fn via(bs: &[Party]) -> Caveat {
    let mut v = bs.to_vec();
    v.sort_by_key(|b| bincode::serialize(b).unwrap());
    Caveat::Via(v)
}

fn printer_gate() -> Party {
    Party::Cell("printer3d.gate".into())
}

fn grant(audience: Key, nonce: u64, depth: u8, ext: Vec<Caveat>) -> Grant {
    let abilities = vec!["wechat.send:send".to_string(), "printer3d:*".to_string()];
    Grant {
        audience,
        abilities: abilities.clone(),
        resource: ResourceV3::Any,
        caveats: Caveats::default(),
        ext,
        delegate: (depth > 0).then(|| Delegate { abilities, audience: AudienceSet::Any, depth }),
        nonce,
    }
}

/// Root by 1 to 2 carrying `parent_ext`; 2 mints a child to 3 carrying `child_ext`.
fn child(parent_ext: Vec<Caveat>, child_ext: Vec<Caveat>) -> Result<Link> {
    let root = mint_root(&ed(1), grant(ed(2).key(), 1, 3, parent_ext)).unwrap();
    attenuate(&ed(2), &root, grant(ed(3).key(), 2, 2, child_ext))
}

fn refused(r: Result<impl std::fmt::Debug>, want: &str) {
    let e = r.expect_err(want).0;
    assert!(e.starts_with("refusing to mint: ") && e.contains(want), "{e:?} does not say {want:?}");
}

const BROADER: &str = "caveats are broader than the parent";

fn ext_of(l: &Link) -> &[Caveat] {
    match l {
        Link::V3 { cap, .. } => &cap.ext,
        Link::V1(_) => panic!("expected a v3 link"),
    }
}

#[test]
fn freshness_none_is_the_loosest() {
    assert!(fresh_no_looser(None, None) && fresh_no_looser(Some(1), None) && fresh_no_looser(Some(600), Some(600)));
    assert!(fresh_no_looser(Some(599), Some(600)));
    assert!(!fresh_no_looser(Some(601), Some(600)) && !fresh_no_looser(None, Some(u64::MAX)));
}

#[test]
fn wechat_read_first_is_kept_tightened_or_added_to_never_dropped() {
    let parent = || vec![Caveat::Requires(vec![read_wechat("family", Some(600))])];
    // Equal, fresher, and with a second requirement added: all minted.
    child(parent(), parent()).unwrap();
    child(parent(), vec![Caveat::Requires(vec![read_wechat("family", Some(60))])]).unwrap();
    let mut two = vec![read_wechat("family", Some(600)), read_wechat("work", None)];
    two.sort_by_key(|r| bincode::serialize(r).unwrap());
    child(parent(), vec![Caveat::Requires(two)]).unwrap();
    // Dropped outright, dropped behind another caveat, or replaced by a different requirement.
    refused(child(parent(), vec![]), BROADER);
    refused(child(parent(), vec![Caveat::Uses { max: 1, per: UsePer::Link }]), BROADER);
    refused(child(parent(), vec![Caveat::Requires(vec![read_wechat("work", Some(600))])]), BROADER);
    // Staler, or no freshness at all.
    refused(child(parent(), vec![Caveat::Requires(vec![read_wechat("family", Some(601))])]), BROADER);
    refused(child(parent(), vec![Caveat::Requires(vec![read_wechat("family", None)])]), BROADER);
    // Another witness, or a pinned message in place of "the newest": equal claims only.
    let mut other = read_wechat("family", Some(600));
    other.witness = Party::Key(ed(7).key());
    refused(child(parent(), vec![Caveat::Requires(vec![other])]), BROADER);
    let mut pinned = read_wechat("family", Some(600));
    pinned.claim = Claim::ReadThrough { source: "wechat".into(), thread: "family".into(), upto_msg: Some("m9".into()) };
    refused(child(parent(), vec![Caveat::Requires(vec![pinned])]), BROADER);
}

#[test]
fn guardian_cosign_and_broker_are_kept_or_added_to_never_dropped() {
    let (guardian, second) = (p256(8).key(), ed(9).key());
    let parent = || vec![cosign(&[guardian]), via(&[Party::Key(guardian)])];
    child(parent(), parent()).unwrap();
    child(parent(), vec![cosign(&[guardian, second]), via(&[Party::Key(guardian), printer_gate()])]).unwrap();
    // Either half dropped.
    refused(child(parent(), vec![cosign(&[guardian])]), BROADER);
    refused(child(parent(), vec![via(&[Party::Key(guardian)])]), BROADER);
    // The guardian swapped for a key the holder controls.
    refused(child(parent(), vec![cosign(&[second]), via(&[Party::Key(guardian)])]), BROADER);
    refused(child(parent(), vec![cosign(&[guardian]), via(&[Party::Key(second)])]), BROADER);
    // One condition is no substitute for another.
    refused(child(parent(), vec![cosign(&[guardian]), Caveat::Requires(vec![read_wechat("family", None)])]), BROADER);
}

#[test]
fn printer_broker_is_kept_or_added_to_never_dropped() {
    let parent = || vec![via(&[printer_gate()])];
    child(parent(), parent()).unwrap();
    child(parent(), vec![via(&[printer_gate(), Party::Key(ed(8).key())])]).unwrap();
    refused(child(parent(), vec![]), BROADER);
    refused(child(parent(), vec![via(&[Party::Cell("printer3d.other".into())])]), BROADER);
    // The cell api is not the same broker as a fixed key, even the key serving it today.
    refused(child(parent(), vec![via(&[Party::Key(ed(8).key())])]), BROADER);
}

#[test]
fn a_child_may_add_a_condition_its_parent_lacks() {
    let l = child(vec![], vec![Caveat::Requires(vec![read_wechat("family", Some(600))]), via(&[printer_gate()])]).unwrap();
    assert_eq!(ext_of(&l).len(), 2);
}

#[test]
fn a_condition_dropped_two_links_down_is_refused_and_cannot_be_laundered() {
    let conds = || vec![Caveat::Requires(vec![read_wechat("family", Some(600))]), via(&[printer_gate()])];
    let t = root_token(&ed(1), grant(ed(2).key(), 1, 3, conds())).unwrap();
    let t = extend(&t, &ed(2), grant(ed(3).key(), 2, 2, conds())).unwrap();
    refused(extend(&t, &ed(3), grant(ed(4).key(), 3, 1, vec![via(&[printer_gate()])])), BROADER);
    let t3 = extend(&t, &ed(3), grant(ed(4).key(), 3, 1, conds())).unwrap();
    assert_eq!(t3.links.len(), 3);
    // A holder who signs the dropping link itself gains nothing: nobody extends that chain.
    let Link::V3 { cap, .. } = &t3.links[2] else { panic!() };
    let mut forged = cap.clone();
    forged.ext = vec![];
    let sig = ed(3).sign(&forged);
    let mut bad = t.clone();
    bad.links.push(Link::V3 { cap: forged, sig });
    refused(extend(&bad, &ed(4), grant(ed(5).key(), 4, 0, vec![])), "the token is already invalid (link 2: caveats are broader");
}

#[test]
fn malformed_conditions_are_refused_at_mint() {
    let root = |ext| mint_root(&ed(1), grant(ed(2).key(), 1, 1, ext));
    refused(root(vec![Caveat::Via(vec![])]), "not canonical");
    refused(root(vec![Caveat::Requires(vec![read_wechat("family", Some(0))])]), "not canonical");
    refused(root(vec![Caveat::Requires(vec![read_wechat("family", Some(5)), read_wechat("family", Some(9))])]), "not canonical");
    refused(root(vec![via(&[printer_gate()]), cosign(&[ed(8).key()])]), "not canonical");
    // A P-256 key off the curve can never sign: the link would be dead on arrival.
    let off_curve = (0u8..=255).map(|b| Key::P256([[2].as_slice(), &[b; 32]].concat().try_into().unwrap()));
    let off_curve = off_curve.into_iter().find(|k| matches!(k, Key::P256(p) if p256::ecdsa::VerifyingKey::from_sec1_bytes(p).is_err())).unwrap();
    for ext in [cosign(&[off_curve]), via(&[Party::Key(off_curve)])] {
        refused(root(vec![ext]), "a condition names a key that is not a P-256 point");
    }
    let mut r = read_wechat("family", None);
    r.witness = Party::Key(off_curve);
    refused(root(vec![Caveat::Requires(vec![r])]), "a condition names a key that is not a P-256 point");
}

#[test]
fn inherit_conditions_carries_every_entry_and_only_tightens() {
    let guardian = p256(8).key();
    let parent_ext = vec![
        Caveat::Programs(vec![[5; 32], [6; 32]]),
        Caveat::Requires(vec![read_wechat("family", Some(600))]),
        cosign(&[guardian]),
        via(&[printer_gate()]),
    ];
    let root = mint_root(&ed(1), grant(ed(2).key(), 1, 3, parent_ext.clone())).unwrap();
    let mint = |ext| attenuate(&ed(2), &root, grant(ed(3).key(), 2, 2, ext));

    // Nothing of its own: exactly the parent's conditions, and no other caveat is invented.
    let bare = inherit_conditions(&root, vec![]);
    assert_eq!(bare, parent_ext[1..].to_vec());
    refused(mint(bare), BROADER); // `Programs` is not a condition: the caller still states it.

    // Its own additions survive; a looser freshness is tightened to the parent's, a tighter one kept.
    let own = vec![
        via(&[Party::Key(ed(9).key())]),
        Caveat::Requires(vec![read_wechat("family", None), read_wechat("work", Some(30))]),
        Caveat::Programs(vec![[5; 32]]),
    ];
    let ext = inherit_conditions(&root, own);
    let l = mint(ext.clone()).unwrap();
    assert_eq!(ext_of(&l), ext.as_slice());
    let Caveat::Requires(rs) = &ext[1] else { panic!() };
    assert!(rs.contains(&read_wechat("family", Some(600))) && rs.contains(&read_wechat("work", Some(30))) && rs.len() == 2);
    let Caveat::Via(bs) = &ext[3] else { panic!() };
    assert!(bs.contains(&printer_gate()) && bs.contains(&Party::Key(ed(9).key())));
    let tighter = inherit_conditions(&root, vec![Caveat::Requires(vec![read_wechat("family", Some(60))])]);
    assert_eq!(tighter[0], Caveat::Requires(vec![read_wechat("family", Some(60))]));

    // Idempotent, and a grandchild inherits what the child added.
    assert_eq!(inherit_conditions(&root, ext.clone()), ext);
    assert_eq!(inherit_conditions(&l, vec![]), ext[1..].to_vec());
}
