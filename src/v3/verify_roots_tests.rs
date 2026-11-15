//! `verify_chain_v3` at the head of the chain: V1 links (section 3.3), owner roots and WebAuthn
//! signatures (sections 2 and 9).

use sha2::{Digest, Sha256};

use super::mint::mint_root;
use super::verify::{OwnerRoot, Roots, verify_chain_v3};
use super::verify_tests::*;
use super::*;
use crate::cap::{Caveats, Resource, SignedCapability};
use crate::program::ResourceV3;
use crate::{Identity, NodeId};

fn id(seed: u8) -> Identity {
    Identity::from_secret_bytes(&[seed; 32])
}

fn node_id(seed: u8) -> NodeId {
    id(seed).node_id()
}

fn v1(issuer: u8, audience: u8, abilities: &[&str], nonce: u64, parent: Option<&SignedCapability>) -> SignedCapability {
    let caveats = Caveats { not_after: T, path_prefix: Some("/opt/x".into()), ..Caveats::default() };
    SignedCapability::issue(&id(issuer), node_id(audience), strs(abilities), Resource::Any, caveats, nonce, parent.map(|p| p.id()))
}

/// A V3 leaf under the V1 link `head`, issued by ed(`issuer`) to ed(3).
fn v3_under(head: &Link, issuer: u8, f: impl FnOnce(&mut CapabilityV3)) -> Link {
    let mut cap = leaf_cap(ed(issuer).key(), ed(3).key(), head);
    f(&mut cap);
    signed(&ed(issuer), cap)
}

#[test]
fn v1_links_head_a_chain() {
    let a = v1(1, 5, &["talk:send", "cell.install:*"], 11, None);
    let b = v1(5, 6, &["talk:send", "cell.install:install-file"], 12, Some(&a));
    let (la, lb) = (Link::V1(a.clone()), Link::V1(b.clone()));
    // one V1 link alone, read as section 3.3: its holder may use it and re-delegate it
    let v = verify(&token(vec![la.clone()])).unwrap();
    assert_eq!((v.holder, v.resource.clone(), v.ext.len(), v.counted.len()), (ed(5).key(), ResourceV3::Any, 0, 0));
    assert_eq!(v.delegate, delegate(&["talk:send", "cell.install:*"], types::AudienceSet::Any, 255));
    // V1, V1, V3: the V3 link names its V1 parent by the v1 cap id
    let leaf = v3_under(&lb, 6, |_| {});
    let t = token(vec![la.clone(), lb.clone(), leaf.clone()]);
    let v = verify(&t).unwrap();
    assert_eq!((v.links, v.holder, v.ids[1], v.counted.len()), (3, ed(3).key(), b.id(), 1));
    // after the first V3 link every link is V3
    assert_eq!(verify(&token(vec![la.clone(), lb.clone(), leaf.clone(), lb.clone()])).unwrap_err(), "link 3: a v1 link cannot follow a v3 link");
    let root = mint_root(&ed(1), root_grant(ed(5).key())).unwrap();
    assert_eq!(verify(&token(vec![root, lb.clone()])).unwrap_err(), "link 1: a v1 link cannot follow a v3 link");
    // a V3 link is held inside its V1 parent: abilities, v1 caveats, continuity
    let under_b = |f: fn(&mut CapabilityV3)| verify(&token(vec![la.clone(), lb.clone(), v3_under(&lb, 6, f)])).unwrap_err();
    assert_eq!(under_b(|c| c.abilities.push("cell.install:install".into())), "link 2: abilities exceed the parent's grant");
    assert_eq!(under_b(|c| c.caveats.not_after = T + 1), "link 2: caveats are broader than the parent");
    assert_eq!(under_b(|c| c.caveats.path_prefix = Some("/opt".into())), "link 2: caveats are broader than the parent");
    assert_eq!(under_b(|c| c.parent = Some([0; 32])), "link 2: parent hash does not match the chain");
    assert_eq!(verify(&token(vec![la.clone(), lb.clone(), v3_under(&lb, 5, |_| {})])).unwrap_err(), "link 2: issuer is not the parent's audience");
}

#[test]
fn v1_links_keep_the_v1_rules() {
    let a = v1(1, 5, &["talk:send"], 11, None);
    let chain = |b: SignedCapability| verify(&token(vec![Link::V1(a.clone()), Link::V1(b)])).map(|v| v.links);
    assert_eq!(chain(v1(5, 6, &["talk:send"], 12, Some(&a))), Ok(2));
    assert_eq!(chain(v1(5, 6, &["talk:send", "talk:read"], 12, Some(&a))).unwrap_err(), "link 1: abilities exceed the parent");
    assert_eq!(chain(v1(7, 6, &["talk:send"], 12, Some(&a))).unwrap_err(), "link 1: issuer is not the parent's audience");
    assert_eq!(chain(v1(5, 6, &["talk:send"], 12, None)).unwrap_err(), "link 1: parent hash does not match the chain");
    let mut wide = v1(5, 6, &["talk:send"], 12, Some(&a));
    wide.cap.caveats.not_after = T + 1;
    assert_eq!(chain(wide).unwrap_err(), "link 1: invalid signature");
    let later = Caveats { not_after: T + 1, path_prefix: Some("/opt/x".into()), ..Caveats::default() };
    let wide = SignedCapability::issue(&id(5), node_id(6), strs(&["talk:send"]), Resource::Any, later, 12, Some(a.id()));
    assert_eq!(chain(wide).unwrap_err(), "link 1: caveats are broader than the parent");
    // a v1 revocation names (issuer, nonce) of a V1 link as Key::Ed25519
    let t = token(vec![Link::V1(a.clone()), Link::V1(v1(5, 6, &["talk:send"], 12, Some(&a)))]);
    let r = Roots { keys: &[ed(1).key()], owners: &[] };
    let revoked = |k: &Key, n: u64| (*k, n) == (ed(5).key(), 12);
    assert_eq!(verify_chain_v3(&t, &r, NOW, &revoked).unwrap_err(), "link 1: capability revoked");
    assert_eq!(verify_chain_v3(&t, &r, T + 1, &never).unwrap_err(), "link 0: capability has expired");
    // a V1 root that names a parent
    let orphan = v1(1, 5, &["talk:send"], 13, Some(&a));
    assert_eq!(verify(&token(vec![Link::V1(orphan)])).unwrap_err(), "root capability must not name a parent");
}

fn owner(key: Key, rp_id: Option<&str>, not_before: u64, not_after: u64) -> [OwnerRoot; 1] {
    [OwnerRoot { key, rp_id: rp_id.map(str::to_string), not_before, not_after }]
}

#[test]
fn owner_roots_head_v3_chains_inside_their_window() {
    let not_root = "capability chain does not root at an accepted authority";
    let t = chain(|_| {});
    let with = |t: &TokenV3, o: &[OwnerRoot]| verify_chain_v3(t, &Roots { keys: &[], owners: o }, NOW, &never).map(|v| v.root);
    assert_eq!(with(&t, &owner(ed(1).key(), None, 0, 0)), Ok(ed(1).key()));
    assert_eq!(with(&t, &owner(ed(1).key(), None, NOW, NOW)), Ok(ed(1).key()));
    assert_eq!(with(&t, &owner(ed(1).key(), None, NOW + 1, 0)).unwrap_err(), not_root);
    assert_eq!(with(&t, &owner(ed(1).key(), None, 0, NOW - 1)).unwrap_err(), not_root);
    assert_eq!(with(&t, &owner(ed(9).key(), None, 0, 0)).unwrap_err(), not_root);
    // an owner key never heads a v1 chain
    let head = token(vec![Link::V1(v1(1, 5, &["talk:send"], 11, None))]);
    assert_eq!(with(&head, &owner(ed(1).key(), None, 0, 0)).unwrap_err(), not_root);
}

/// A passkey assertion by p256(`seed`) with the given challenge, rp id and flags.
pub(super) fn assertion(seed: u8, challenge: &[u8; 32], rp_id: &str, flags: u8) -> Sig {
    use p256::ecdsa::signature::Signer as _;
    let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    let client_data =
        format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://{rp_id}"}}"#, webauthn::b64url(challenge)).into_bytes();
    let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
    auth_data.extend([flags, 0, 0, 0, 1]);
    let mut msg = auth_data.clone();
    msg.extend(Sha256::digest(&client_data));
    let s: p256::ecdsa::Signature = sk.sign(&msg);
    Sig::WebAuthn { auth_data, client_data, sig: s.to_der().as_bytes().to_vec() }
}

#[test]
fn webauthn_signatures_need_a_live_owner_entry_with_the_rp_id() {
    let key = p256(9).key();
    let Link::V3 { cap, .. } = mint_root(&p256(9), root_grant(p256(2).key())).unwrap() else { unreachable!() };
    let good = assertion(9, &cap_id(&cap), "ce-net.com", 0x05);
    let run = |sig: Sig, keys: &[Key], o: &[OwnerRoot]| {
        let t = token(vec![Link::V3 { cap: cap.clone(), sig }]);
        verify_chain_v3(&t, &Roots { keys, owners: o }, NOW, &never).map(|v| v.root)
    };
    let live = owner(key, Some("ce-net.com"), 0, 0);
    assert_eq!(run(good.clone(), &[], &live), Ok(key));
    let bad = "link 0: invalid signature";
    assert_eq!(run(assertion(9, &[0; 32], "ce-net.com", 0x05), &[], &live).unwrap_err(), bad);
    assert_eq!(run(assertion(9, &cap_id(&cap), "ce-net.com", 0x01), &[], &live).unwrap_err(), bad, "no user verification");
    assert_eq!(run(assertion(9, &cap_id(&cap), "ce-net.com", 0x04), &[], &live).unwrap_err(), bad, "no user presence");
    assert_eq!(run(assertion(9, &cap_id(&cap), "evil.example", 0x05), &[], &live).unwrap_err(), bad);
    assert_eq!(run(assertion(8, &cap_id(&cap), "ce-net.com", 0x05), &[], &live).unwrap_err(), bad, "another passkey");
    // the rp id comes from an owner entry valid now: none recorded, or a gate key only, is no rp id
    assert_eq!(run(good.clone(), &[], &owner(key, None, 0, 0)).unwrap_err(), bad);
    assert_eq!(run(good.clone(), &[key], &[]).unwrap_err(), bad);
    assert_eq!(run(good.clone(), &[key], &owner(key, Some("ce-net.com"), 0, NOW - 1)).unwrap_err(), bad);
    assert_eq!(run(good.clone(), &[key], &owner(p256(8).key(), Some("ce-net.com"), 0, 0)).unwrap_err(), bad);
    // an Ed25519 issuer cannot carry a WebAuthn signature
    let Link::V3 { cap: ed_cap, .. } = chain(|_| {}).links[0].clone() else { unreachable!() };
    let t = token(vec![Link::V3 { sig: assertion(9, &cap_id(&ed_cap), "ce-net.com", 0x05), cap: ed_cap }]);
    assert_eq!(verify(&t).unwrap_err(), "link 0: signature type does not match the issuer key");
}
