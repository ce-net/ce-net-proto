//! Byte-for-byte compatibility with the in-tree `ce-cap` (dev-dependency only).
//!
//! Both directions: chains issued / delegated / revoked with `ce-cap` verify with `ce-net-proto`,
//! and vice versa. Because Ed25519 is deterministic, the same keys and inputs must also produce the
//! *identical* token bytes in both implementations — asserted directly.

use ce_cap as old;
use ce_net_proto as new;

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}
fn old_id(n: u8) -> ce_identity::Identity {
    ce_identity::Identity::from_secret_bytes(&seed(n))
}
fn new_id(n: u8) -> new::Identity {
    new::Identity::from_secret_bytes(&seed(n))
}
fn never(_: &[u8; 32], _: u64) -> bool {
    false
}
fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

const ROOT: u8 = 1;
const MID: u8 = 2;
const LEAF: u8 = 3;
const NODE: u8 = 9;

fn old_caveats() -> old::Caveats {
    old::Caveats {
        not_before: 100,
        not_after: 10_000,
        max_cpu: Some(8),
        max_mem_mb: Some(4096),
        max_credits: None,
        allowed_ports: Some(vec![22, 443]),
        path_prefix: Some("/srv/data".into()),
    }
}
fn new_caveats() -> new::Caveats {
    new::Caveats {
        not_before: 100,
        not_after: 10_000,
        max_cpu: Some(8),
        max_mem_mb: Some(4096),
        max_credits: None,
        allowed_ports: Some(vec![22, 443]),
        path_prefix: Some("/srv/data".into()),
    }
}

/// root -> mid (issue) -> leaf (delegate), built with ce-cap.
fn old_chain() -> Vec<old::SignedCapability> {
    let (root, mid, leaf) = (old_id(ROOT), old_id(MID), old_id(LEAF));
    let c0 = old::SignedCapability::issue(
        &root,
        mid.node_id(),
        s(&["exec", "sync", "app:spawn:*"]),
        old::Resource::AllOf(s(&["gpu", "linux"])),
        old_caveats(),
        7,
        None,
    );
    old::delegate::delegate(
        &[c0],
        &mid,
        leaf.node_id(),
        &old::delegate::Grant { abilities: &["sync", "app:spawn:wasm", "tunnel"], resource: None, ttl_secs: 600, nonce: 8 },
        1_000,
    )
    .unwrap()
}

/// The identical chain built with ce-net-proto.
fn new_chain() -> Vec<new::SignedCapability> {
    let (root, mid, leaf) = (new_id(ROOT), new_id(MID), new_id(LEAF));
    let c0 = new::SignedCapability::issue(
        &root,
        mid.node_id(),
        s(&["exec", "sync", "app:spawn:*"]),
        new::Resource::AllOf(s(&["gpu", "linux"])),
        new_caveats(),
        7,
        None,
    );
    new::delegate::delegate(
        &[c0],
        &mid,
        leaf.node_id(),
        &new::delegate::Grant { abilities: &["sync", "app:spawn:wasm", "tunnel"], resource: None, ttl_secs: 600, nonce: 8 },
        1_000,
    )
    .unwrap()
}

#[test]
fn identities_and_signatures_are_identical() {
    for n in [ROOT, MID, LEAF, NODE] {
        assert_eq!(old_id(n).node_id(), new_id(n).node_id());
        assert_eq!(old_id(n).sign(b"hello"), new_id(n).sign(b"hello"));
        let sig = old_id(n).sign(b"x");
        assert!(new::identity::verify(&old_id(n).node_id(), b"x", &sig).is_ok());
        assert!(ce_identity::verify(&new_id(n).node_id(), b"x", &new_id(n).sign(b"x")).is_ok());
    }
}

#[test]
fn same_inputs_produce_identical_token_bytes() {
    let o = old_chain();
    let n = new_chain();
    assert_eq!(old::encode_chain(&o), new::encode_chain(&n), "token hex differs");
    for (a, b) in o.iter().zip(&n) {
        assert_eq!(old::cap_bytes(&a.cap), new::cap_bytes(&b.cap));
        assert_eq!(a.id(), b.id());
        assert_eq!(a.sig, b.sig);
    }
    // Revocations too.
    let ro = old::SignedRevocation::issue(&old_id(MID), 8, 1_600);
    let rn = new::SignedRevocation::issue(&new_id(MID), 8, 1_600);
    assert_eq!(ro.encode(), rn.encode());
    assert_eq!(old::revoke_bytes(&ro.revocation), new::revoke_bytes(&rn.revocation));
}

/// Run authorize in both implementations over the same token and assert identical outcomes.
fn both_authorize(token: &str, now: u64, requester: u8, action: &str, tags: &[&str], revoked: &[(u8, u64)]) -> Result<(), String> {
    let oc = old::decode_chain(token).unwrap();
    let nc = new::decode_chain(token).unwrap();
    let node = old_id(NODE).node_id();
    let roots = [old_id(ROOT).node_id()];
    let tags = s(tags);
    let req = old_id(requester).node_id();
    let rev: Vec<([u8; 32], u64)> = revoked.iter().map(|(i, n)| (old_id(*i).node_id(), *n)).collect();
    let is_rev = |i: &[u8; 32], n: u64| rev.iter().any(|(ri, rn)| ri == i && *rn == n);
    let ro = old::authorize(&node, &roots, &tags, now, &req, action, &oc, &is_rev);
    let rn = new::authorize(&node, &roots, &tags, now, &req, action, &nc, &is_rev);
    assert_eq!(ro, rn, "authorize diverged: now={now} action={action}");
    ro
}

#[test]
fn ce_cap_issued_and_delegated_verifies_with_ce_net_proto() {
    let token = old::encode_chain(&old_chain());
    let gl = &["gpu", "linux", "arm"];
    // Valid cases.
    assert!(both_authorize(&token, 1_200, LEAF, "sync", gl, &[]).is_ok());
    assert!(both_authorize(&token, 1_200, LEAF, "app:spawn:wasm", gl, &[]).is_ok());
    // Denied cases, identical reasons in both.
    assert!(both_authorize(&token, 1_200, LEAF, "exec", gl, &[]).unwrap_err().contains("does not grant"));
    assert!(both_authorize(&token, 1_200, LEAF, "tunnel", gl, &[]).unwrap_err().contains("does not grant"));
    assert!(both_authorize(&token, 1_601, LEAF, "sync", gl, &[]).unwrap_err().contains("expired"));
    assert!(both_authorize(&token, 50, LEAF, "sync", gl, &[]).unwrap_err().contains("not yet valid"));
    assert!(both_authorize(&token, 1_200, MID, "sync", gl, &[]).unwrap_err().contains("not held by"));
    assert!(both_authorize(&token, 1_200, LEAF, "sync", &["gpu"], &[]).unwrap_err().contains("does not match"));
    assert!(both_authorize(&token, 1_200, LEAF, "sync", gl, &[(MID, 8)]).unwrap_err().contains("link 1: capability revoked"));
    assert!(both_authorize(&token, 1_200, LEAF, "sync", gl, &[(ROOT, 7)]).unwrap_err().contains("link 0: capability revoked"));

    // Offline verify_chain against the root key.
    let chain = new::decode_chain(&token).unwrap();
    let v = new::verify_chain(&chain, &new_id(ROOT).node_id(), 1_200, &never).unwrap();
    assert_eq!(v.links, 2);
    assert_eq!(v.holder, new_id(LEAF).node_id());
    assert_eq!(v.abilities, s(&["sync", "app:spawn:wasm"]));
    assert_eq!(v.caveats.not_after, 1_600);
    assert!(new::verify_chain(&chain, &new_id(MID).node_id(), 1_200, &never).is_err());

    // ce-cap revocation -> ce-net-proto decodes and verifies it.
    let r = old::SignedRevocation::issue(&old_id(MID), 8, 1_600);
    let back = new::SignedRevocation::decode(&r.encode()).unwrap();
    assert!(back.verify_sig().is_ok());
    assert_eq!(back.revocation.nonce, 8);
    let rv = back.revocation.clone();
    let is_rev = |i: &[u8; 32], n: u64| *i == rv.issuer && n == rv.nonce;
    assert!(new::verify_chain(&chain, &new_id(ROOT).node_id(), 1_200, &is_rev).unwrap_err().contains("revoked"));
}

#[test]
fn ce_net_proto_issued_and_delegated_verifies_with_ce_cap() {
    let token = new::encode_chain(&new_chain());
    let oc = old::decode_chain(&token).unwrap();
    let node = old_id(NODE).node_id();
    let roots = [old_id(ROOT).node_id()];
    let tags = s(&["gpu", "linux"]);
    let leaf = old_id(LEAF).node_id();
    assert!(old::authorize(&node, &roots, &tags, 1_200, &leaf, "sync", &oc, &never).is_ok());
    assert!(old::authorize(&node, &roots, &tags, 1_200, &leaf, "exec", &oc, &never).is_err());
    for l in &oc {
        assert!(l.verify_sig().is_ok());
    }
    // A further delegation by ce-cap on top of a ce-net-proto chain, verified by ce-net-proto.
    let deeper = old::delegate::delegate(
        &oc,
        &old_id(LEAF),
        old_id(4).node_id(),
        &old::delegate::Grant { abilities: &["sync"], resource: Some(old::Resource::AllOf(s(&["gpu", "linux", "arm"]))), ttl_secs: 60, nonce: 1 },
        1_100,
    )
    .unwrap();
    let nd = new::decode_chain(&old::encode_chain(&deeper)).unwrap();
    let v = new::verify_chain(&nd, &new_id(ROOT).node_id(), 1_150, &never).unwrap();
    assert_eq!(v.links, 3);
    assert_eq!(v.caveats.not_after, 1_160);
    assert!(new::verify_chain(&nd, &new_id(ROOT).node_id(), 1_161, &never).unwrap_err().contains("expired"));

    // ce-net-proto revocation -> ce-cap decodes and verifies it.
    let r = new::SignedRevocation::issue(&new_id(MID), 8, 1_600);
    let back = old::SignedRevocation::decode(&r.encode()).unwrap();
    assert!(back.verify_sig().is_ok());
    let is_rev = |i: &[u8; 32], n: u64| *i == back.revocation.issuer && n == back.revocation.nonce;
    assert!(old::authorize(&node, &roots, &tags, 1_200, &leaf, "sync", &oc, &is_rev).unwrap_err().contains("revoked"));
}

#[test]
fn tampering_is_rejected_identically() {
    let mut n = new_chain();
    n[1].cap.abilities.push("exec".into()); // escalate after signing
    let token = new::encode_chain(&n);
    let e = both_authorize(&token, 1_200, LEAF, "exec", &["gpu", "linux"], &[]).unwrap_err();
    assert!(e.contains("link 1: invalid signature"), "{e}");
    // Truncated / garbage tokens fail to decode in both.
    let good = new::encode_chain(&new_chain());
    for bad in [&good[..good.len() - 2], "zz", ""] {
        assert_eq!(old::decode_chain(bad).is_err(), new::decode_chain(bad).is_err());
    }
}
