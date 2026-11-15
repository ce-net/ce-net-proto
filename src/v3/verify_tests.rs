//! Verifier tests: a good chain, then one refusal per check of sections 5.1 and 5.2, with links
//! signed directly (not through the minter) so the verifier alone has to catch them.

use std::cell::RefCell;

use super::mint::{Grant, mint_root};
use super::sign::Signer;
use super::types::AudienceSet;
use super::verify::{Charge, Node, OwnerRoot, Request, Roots, authorize_v3, verify_chain_v3};
use super::*;
use crate::Identity;
use crate::cap::{Caveats, Resource, SignedCapability};
use crate::program::{ResourceV3, Step};

const T: u64 = 2_000_000_000;
const NOW: u64 = T - 1000;
const HERE: [u8; 32] = [1; 32];

fn ed(seed: u8) -> Signer {
    Signer::ed25519(&[seed; 32])
}

fn p256(seed: u8) -> Signer {
    Signer::p256(&[seed; 32]).unwrap()
}

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn root_grant(audience: Key) -> Grant {
    Grant {
        audience,
        abilities: vec![],
        resource: ResourceV3::Nodes(vec![HERE, [2; 32]]),
        caveats: Caveats { not_after: T, path_prefix: Some("/opt/x".into()), ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 5, per: UsePer::Link }],
        delegate: Some(Delegate { abilities: strs(&["cell.install:*", "talk:send"]), audience: AudienceSet::Any, depth: 3 }),
        nonce: 1,
    }
}

/// The leaf statement under `parent`, issued by `issuer` to `audience`: no wider than the root.
fn leaf_cap(issuer: Key, audience: Key, parent: &Link) -> CapabilityV3 {
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

fn signed(s: &Signer, cap: CapabilityV3) -> Link {
    let sig = s.sign(&cap);
    Link::V3 { cap, sig }
}

/// root ed(1) -> p256(2) -> ed(3), the leaf changed by `f` and signed by p256(2) as is.
fn chain(f: impl FnOnce(&mut CapabilityV3)) -> TokenV3 {
    let root = mint_root(&ed(1), root_grant(p256(2).key())).unwrap();
    let mut cap = leaf_cap(p256(2).key(), ed(3).key(), &root);
    f(&mut cap);
    TokenV3 { links: vec![root.clone(), signed(&p256(2), cap)], programs: vec![] }
}

fn roots_keys() -> Vec<Key> {
    vec![ed(1).key()]
}

fn never(_: &Key, _: u64) -> bool {
    false
}

fn verify(t: &TokenV3) -> Result<verify::VerifiedV3, String> {
    verify_chain_v3(t, &Roots { keys: &roots_keys(), owners: &[] }, NOW, &never)
}

fn refusal(f: impl FnOnce(&mut CapabilityV3)) -> String {
    verify(&chain(f)).unwrap_err()
}

#[test]
fn good_chain_verifies() {
    let t = chain(|_| {});
    let v = verify(&t).unwrap();
    assert_eq!(v.links, 2);
    assert_eq!(v.holder, ed(3).key());
    assert_eq!(v.resource, ResourceV3::Node(HERE));
    assert_eq!(v.ids, t.links.iter().map(Link::id).collect::<Vec<_>>());
    assert_eq!(v.counted.len(), 2);
    assert_eq!(v.counted[0].link, t.links[0].id());
    assert_eq!(v.counted[1].uses, Some(Caveat::Uses { max: 2, per: UsePer::Link }));
    // the same chain from its hex
    assert!(verify(&TokenV3::from_hex(&t.to_hex()).unwrap()).is_ok());
}

#[test]
fn root_must_be_accepted_and_parentless() {
    let t = chain(|_| {});
    let other = [ed(9).key()];
    assert_eq!(
        verify_chain_v3(&t, &Roots { keys: &other, owners: &[] }, NOW, &never).unwrap_err(),
        "capability chain does not root at an accepted authority"
    );
    let mut g = root_grant(p256(2).key());
    g.nonce = 7;
    let mut cap = leaf_cap(ed(1).key(), p256(2).key(), &mint_root(&ed(1), g).unwrap());
    cap.parent = Some([0; 32]);
    let t = TokenV3 { links: vec![signed(&ed(1), cap)], programs: vec![] };
    assert_eq!(verify(&t).unwrap_err(), "root capability must not name a parent");
    assert_eq!(verify(&TokenV3 { links: vec![], programs: vec![] }).unwrap_err(), "no capability presented");
}

#[test]
fn signatures() {
    let mut t = chain(|_| {});
    if let Link::V3 { cap, .. } = &mut t.links[1] {
        cap.nonce = 99;
    }
    assert_eq!(verify(&t).unwrap_err(), "link 1: invalid signature");
    let mut t = chain(|_| {});
    if let Link::V3 { sig, .. } = &mut t.links[1] {
        *sig = Sig::Ed25519([0; 64]);
    }
    assert_eq!(verify(&t).unwrap_err(), "link 1: signature type does not match the issuer key");
}

#[test]
fn time_window_and_revocation() {
    assert_eq!(refusal(|c| c.caveats.not_before = NOW + 1), "link 1: capability not yet valid");
    let t = chain(|_| {});
    let roots = roots_keys();
    let r = Roots { keys: &roots, owners: &[] };
    assert_eq!(verify_chain_v3(&t, &r, T - 5, &never).unwrap_err(), "link 1: capability has expired");
    let leaf_issuer = p256(2).key();
    let revoked = |k: &Key, n: u64| *k == leaf_issuer && n == 2;
    assert_eq!(verify_chain_v3(&t, &r, NOW, &revoked).unwrap_err(), "link 1: capability revoked");
    let root_revoked = |k: &Key, n: u64| *k == ed(1).key() && n == 1;
    assert_eq!(verify_chain_v3(&t, &r, NOW, &root_revoked).unwrap_err(), "link 0: capability revoked");
}

#[test]
fn continuity() {
    // issued by someone other than the parent's audience (and signed by them)
    let root = mint_root(&ed(1), root_grant(p256(2).key())).unwrap();
    let cap = leaf_cap(ed(5).key(), ed(3).key(), &root);
    let t = TokenV3 { links: vec![root, signed(&ed(5), cap)], programs: vec![] };
    assert_eq!(verify(&t).unwrap_err(), "link 1: issuer is not the parent's audience");
    assert_eq!(refusal(|c| c.parent = Some([7; 32])), "link 1: parent hash does not match the chain");
    assert_eq!(refusal(|c| c.parent = None), "link 1: parent hash does not match the chain");
}

#[test]
fn narrowing_at_every_link() {
    assert_eq!(refusal(|c| c.abilities.push("proc.spawn:run".into())), "link 1: abilities exceed the parent's grant");
    assert_eq!(refusal(|c| c.resource = ResourceV3::Nodes(vec![HERE, [3; 32]])), "link 1: resource is broader than the parent");
    assert_eq!(refusal(|c| c.resource = ResourceV3::Any), "link 1: not canonical (a counted link must name a finite resource (Node or Nodes))");
    assert_eq!(refusal(|c| c.caveats.not_after = T + 1), "link 1: caveats are broader than the parent");
    assert_eq!(refusal(|c| c.caveats.path_prefix = Some("/opt".into())), "link 1: caveats are broader than the parent");
    assert_eq!(refusal(|c| c.ext = vec![Caveat::Uses { max: 6, per: UsePer::Link }]), "link 1: caveats are broader than the parent");
    assert_eq!(refusal(|c| c.ext.clear()), "link 1: caveats are broader than the parent");
    let d = |abilities: &[&str], audience, depth| Some(Delegate { abilities: strs(abilities), audience, depth });
    assert_eq!(refusal(|c| c.delegate = d(&["talk:send"], AudienceSet::Any, 3)), "link 1: delegation depth exceeds the parent");
    assert_eq!(refusal(|c| c.delegate = d(&["proc.spawn:run"], AudienceSet::Any, 2)), "link 1: grantable abilities exceed the parent");
    assert!(verify(&chain(|c| c.delegate = d(&["talk:send"], AudienceSet::Keys(vec![ed(4).key()]), 2))).is_ok());
}

#[test]
fn a_final_or_closed_parent_stops_the_chain() {
    let mut g = root_grant(p256(2).key());
    g.delegate = Some(Delegate { abilities: strs(&["talk:send"]), audience: AudienceSet::Keys(vec![ed(4).key()]), depth: 1 });
    let root = mint_root(&ed(1), g.clone()).unwrap();
    let mut cap = leaf_cap(p256(2).key(), ed(3).key(), &root);
    cap.abilities = strs(&["talk:send"]);
    let t = TokenV3 { links: vec![root, signed(&p256(2), cap.clone())], programs: vec![] };
    assert_eq!(verify(&t).unwrap_err(), "link 1: audience is outside the parent's grant");
    g.delegate = None;
    let root = mint_root(&ed(1), g).unwrap();
    cap.parent = Some(root.id());
    let t = TokenV3 { links: vec![root, signed(&p256(2), cap)], programs: vec![] };
    assert_eq!(verify(&t).unwrap_err(), "link 1: the parent may not delegate");
}

fn v1_root() -> SignedCapability {
    let caveats = Caveats { not_after: T, path_prefix: Some("/opt/x".into()), ..Caveats::default() };
    let abilities = strs(&["talk:send", "cell.install:install-file"]);
    SignedCapability::issue(&Identity::from_secret_bytes(&[1; 32]), p256_as_v1(), abilities, Resource::Any, caveats, 11, None)
}

/// v1 audiences are Ed25519; the v3 child below is issued by ed(6).
fn p256_as_v1() -> crate::NodeId {
    match ed(6).key() {
        Key::Ed25519(k) => k,
        _ => unreachable!(),
    }
}

#[test]
fn v1_links_only_at_the_head() {
    let head = Link::V1(v1_root());
    let mut cap = leaf_cap(ed(6).key(), ed(3).key(), &head);
    cap.caveats.path_prefix = Some("/opt/x".into());
    let leaf = signed(&ed(6), cap);
    let t = TokenV3 { links: vec![head.clone(), leaf.clone()], programs: vec![] };
    let v = verify(&t).unwrap();
    assert_eq!(v.ids[0], head.id());
    // a v1 link after a v3 one
    let t = TokenV3 { links: vec![head.clone(), leaf, head.clone()], programs: vec![] };
    assert_eq!(verify(&t).unwrap_err(), "link 2: a v1 link cannot follow a v3 link");
    // an owner key heads only v3 chains
    let owner = [OwnerRoot { key: ed(1).key(), rp_id: None, not_before: 0, not_after: 0 }];
    let t = TokenV3 { links: vec![head], programs: vec![] };
    assert_eq!(
        verify_chain_v3(&t, &Roots { keys: &[], owners: &owner }, NOW, &never).unwrap_err(),
        "capability chain does not root at an accepted authority"
    );
}

#[test]
fn owner_roots_and_webauthn() {
    use p256::ecdsa::signature::Signer as _;
    let sk = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
    let key = p256(9).key();
    let mut cap = match mint_root(&p256(9), root_grant(p256(2).key())).unwrap() {
        Link::V3 { cap, .. } => cap,
        _ => unreachable!(),
    };
    cap.nonce = 3;
    let assert_with = |challenge: &str, flags: u8| {
        let client_data = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://ce-net.com"}}"#).into_bytes();
        let mut auth_data = sha2::Sha256::digest(b"ce-net.com").to_vec();
        auth_data.extend([flags, 0, 0, 0, 1]);
        let mut msg = auth_data.clone();
        msg.extend(sha2::Sha256::digest(&client_data));
        let s: p256::ecdsa::Signature = sk.sign(&msg);
        TokenV3 { links: vec![Link::V3 { cap: cap.clone(), sig: Sig::WebAuthn { auth_data, client_data, sig: s.to_der().as_bytes().to_vec() } }], programs: vec![] }
    };
    use sha2::Digest;
    let good = webauthn::b64url(&cap_id(&cap));
    let owners = |rp: Option<&str>, not_after| [OwnerRoot { key, rp_id: rp.map(str::to_string), not_before: 0, not_after }];
    let ok = owners(Some("ce-net.com"), 0);
    let r = Roots { keys: &[], owners: &ok };
    assert!(verify_chain_v3(&assert_with(&good, 0x05), &r, NOW, &never).is_ok());
    assert_eq!(verify_chain_v3(&assert_with("AAAA", 0x05), &r, NOW, &never).unwrap_err(), "link 0: invalid signature");
    assert_eq!(verify_chain_v3(&assert_with(&good, 0x01), &r, NOW, &never).unwrap_err(), "link 0: invalid signature");
    let no_rp = owners(None, 0);
    let r = Roots { keys: &[], owners: &no_rp };
    assert_eq!(verify_chain_v3(&assert_with(&good, 0x05), &r, NOW, &never).unwrap_err(), "link 0: invalid signature");
    let expired = owners(Some("ce-net.com"), NOW - 1);
    let r = Roots { keys: &[], owners: &expired };
    assert_eq!(
        verify_chain_v3(&assert_with(&good, 0x05), &r, NOW, &never).unwrap_err(),
        "capability chain does not root at an accepted authority"
    );
}

// ---- authorize_v3 ----

fn node() -> Node<'static> {
    Node { id: HERE, tags: &[], host: Some("pi") }
}

/// `burns` records each charged action; a burn refuses once it holds `USED_UP` entries.
const USED_UP: usize = 3;

fn auth(t: &TokenV3, requester: Key, req: Request, burns: &RefCell<Vec<String>>) -> Result<verify::VerifiedV3, String> {
    let roots = roots_keys();
    let mut burn = |c: &Charge| {
        assert_eq!(c.counted.len(), 2, "every counted link is charged");
        if burns.borrow().len() >= USED_UP {
            return Err("capability used up".to_string());
        }
        burns.borrow_mut().push(c.action.clone());
        Ok(())
    };
    authorize_v3(&node(), &Roots { keys: &roots, owners: &[] }, NOW, &requester, &req, t, &never, &mut burn)
}

#[test]
fn authorize_a_call() {
    let burns = RefCell::new(vec![]);
    let t = chain(|_| {});
    assert!(auth(&t, ed(3).key(), Request::Call("talk:send"), &burns).is_ok());
    assert_eq!(*burns.borrow(), vec!["talk:send".to_string()]);
    assert_eq!(auth(&t, ed(4).key(), Request::Call("talk:send"), &burns).unwrap_err(), "leaf capability is not held by the request sender");
    assert_eq!(auth(&t, ed(3).key(), Request::Call("talk:read"), &burns).unwrap_err(), "capability does not grant 'talk:read'");
    assert_eq!(burns.borrow().len(), 1, "no burn on a refusal");
    // the leaf's delegate abilities never authorize a call
    let t = chain(|c| {
        c.abilities = vec![];
        c.delegate = Some(Delegate { abilities: strs(&["talk:send"]), audience: AudienceSet::Any, depth: 1 });
    });
    assert_eq!(auth(&t, ed(3).key(), Request::Call("talk:send"), &burns).unwrap_err(), "capability does not grant 'talk:send'");
    // the leaf names another node
    let t = chain(|c| c.resource = ResourceV3::Node([2; 32]));
    assert_eq!(auth(&t, ed(3).key(), Request::Call("talk:send"), &burns).unwrap_err(), "link 1: resource does not match this node");
    // counters: the burn's refusal is the answer
    let t = chain(|_| {});
    assert!(auth(&t, ed(3).key(), Request::Call("talk:send"), &burns).is_ok());
    assert!(auth(&t, ed(3).key(), Request::Call("talk:send"), &burns).is_ok());
    assert_eq!(auth(&t, ed(3).key(), Request::Call("talk:send"), &burns).unwrap_err(), "capability used up");
}

fn inst(path: &str, size: u64, mode: u32) -> Step {
    Step::Install { on: HERE, path: path.into(), sha256: [9; 32], size, mode }
}

fn exec(program: Hash, step: &Step) -> Request<'_> {
    Request::Execute { program, run: 0, step: 0, req: step }
}

fn install() -> Step {
    inst("/opt/x/app/run.py", 10, 0o755)
}

#[test]
fn authorize_a_program_step() {
    let burns = RefCell::new(vec![]);
    let p = Program::new(vec![install()]);
    let id = p.id();
    let mut t = chain(|c| c.ext.push(Caveat::Programs(vec![id])));
    t.programs = vec![p.clone()];
    assert!(auth(&t, ed(3).key(), exec(id, &install()), &burns).is_ok());
    assert_eq!(*burns.borrow(), vec!["cell.install:install-file".to_string()]);
    assert_eq!(auth(&t, ed(3).key(), Request::Call("talk:send"), &burns).unwrap_err(), "capability is bound to a program");
    let other = Program::new(vec![inst("/opt/x/app/run.py", 11, 0o755)]);
    t.programs.push(other.clone());
    assert_eq!(auth(&t, ed(3).key(), exec(other.id(), &other.steps[0]), &burns).unwrap_err(), "program is not the one granted");
    let wrong = inst("/opt/x/app/run.py", 10, 0o777);
    assert_eq!(auth(&t, ed(3).key(), exec(id, &wrong), &burns).unwrap_err(), "the request is not program step 0");
    t.programs.clear();
    assert!(auth(&t, ed(3).key(), exec(id, &install()), &burns).unwrap_err().contains("is not in the token"));
    // unbound chain: a program still executes, typed the same way; outside path_prefix it is refused
    let mut t = chain(|_| {});
    let bad = Program::new(vec![inst("/opt/x/other", 10, 0o755)]);
    t.programs = vec![p.clone(), bad.clone()];
    assert!(auth(&t, ed(3).key(), exec(id, &install()), &burns).is_ok());
    assert!(auth(&t, ed(3).key(), exec(bad.id(), &bad.steps[0]), &burns).unwrap_err().contains("is outside /opt/x/app"));
}
