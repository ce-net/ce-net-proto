//! Conditions at verify and at use (section 4.1): Leif's three rules, each met and each refused;
//! a child that drops or loosens an inherited condition; the binding of the proofs to one request.
//! Links are signed directly, never through the minter, so the verifier alone has to catch them.

use std::cell::RefCell;

use sha2::{Digest, Sha256};

use super::authorize_tests::node;
use super::sign::Signer;
use super::verify::{Charge, OwnerRoot, Presented, Request, Roots, VerifiedV3, authorize_use_v3, authorize_v3, verify_chain_v3};
use super::verify_roots_tests::assertion;
use super::verify_tests::*;
use super::*;
use crate::program::Hash;

const BODY: Hash = [7; 32];
const BROADER: &str = "link 1: caveats are broader than the parent";

/// "have you read the wechat chat before writing": the wechat cell attests it, at most 10 min ago.
fn read_wechat(fresh: Option<u64>) -> Requirement {
    let claim = Claim::ReadThrough { source: "wechat".into(), thread: "family".into(), upto_msg: None };
    Requirement { witness: Party::Cell("wechat.read".into()), claim, fresh_within_s: fresh }
}

fn requires(fresh: Option<u64>) -> Caveat {
    Caveat::Requires(vec![read_wechat(fresh)])
}

/// "always verify the auth code and talk to this all through the same systems agent": ed(30)
/// co-signs every use and is the broker.
fn guardian() -> Vec<Caveat> {
    vec![Caveat::CoSign(vec![CoSigner { by: ed(30).key(), per: CoSignPer::Use }]), Caveat::Via(vec![Party::Key(ed(30).key())])]
}

/// "always talk to this agent if you want to access the 3d printer".
fn printer() -> Caveat {
    Caveat::Via(vec![Party::Cell("printer3d.gate".into())])
}

/// The keys this node trusts per cell api.
fn cell_keys(api: &str) -> Vec<Key> {
    match api {
        "wechat.read" => vec![ed(20).key()],
        "printer3d.gate" => vec![ed(21).key(), p256(22).key()],
        _ => vec![],
    }
}

/// root ed(1) -> p256(2) -> ed(3), the root carrying `conds`, the leaf `leaf` (after its `Uses`).
fn conditioned(conds: Vec<Caveat>, leaf: Vec<Caveat>) -> TokenV3 {
    chain2(|g| g.ext.extend(conds), |c| c.ext.extend(leaf))
}

fn both(conds: Vec<Caveat>) -> TokenV3 {
    conditioned(conds.clone(), conds)
}

fn request(t: &TokenV3) -> UseRequest {
    UseRequest { leaf: t.links[t.links.len() - 1].id(), node: HERE, requester: ed(3).key(), action: "talk:send".into(), body: BODY, at: NOW, nonce: 1 }
}

fn attested(witness: &Signer, subject: Key, thread: &str, at: u64) -> Proof {
    let claim = Claim::ReadThrough { source: "wechat".into(), thread: thread.into(), upto_msg: Some("m42".into()) };
    let body = AttestationBody { witness: witness.key(), subject, claim, at };
    Proof::Attested(Attestation { sig: witness.sign_bytes(&attest_bytes(&body)), body })
}

fn cosigned(s: &Signer, r: &UseRequest) -> Proof {
    Proof::CoSigned { by: s.key(), sig: s.sign_bytes(&cosign_bytes(r)) }
}

fn brokered(s: &Signer, r: &UseRequest) -> Proof {
    Proof::Brokered { broker: s.key(), sig: s.sign_bytes(&via_bytes(r)) }
}

/// What a node remembers between uses: request ids executed, and how often it burned.
#[derive(Default)]
struct Log {
    seen: RefCell<Vec<Hash>>,
    burns: RefCell<u32>,
}

impl Log {
    fn used(&self, t: &TokenV3, r: &UseRequest, proofs: &[Proof], roots: &Roots) -> Result<VerifiedV3, String> {
        let mut first_use = |id: &Hash, forget_after: u64| {
            assert_eq!(forget_after, r.at + 300);
            if self.seen.borrow().contains(id) {
                return Err("request replayed".to_string());
            }
            self.seen.borrow_mut().push(*id);
            Ok(())
        };
        let mut burn = |_: &Charge| {
            *self.burns.borrow_mut() += 1;
            Ok(())
        };
        let mut p = Presented { request: r, proofs, body: BODY, cell_keys: &cell_keys, first_use: &mut first_use };
        authorize_use_v3(&node(), roots, NOW, &ed(3).key(), &Request::Call("talk:send"), t, &mut p, &never, &mut burn)
    }

    fn nothing_recorded(&self) -> bool {
        self.seen.borrow().is_empty() && *self.burns.borrow() == 0
    }
}

/// One use at a fresh node with ed(1) as the root.
fn used(t: &TokenV3, r: &UseRequest, proofs: &[Proof]) -> Result<(), String> {
    let log = Log::default();
    let out = log.used(t, r, proofs, &Roots { keys: &[ed(1).key()], owners: &[] }).map(|_| ());
    assert_eq!(out.is_err(), log.nothing_recorded(), "a refused use records nothing, an accepted one both");
    out
}

#[test]
fn requires_read_the_wechat_chat_first() {
    let t = both(vec![requires(Some(600))]);
    let r = request(&t);
    let unmet = "condition not met: requires";
    assert_eq!(used(&t, &r, &[attested(&ed(20), ed(3).key(), "family", NOW - 100)]), Ok(()));
    assert_eq!(used(&t, &r, &[attested(&ed(20), ed(3).key(), "family", NOW - 600)]), Ok(()));
    assert_eq!(used(&t, &r, &[]).unwrap_err(), unmet);
    assert_eq!(used(&t, &r, &[attested(&ed(20), ed(3).key(), "family", NOW - 601)]).unwrap_err(), unmet, "read too long ago");
    assert_eq!(used(&t, &r, &[attested(&ed(20), ed(3).key(), "family", NOW + 1)]).unwrap_err(), unmet, "dated in the future");
    assert_eq!(used(&t, &r, &[attested(&ed(20), ed(4).key(), "family", NOW)]).unwrap_err(), unmet, "someone else read it");
    assert_eq!(used(&t, &r, &[attested(&ed(20), ed(3).key(), "work", NOW)]).unwrap_err(), unmet, "another thread");
    assert_eq!(used(&t, &r, &[attested(&ed(3), ed(3).key(), "family", NOW)]).unwrap_err(), unmet, "the requester vouching for itself");
    assert_eq!(used(&t, &r, &[attested(&ed(21), ed(3).key(), "family", NOW)]).unwrap_err(), unmet, "a key of another cell");
    // a forged attestation: the body names the witness, another key signed
    let Proof::Attested(mut a) = attested(&ed(20), ed(3).key(), "family", NOW - 601) else { unreachable!() };
    a.body.at = NOW;
    assert_eq!(used(&t, &r, &[Proof::Attested(a)]).unwrap_err(), unmet);
    // one good proof among useless ones is enough; a fact is not a read
    let fact = AttestationBody { witness: ed(20).key(), subject: ed(3).key(), claim: Claim::Fact { name: "wechat.read".into(), value: vec![1] }, at: NOW };
    let fact = Proof::Attested(Attestation { sig: ed(20).sign_bytes(&attest_bytes(&fact)), body: fact });
    assert_eq!(used(&t, &r, &[fact.clone()]).unwrap_err(), unmet);
    assert_eq!(used(&t, &r, &[fact, attested(&ed(9), ed(3).key(), "family", NOW), attested(&ed(20), ed(3).key(), "family", NOW)]), Ok(()));
    // no proofs handed over at all: the plain entry point refuses the chain
    let mut burn = |_: &Charge| -> Result<(), String> { panic!("no burn") };
    let roots = Roots { keys: &[ed(1).key()], owners: &[] };
    assert_eq!(authorize_v3(&node(), &roots, NOW, &ed(3).key(), &Request::Call("talk:send"), &t, &never, &mut burn).unwrap_err(), unmet);
}

#[test]
fn cosign_and_via_the_same_guardian_agent() {
    let t = both(guardian());
    let r = request(&t);
    let g = ed(30);
    assert_eq!(used(&t, &r, &[cosigned(&g, &r), brokered(&g, &r)]), Ok(()));
    assert_eq!(used(&t, &r, &[]).unwrap_err(), "condition not met: cosign");
    assert_eq!(used(&t, &r, &[cosigned(&g, &r)]).unwrap_err(), "condition not met: via");
    assert_eq!(used(&t, &r, &[brokered(&g, &r)]).unwrap_err(), "condition not met: cosign");
    // another agent is not "the same systems agent", for either half
    assert_eq!(used(&t, &r, &[cosigned(&ed(31), &r), brokered(&g, &r)]).unwrap_err(), "condition not met: cosign");
    assert_eq!(used(&t, &r, &[cosigned(&g, &r), brokered(&ed(31), &r)]).unwrap_err(), "condition not met: via");
    assert_eq!(used(&t, &r, &[cosigned(&ed(3), &r), brokered(&ed(3), &r)]).unwrap_err(), "condition not met: cosign", "the requester itself");
    // one signature does not serve as the other (separate domains)
    let Proof::CoSigned { sig, .. } = cosigned(&g, &r) else { unreachable!() };
    let as_broker = Proof::Brokered { broker: g.key(), sig: sig.clone() };
    assert_eq!(used(&t, &r, &[cosigned(&g, &r), as_broker]).unwrap_err(), "condition not met: via");
    let named = Proof::CoSigned { by: g.key(), sig: ed(31).sign_bytes(&cosign_bytes(&r)) };
    assert_eq!(used(&t, &r, &[named, brokered(&g, &r)]).unwrap_err(), "condition not met: cosign");
    // the guardian approved another request: any field that differs voids its signatures
    for other in [
        UseRequest { body: [8; 32], ..r.clone() },
        UseRequest { nonce: 2, ..r.clone() },
        UseRequest { at: NOW - 1, ..r.clone() },
        UseRequest { action: "talk:read".into(), ..r.clone() },
        UseRequest { node: THERE, ..r.clone() },
        UseRequest { leaf: t.links[0].id(), ..r.clone() },
        UseRequest { requester: ed(4).key(), ..r.clone() },
    ] {
        assert_eq!(used(&t, &r, &[cosigned(&g, &other), brokered(&g, &other)]).unwrap_err(), "condition not met: cosign");
    }
}

#[test]
fn via_the_3d_printer_agent() {
    let t = both(vec![printer()]);
    let r = request(&t);
    assert_eq!(used(&t, &r, &[brokered(&ed(21), &r)]), Ok(()));
    assert_eq!(used(&t, &r, &[brokered(&p256(22), &r)]), Ok(()));
    let unmet = "condition not met: via";
    assert_eq!(used(&t, &r, &[]).unwrap_err(), unmet);
    assert_eq!(used(&t, &r, &[brokered(&ed(20), &r)]).unwrap_err(), unmet, "the wechat cell is not the printer agent");
    assert_eq!(used(&t, &r, &[cosigned(&ed(21), &r)]).unwrap_err(), unmet, "a co-signature is not a broker approval");
    // a cell api this node holds no key for cannot be met by anyone
    let t = both(vec![Caveat::Via(vec![Party::Cell("printer9.gate".into())])]);
    let r = request(&t);
    assert_eq!(used(&t, &r, &[brokered(&ed(21), &r)]).unwrap_err(), unmet);
}

#[test]
fn a_child_cannot_drop_or_loosen_an_inherited_condition() {
    let all = || [vec![requires(Some(600))], guardian()].concat();
    let under = |leaf: Vec<Caveat>| verify(&conditioned(all(), leaf)).map(|v| v.conditions);
    assert_eq!(under(all()), Ok([all(), all()].concat()));
    assert_eq!(under(vec![]).unwrap_err(), BROADER);
    // each of the three dropped alone
    for i in 0..3 {
        let mut ext = all();
        ext.remove(i);
        assert_eq!(under(ext).unwrap_err(), BROADER);
    }
    // loosened or swapped: staler, any age, another thread, another witness, another agent
    let swap = |i: usize, c: Caveat| {
        let mut ext = all();
        ext[i] = c;
        under(ext)
    };
    assert_eq!(swap(0, requires(Some(601))).unwrap_err(), BROADER);
    assert_eq!(swap(0, requires(None)).unwrap_err(), BROADER);
    let mut other = read_wechat(Some(600));
    other.claim = Claim::ReadThrough { source: "wechat".into(), thread: "work".into(), upto_msg: None };
    assert_eq!(swap(0, Caveat::Requires(vec![other])).unwrap_err(), BROADER);
    let mut other = read_wechat(Some(600));
    other.witness = Party::Key(ed(3).key());
    assert_eq!(swap(0, Caveat::Requires(vec![other])).unwrap_err(), BROADER);
    assert_eq!(swap(1, Caveat::CoSign(vec![CoSigner { by: ed(3).key(), per: CoSignPer::Use }])).unwrap_err(), BROADER);
    assert_eq!(swap(2, Caveat::Via(vec![Party::Key(ed(3).key())])).unwrap_err(), BROADER);
    assert_eq!(swap(2, printer()).unwrap_err(), BROADER);
    // tightening and adding are fine, and the use must then meet the added condition too
    assert!(swap(0, requires(Some(60))).is_ok());
    let t = conditioned(vec![requires(Some(600))], vec![requires(Some(600)), printer()]);
    assert_eq!(verify(&t).map(|v| v.conditions.len()), Ok(3));
    let r = request(&t);
    let read = attested(&ed(20), ed(3).key(), "family", NOW);
    assert_eq!(used(&t, &r, &[read.clone()]).unwrap_err(), "condition not met: via");
    assert_eq!(used(&t, &r, &[read, brokered(&ed(21), &r)]), Ok(()));
    // dropped two links down: the middle link added the printer rule, the link below omits it
    let mid = chain2(|g| g.ext.push(requires(Some(600))), |c| {
        c.ext.extend([requires(Some(600)), printer()]);
        c.abilities = strs(&["talk:send"]);
        c.delegate = delegate(&["talk:send"], types::AudienceSet::Any, 1);
    });
    let below = |ext: Vec<Caveat>| {
        let mut cap = leaf_cap(ed(3).key(), ed(4).key(), &mid.links[1]);
        cap.abilities = strs(&["talk:send"]);
        cap.nonce = 3;
        cap.ext.extend(ext);
        verify(&token(vec![mid.links[0].clone(), mid.links[1].clone(), signed(&ed(3), cap)])).map(|v| v.conditions.len())
    };
    assert_eq!(below(vec![requires(Some(600)), printer()]), Ok(5));
    assert_eq!(below(vec![requires(Some(600))]).unwrap_err(), "link 2: caveats are broader than the parent");
    assert_eq!(below(vec![printer()]).unwrap_err(), "link 2: caveats are broader than the parent");
}

#[test]
fn the_use_request_is_this_use_once() {
    let t = both(guardian());
    let r = request(&t);
    let g = ed(30);
    let signed_off = |r: &UseRequest| [cosigned(&g, r), brokered(&g, r)];
    // a request the guardian did sign, but which is not the call arriving here
    let wrong = |other: UseRequest| used(&t, &other, &signed_off(&other)).unwrap_err();
    assert_eq!(wrong(UseRequest { leaf: t.links[0].id(), ..r.clone() }), "use request is not this use (leaf)");
    assert_eq!(wrong(UseRequest { node: THERE, ..r.clone() }), "use request is not this use (node)");
    assert_eq!(wrong(UseRequest { requester: ed(4).key(), ..r.clone() }), "use request is not this use (requester)");
    assert_eq!(wrong(UseRequest { action: "talk:*".into(), ..r.clone() }), "use request is not this use (action)");
    assert_eq!(wrong(UseRequest { body: [8; 32], ..r.clone() }), "use request is not this use (body)");
    assert_eq!(wrong(UseRequest { action: String::new(), ..r.clone() }), "use request is malformed (use request names no action)");
    let window = "use request is outside the 300 s window";
    assert_eq!(wrong(UseRequest { at: NOW - 301, ..r.clone() }), window);
    assert_eq!(wrong(UseRequest { at: NOW + 301, ..r.clone() }), window);
    let edge = UseRequest { at: NOW - 300, ..r.clone() };
    assert_eq!(used(&t, &edge, &signed_off(&edge)), Ok(()));
    // replay: the same signed request a second time; a new nonce needs a new signature
    let log = Log::default();
    let roots = Roots { keys: &[ed(1).key()], owners: &[] };
    assert!(log.used(&t, &r, &signed_off(&r), &roots).is_ok());
    assert_eq!(log.used(&t, &r, &signed_off(&r), &roots).unwrap_err(), "request replayed");
    let again = UseRequest { nonce: 2, ..r.clone() };
    assert_eq!(log.used(&t, &again, &signed_off(&r), &roots).unwrap_err(), "condition not met: cosign");
    assert!(log.used(&t, &again, &signed_off(&again), &roots).is_ok());
    assert_eq!((log.seen.borrow().len(), *log.burns.borrow()), (2, 2));
    // malformed proofs are refused outright; the request is recorded even with no condition
    let Proof::Attested(mut a) = attested(&ed(20), ed(3).key(), "family", NOW) else { unreachable!() };
    a.body.claim = Claim::ReadThrough { source: "wechat".into(), thread: "family".into(), upto_msg: None };
    assert!(used(&t, &r, &[Proof::Attested(a)]).unwrap_err().starts_with("proof 0: not canonical"));
    assert_eq!(used(&t, &r, &vec![cosigned(&g, &r); 65]).unwrap_err(), "more than 64 proofs");
    let plain = chain(|_| {});
    let log = Log::default();
    assert!(log.used(&plain, &request(&plain), &[], &roots).is_ok());
    assert_eq!(log.used(&plain, &request(&plain), &[], &roots).unwrap_err(), "request replayed");
}

#[test]
fn a_passkey_co_signs_through_its_owner_entry() {
    let passkey = p256(9).key();
    let t = both(vec![Caveat::CoSign(vec![CoSigner { by: passkey, per: CoSignPer::Use }])]);
    let r = request(&t);
    let challenge: Hash = Sha256::digest(cosign_bytes(&r)).into();
    let proof = |challenge: &Hash, flags| [Proof::CoSigned { by: passkey, sig: assertion(9, challenge, "ce-net.com", flags) }];
    let owners = [OwnerRoot { key: passkey, rp_id: Some("ce-net.com".into()), not_before: 0, not_after: 0 }];
    let with = |proofs: &[Proof], owners: &[OwnerRoot]| Log::default().used(&t, &r, proofs, &Roots { keys: &[ed(1).key()], owners }).map(|_| ());
    assert_eq!(with(&proof(&challenge, 0x05), &owners), Ok(()));
    let unmet = "condition not met: cosign";
    assert_eq!(with(&proof(&challenge, 0x05), &[]).unwrap_err(), unmet, "no rp id recorded for the key");
    assert_eq!(with(&proof(&challenge, 0x01), &owners).unwrap_err(), unmet, "no user verification");
    let via: Hash = Sha256::digest(via_bytes(&r)).into();
    assert_eq!(with(&proof(&via, 0x05), &owners).unwrap_err(), unmet, "an assertion over the broker bytes");
    assert_eq!(with(&proof(&t.links[1].id(), 0x05), &owners).unwrap_err(), unmet, "an assertion over the link");
    // offline, the chain verifies and reports the condition; that authorizes nothing
    let v = verify_chain_v3(&t, &Roots { keys: &[ed(1).key()], owners: &[] }, NOW, &never).unwrap();
    assert_eq!(v.conditions.len(), 2);
}
