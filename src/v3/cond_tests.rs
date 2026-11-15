//! Conditions (section 4.1): wire round-trip, strict decode, canonical form, signed bytes.

use super::*;
use crate::cap::Caveats;
use crate::program::ResourceV3;
use bincode::Options;

fn key(b: u8) -> Key {
    Key::Ed25519([b; 32])
}

fn p256(b: u8) -> Key {
    let mut k = [b; 33];
    k[0] = 0x03;
    Key::P256(k)
}

fn wechat(upto: Option<&str>) -> Claim {
    Claim::ReadThrough { source: "wechat".into(), thread: "family".into(), upto_msg: upto.map(String::from) }
}

/// "have you read the wechat chat before writing".
fn requires() -> Caveat {
    Caveat::Requires(vec![Requirement { witness: Party::Cell("wechat.read".into()), claim: wechat(None), fresh_within_s: Some(600) }])
}

/// "always verify the auth code ... through the same systems agent".
fn cosign() -> Caveat {
    Caveat::CoSign(vec![CoSigner { by: p256(0x21), per: CoSignPer::Use }])
}

/// "always talk to this agent if you want to access the 3d printer".
fn via() -> Caveat {
    Caveat::Via(vec![Party::Key(key(0x31))])
}

fn cap(ext: Vec<Caveat>) -> CapabilityV3 {
    CapabilityV3 {
        v: 3,
        issuer: key(1),
        audience: key(2),
        abilities: vec!["printer3d:print".into()],
        resource: ResourceV3::Any,
        caveats: Caveats::default(),
        ext,
        delegate: None,
        nonce: 7,
        parent: None,
    }
}

fn token(ext: Vec<Caveat>) -> TokenV3 {
    TokenV3 { links: vec![Link::V3 { cap: cap(ext), sig: Sig::Ed25519([9; 64]) }], programs: vec![] }
}

fn refused(ext: Vec<Caveat>) -> String {
    match TokenV3::decode(&token(ext).encode()) {
        Ok(_) => panic!("decoded a token that must be refused"),
        Err(e) => e.0,
    }
}

fn request() -> UseRequest {
    UseRequest { leaf: [4; 32], node: [5; 32], requester: key(2), action: "printer3d:print".into(), body: [6; 32], at: 1_800_000_000, nonce: 1 }
}

fn attestation() -> Attestation {
    Attestation {
        body: AttestationBody { witness: key(0x41), subject: key(2), claim: wechat(Some("msg-812")), at: 1_800_000_000 },
        sig: Sig::Ed25519([8; 64]),
    }
}

#[test]
fn conditions_round_trip_in_a_token() {
    let t = token(vec![requires(), cosign(), via()]);
    let b = t.encode();
    let back = TokenV3::decode(&b).expect("canonical conditions decode");
    assert_eq!(back.encode(), b);
    let Link::V3 { cap: c, .. } = &back.links[0] else { panic!("v3 link") };
    assert_eq!(c.ext, vec![requires(), cosign(), via()]);
    assert_eq!(c.ext.iter().map(Caveat::index).collect::<Vec<_>>(), [4, 5, 6]);
    assert!(c.ext.iter().all(Caveat::is_condition));
    assert!(!Caveat::Uses { max: 1, per: UsePer::Link }.is_condition() && !Caveat::Programs(vec![[1; 32]]).is_condition());
    assert_eq!(TokenV3::from_hex(&t.to_hex()).unwrap().encode(), b);
}

/// The wire bytes are the spec's grammar read left to right (u32 tags, u64 lengths, LE).
#[test]
fn wire_layout_is_the_grammar() {
    let mut want = vec![6, 0, 0, 0]; // Caveat::Via
    want.extend(1u64.to_le_bytes()); // one broker
    want.extend([0, 0, 0, 0]); // Party::Key
    want.extend([0, 0, 0, 0]); // Key::Ed25519
    want.extend([0x31; 32]);
    assert_eq!(bincode::serialize(&via()).unwrap(), want);

    let mut want = vec![5, 0, 0, 0]; // Caveat::CoSign
    want.extend(1u64.to_le_bytes());
    want.extend([1, 0, 0, 0, 0x03]); // Key::P256, parity byte
    want.extend([0x21; 32]);
    want.extend([0, 0, 0, 0]); // CoSignPer::Use
    assert_eq!(bincode::serialize(&cosign()).unwrap(), want);

    let mut want = vec![4, 0, 0, 0]; // Caveat::Requires
    want.extend(1u64.to_le_bytes());
    want.extend([1, 0, 0, 0]); // Party::Cell
    want.extend(11u64.to_le_bytes());
    want.extend(b"wechat.read");
    want.extend([0, 0, 0, 0]); // Claim::ReadThrough
    want.extend(6u64.to_le_bytes());
    want.extend(b"wechat");
    want.extend(6u64.to_le_bytes());
    want.extend(b"family");
    want.push(0); // upto_msg: None
    want.push(1); // fresh_within_s: Some
    want.extend(600u64.to_le_bytes());
    assert_eq!(bincode::serialize(&requires()).unwrap(), want);
}

#[test]
fn every_condition_enum_refuses_the_next_variant() {
    fn bad<T: serde::Serialize + serde::de::DeserializeOwned>(v: &T, next: u32) {
        let mut b = bincode::serialize(v).unwrap();
        assert!(strict().deserialize::<T>(&b).is_ok(), "the unmodified value decodes");
        b[..4].copy_from_slice(&next.to_le_bytes());
        assert!(strict().deserialize::<T>(&b).is_err(), "variant {next} must be refused");
        b[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(strict().deserialize::<T>(&b).is_err());
    }
    bad(&requires(), 7);
    bad(&cosign(), 7);
    bad(&via(), 7);
    bad(&Party::Key(key(1)), 2);
    bad(&wechat(None), 2);
    bad(&CoSignPer::Use, 1);
    bad(&Proof::CoSigned { by: key(1), sig: Sig::Ed25519([1; 64]) }, 3);
}

/// An unknown variant nested inside a condition refuses the whole token.
#[test]
fn unknown_nested_variants_refuse_the_token() {
    let b = token(vec![requires(), cosign(), via()]).encode();
    let at = |needle: &[u8]| b.windows(needle.len()).position(|w| w == needle).expect("needle in token");
    let flip = |i: usize, v: u8| {
        let mut x = b.clone();
        x[i] = v;
        TokenV3::decode(&x).expect_err("must be refused").0
    };
    let req = at(&bincode::serialize(&requires()).unwrap());
    assert!(flip(req, 7).contains("malformed"), "caveat variant 7");
    assert!(flip(req + 12, 2).contains("malformed"), "Party variant 2");
    assert!(flip(req + 12 + 4 + 8 + 11, 2).contains("malformed"), "Claim variant 2");
    let per = at(&bincode::serialize(&cosign()).unwrap()) + 12 + 4 + 33;
    assert!(flip(per, 1).contains("malformed"), "CoSignPer variant 1");
    let opt = at(b"family") + 6;
    assert!(flip(opt, 2).contains("malformed"), "option tag 2");
}

#[test]
fn non_canonical_conditions_are_refused() {
    let nc = "link 0: not canonical";
    let req = |witness: Party, claim: Claim, fresh: Option<u64>| Requirement { witness, claim, fresh_within_s: fresh };
    let w = || Party::Cell("wechat.read".into());
    // order of variants, one per variant
    assert!(refused(vec![via(), cosign()]).contains(nc));
    assert!(refused(vec![via(), via()]).contains(nc));
    // empty lists
    assert!(refused(vec![Caveat::Requires(vec![])]).contains(nc));
    assert!(refused(vec![Caveat::CoSign(vec![])]).contains(nc));
    assert!(refused(vec![Caveat::Via(vec![])]).contains(nc));
    // unsorted, duplicate
    assert!(refused(vec![Caveat::Via(vec![Party::Key(key(2)), Party::Key(key(1))])]).contains(nc));
    assert!(refused(vec![Caveat::Via(vec![Party::Key(key(1)), Party::Key(key(1))])]).contains(nc));
    let two = |a: u8, b: u8| vec![CoSigner { by: key(a), per: CoSignPer::Use }, CoSigner { by: key(b), per: CoSignPer::Use }];
    assert!(refused(vec![Caveat::CoSign(two(2, 1))]).contains(nc));
    assert!(TokenV3::decode(&token(vec![Caveat::CoSign(two(1, 2))]).encode()).is_ok());
    // one entry per (witness, claim): two freshness values for one claim
    assert!(refused(vec![Caveat::Requires(vec![req(w(), wechat(None), Some(60)), req(w(), wechat(None), Some(600))])]).contains(nc));
    // freshness 0, empty and oversized strings, malformed keys
    assert!(refused(vec![Caveat::Requires(vec![req(w(), wechat(None), Some(0))])]).contains(nc));
    assert!(refused(vec![Caveat::Requires(vec![req(Party::Cell(String::new()), wechat(None), None)])]).contains(nc));
    assert!(refused(vec![Caveat::Requires(vec![req(w(), wechat(Some("")), None)])]).contains(nc));
    let long = Claim::Fact { name: "a.b".into(), value: vec![0; MAX_COND_STR + 1] };
    assert!(refused(vec![Caveat::Requires(vec![req(w(), long, None)])]).contains(nc));
    assert!(refused(vec![Caveat::Via(vec![Party::Cell("x".repeat(MAX_COND_STR + 1))])]).contains(nc));
    assert!(refused(vec![Caveat::Via(vec![Party::Key(Key::P256([4; 33]))])]).contains(nc));
    assert!(refused(vec![Caveat::CoSign(vec![CoSigner { by: Key::P256([4; 33]), per: CoSignPer::Use }])]).contains(nc));
    // the list bound
    let many: Vec<Party> = (0..=MAX_CONDITIONS as u8).map(|i| Party::Key(key(i))).collect();
    assert!(refused(vec![Caveat::Via(many.clone())]).contains(nc));
    assert!(TokenV3::decode(&token(vec![Caveat::Via(many[..MAX_CONDITIONS].to_vec())]).encode()).is_ok());
}

/// A condition is signed: changing or dropping one changes the link's id and signed bytes.
#[test]
fn conditions_are_covered_by_the_signature() {
    let full = cap(vec![requires(), cosign(), via()]);
    for drop in 0..3 {
        let mut c = full.clone();
        c.ext.remove(drop);
        assert_ne!(cap_id(&c), cap_id(&full));
    }
    let mut c = full.clone();
    c.ext[0] = Caveat::Requires(vec![Requirement { witness: Party::Cell("wechat.read".into()), claim: wechat(None), fresh_within_s: Some(601) }]);
    assert_ne!(cap_bytes(&c), cap_bytes(&full));
}

#[test]
fn claims_are_proved_only_by_the_same_statement() {
    assert!(wechat(None).proved_by(&wechat(Some("msg-812"))));
    assert!(wechat(Some("msg-812")).proved_by(&wechat(Some("msg-812"))));
    assert!(!wechat(Some("msg-812")).proved_by(&wechat(Some("msg-811"))));
    assert!(!wechat(None).proved_by(&wechat(None)), "an attestation names its message");
    let other = Claim::ReadThrough { source: "wechat".into(), thread: "work".into(), upto_msg: Some("msg-812".into()) };
    assert!(!wechat(None).proved_by(&other));
    let mail = Claim::ReadThrough { source: "mail".into(), thread: "family".into(), upto_msg: Some("msg-812".into()) };
    assert!(!wechat(None).proved_by(&mail));
    let fact = |v: u8| Claim::Fact { name: "door.code_ok".into(), value: vec![v] };
    assert!(fact(1).proved_by(&fact(1)));
    assert!(!fact(1).proved_by(&fact(2)));
    assert!(!fact(1).proved_by(&wechat(Some("msg-812"))));
    assert!(!wechat(None).proved_by(&fact(1)));
}

/// One request, four byte strings: none is a prefix-compatible stand-in for another or for a link.
#[test]
fn signed_bytes_are_domain_separated() {
    let r = request();
    let all = [cosign_bytes(&r), via_bytes(&r), attest_bytes(&attestation().body), cap_bytes(&cap(vec![]))];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert_eq!(&cosign_bytes(&r)[..24], [&16u64.to_le_bytes()[..], b"ce-cap-v3-cosign"].concat());
    assert_eq!(&via_bytes(&r)[..21], [&13u64.to_le_bytes()[..], b"ce-cap-v3-via"].concat());
    assert_eq!(&attest_bytes(&attestation().body)[..24], [&16u64.to_le_bytes()[..], b"ce-cap-v3-attest"].concat());
    assert_eq!(cosign_bytes(&r)[24..], bincode::serialize(&r).unwrap()[..]);
    // every field of the request is under the signature and in the id
    let edits: [fn(&mut UseRequest); 7] = [
        |r| r.leaf[0] ^= 1,
        |r| r.node[0] ^= 1,
        |r| r.requester = Key::Ed25519([3; 32]),
        |r| r.action.push('x'),
        |r| r.body[0] ^= 1,
        |r| r.at += 1,
        |r| r.nonce += 1,
    ];
    for edit in edits {
        let mut x = r.clone();
        edit(&mut x);
        assert_ne!(cosign_bytes(&x), cosign_bytes(&r));
        assert_ne!(via_bytes(&x), via_bytes(&r));
        assert_ne!(request_id(&x), request_id(&r));
    }
    assert!(r.check().is_ok());
    assert!(UseRequest { action: String::new(), ..r.clone() }.check().is_err());
    assert!(UseRequest { requester: Key::P256([4; 33]), ..r }.check().is_err());
}

#[test]
fn proofs_round_trip_and_decode_strictly() {
    let ps = vec![
        Proof::Attested(attestation()),
        Proof::CoSigned { by: p256(0x21), sig: Sig::Ed25519([1; 64]) },
        Proof::Brokered { broker: key(0x31), sig: Sig::Ed25519([2; 64]) },
    ];
    let b = encode_proofs(&ps);
    assert_eq!(decode_proofs(&b).unwrap(), ps);
    assert_eq!(decode_proofs(&encode_proofs(&[])).unwrap(), vec![]);
    let err = |b: &[u8]| decode_proofs(b).expect_err("must be refused").0;
    let mut x = b.clone();
    x.push(0);
    assert!(err(&x).contains("malformed"), "trailing byte");
    assert!(err(&b[..b.len() - 1]).contains("malformed"), "truncated");
    let mut x = b.clone();
    x[8] = 3; // Proof variant 3
    assert!(err(&x).contains("malformed"));
    // an attestation that names no message, a malformed key, a high-S signature
    let mut a = attestation();
    a.body.claim = wechat(None);
    assert!(err(&encode_proofs(&[Proof::Attested(a)])).contains("proof 0: not canonical"));
    let mut a = attestation();
    a.body.subject = Key::P256([4; 33]);
    assert!(err(&encode_proofs(&[ps[1].clone(), Proof::Attested(a)])).contains("proof 1: not canonical"));
    assert!(err(&encode_proofs(&[Proof::Brokered { broker: key(1), sig: Sig::P256([0xff; 64]) }])).contains("not canonical"));
    assert!(err(&encode_proofs(&vec![ps[2].clone(); MAX_PROOFS + 1])).contains("more than"));
    assert!(decode_proofs(&encode_proofs(&vec![ps[2].clone(); MAX_PROOFS])).is_ok());
}
