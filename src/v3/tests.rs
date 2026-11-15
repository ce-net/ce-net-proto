//! Round-trip and strict-decode tests of the v3 wire form.

use super::*;
use crate::cap::{Caveats, Resource, SignedCapability};
use crate::program::{EgressRule, HostPat, Limit, Proto, ResourceV3, Step};
use crate::Identity;
use sha2::Digest;

fn ed(seed: u8) -> Identity {
    Identity::from_secret_bytes(&[seed; 32])
}

fn p256_key() -> Key {
    let mut k = [0x11u8; 33];
    k[0] = 0x02;
    Key::P256(k)
}

fn program() -> Program {
    Program::new(vec![Step::Install { on: [7; 32], path: "/opt/x/run.py".into(), sha256: [9; 32], size: 10, mode: 0o755 }])
}

fn v3_cap(issuer: Key, audience: Key, parent: Option<Hash>) -> CapabilityV3 {
    CapabilityV3 {
        v: 3,
        issuer,
        audience,
        abilities: vec!["cell.install:install-file".into()],
        resource: ResourceV3::Nodes(vec![[7; 32], [8; 32]]),
        caveats: Caveats { not_after: 2_000_000_000, path_prefix: Some("/opt/x".into()), ..Caveats::default() },
        ext: vec![
            Caveat::Uses { max: 0xA5A5_A5A5, per: UsePer::Link },
            Caveat::Limits(vec![Limit { name: "net.egress.bytes_in".into(), max: 100 }, Limit { name: "proc.spawn.wall_s".into(), max: 600 }]),
            Caveat::Egress(vec![EgressRule { host: HostPat::Name("api.example.org".into()), ports: vec![443], proto: Proto::Tcp }]),
            Caveat::Programs(vec![program().id()]),
        ],
        delegate: Some(Delegate { abilities: vec!["net.egress:connect".into()], audience: AudienceSet::Any, depth: 2 }),
        nonce: 42,
        parent,
    }
}

/// A mixed token: a v1 root, a P-256-issued v3 link (low-S), a leaf signed P-256.
fn token() -> TokenV3 {
    let root = ed(1);
    let v1 = SignedCapability::issue(&root, ed(2).node_id(), vec!["*".into()], Resource::Any, Caveats::default(), 1, None);
    let mut c1 = v3_cap(Key::from_node_id(ed(2).node_id()), p256_key(), Some(v1.id()));
    c1.delegate = Some(Delegate {
        abilities: vec!["cell.install:install-file".into()],
        audience: AudienceSet::Keys(vec![Key::Ed25519(ed(3).node_id())]),
        depth: 1,
    });
    let l1 = Link::V3 { cap: c1.clone(), sig: Sig::Ed25519(ed(2).sign(&cap_bytes(&c1))) };
    let mut c2 = v3_cap(p256_key(), Key::Ed25519(ed(3).node_id()), Some(l1.id()));
    c2.delegate = None;
    let mut rs = [0x33u8; 64];
    rs[32] = 0x10; // low S
    let l2 = Link::V3 { cap: c2, sig: Sig::P256(rs) };
    TokenV3 { links: vec![Link::V1(v1), l1, l2], programs: vec![program()] }
}

fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).position(|w| w == needle).expect("needle in token")
}

#[test]
fn round_trip_bytes_and_hex() {
    let t = token();
    let b = t.encode();
    assert_eq!(&b[..4], b"CEC3");
    assert!(is_v3(&b));
    let back = TokenV3::decode(&b).expect("decodes");
    assert_eq!(back.encode(), b);
    assert_eq!(back.programs, t.programs);
    assert_eq!(back.links.len(), 3);
    match (&back.links[2], &t.links[2]) {
        (Link::V3 { cap: a, sig: sa }, Link::V3 { cap: b, sig: sb }) => {
            assert_eq!(a, b);
            assert_eq!(sa, sb);
        }
        _ => panic!("leaf must be V3"),
    }
    let hex = t.to_hex();
    assert_eq!(hex, hex.to_lowercase());
    assert_eq!(TokenV3::from_hex(&format!("  {hex}\n")).unwrap().encode(), b);
}

fn hex_refuses(s: &str) -> String {
    match TokenV3::from_hex(s) {
        Ok(_) => panic!("decoded a hex token that must be refused"),
        Err(e) => e.0,
    }
}

#[test]
fn hex_is_lowercase_and_bounded() {
    let hex = token().to_hex();
    assert!(hex_refuses(&hex.to_uppercase()).contains("lowercase"));
    assert!(hex_refuses(&hex.replacen("43", "4 3", 1)).contains("lowercase"), "inner whitespace");
    assert!(hex_refuses(&hex[..hex.len() - 1]).contains("hex"), "odd length");
    assert!(hex_refuses(&"0".repeat(2 * MAX_TOKEN + 2)).contains("too large"));
    assert!(refuses(&vec![0u8; MAX_TOKEN + 1]).contains("too large"));
}

/// The variant index one past the last of every v3 enum, and a tag that is neither 0 nor 1 on an
/// option, are decode errors (sections 1 and 13): nothing is skipped.
#[test]
fn every_enum_refuses_the_next_variant() {
    fn bad<T: serde::Serialize + serde::de::DeserializeOwned>(v: &T, next: u32) {
        let mut b = bincode::serialize(v).unwrap();
        assert!(strict().deserialize::<T>(&b).is_ok(), "the unmodified value decodes");
        b[..4].copy_from_slice(&next.to_le_bytes());
        assert!(strict().deserialize::<T>(&b).is_err(), "variant {next} must be refused");
        b[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(strict().deserialize::<T>(&b).is_err());
    }
    bad(&Key::Ed25519([1; 32]), 2);
    bad(&Sig::Ed25519([1; 64]), 3);
    bad(&AudienceSet::Any, 2);
    bad(&UsePer::Link, 2);
    bad(&Caveat::Uses { max: 1, per: UsePer::Link }, 4);
    bad(&ResourceV3::Any, 5);
    bad(&HostPat::Name("a.example".into()), 3);
    bad(&Proto::Tcp, 2);
    bad(&token().links[0], 2);
    // option<Delegate>: tag 2.
    let mut b = bincode::serialize(&Some(Delegate { abilities: vec!["a".into()], audience: AudienceSet::Any, depth: 1 })).unwrap();
    b[0] = 2;
    assert!(strict().deserialize::<Option<Delegate>>(&b).is_err());
    // a non-UTF-8 ability string.
    let mut b = bincode::serialize(&vec!["ab".to_string()]).unwrap();
    *b.last_mut().unwrap() = 0xff;
    assert!(strict().deserialize::<Vec<String>>(&b).is_err());
}

/// `P256_HALF_N` is floor(n / 2) of the curve order the `p256` crate uses; `s == n/2` is low,
/// `n/2 + 1` is not.
#[test]
fn low_s_bound_is_half_the_group_order() {
    use p256::elliptic_curve::{Curve, bigint::Encoding};
    let n = p256::NistP256::ORDER.to_be_bytes();
    let mut half = [0u8; 32];
    let mut carry = 0u8;
    for (h, b) in half.iter_mut().zip(n.iter()) {
        *h = (b >> 1) | (carry << 7);
        carry = b & 1;
    }
    assert_eq!(half, P256_HALF_N);
    let mut rs = [1u8; 64];
    rs[32..].copy_from_slice(&P256_HALF_N);
    assert!(Sig::P256(rs).canonical());
    rs[63] += 1;
    assert!(!Sig::P256(rs).canonical());
}

#[test]
fn signed_bytes_differ_per_link() {
    let a = v3_cap(p256_key(), p256_key(), None);
    let mut b = a.clone();
    b.nonce += 1;
    assert!(!cap_bytes(&a).is_empty());
    assert_ne!(cap_id(&a), cap_id(&b));
    let mut c = a.clone();
    c.delegate = None;
    assert_ne!(cap_id(&a), cap_id(&c), "the delegation right is signed");
}

#[test]
fn signed_bytes_are_domain_separated() {
    let c = v3_cap(p256_key(), p256_key(), None);
    let b = cap_bytes(&c);
    assert_eq!(&b[..17], b"\x09\0\0\0\0\0\0\0ce-cap-v3");
    assert_eq!(&b[17..], &bincode::serialize(&c).unwrap()[..]);
    assert_eq!(cap_id(&c), <[u8; 32]>::from(sha2::Sha256::digest(&b)));
    // fixed-size fields have no length prefix: tag(4) + 33 bytes, tag(4) + 64 bytes
    assert_eq!(bincode::serialize(&p256_key()).unwrap().len(), 37);
    assert_eq!(bincode::serialize(&Sig::P256([0; 64])).unwrap().len(), 68);
}

#[test]
fn v1_bytes_are_not_v3() {
    let v1 = SignedCapability::issue(&ed(1), ed(2).node_id(), vec!["exec".into()], Resource::Any, Caveats::default(), 1, None);
    let b = crate::encode_chain_bytes(&[v1]);
    assert!(!is_v3(&b));
    assert!(TokenV3::decode(&b).is_err());
}

fn refuses(b: &[u8]) -> String {
    match TokenV3::decode(b) {
        Ok(_) => panic!("decoded a token that must be refused"),
        Err(e) => e.0,
    }
}

#[test]
fn unknown_variants_are_refused() {
    let b = token().encode();
    // Link tag of links[0] sits after magic(4) + len(8).
    let mut x = b.clone();
    x[12] = 2;
    assert!(refuses(&x).contains("malformed"));
    // Caveat::Uses -> unknown caveat variant 4.
    let uses = bincode::serialize(&Caveat::Uses { max: 0xA5A5_A5A5, per: UsePer::Link }).unwrap();
    let at = find(&b, &uses);
    let mut x = b.clone();
    x[at] = 4;
    assert!(refuses(&x).contains("malformed"));
    // UsePer variant 2.
    let mut x = b.clone();
    x[at + 8] = 2;
    assert!(refuses(&x).contains("malformed"));
    // Sig variant 3 (the P-256 sig of the leaf).
    let mut rs = [0x33u8; 64];
    rs[32] = 0x10;
    let sig = bincode::serialize(&Sig::P256(rs)).unwrap();
    let at = find(&b, &sig);
    let mut x = b.clone();
    x[at] = 3;
    assert!(refuses(&x).contains("malformed"));
    // Key variant 2: the P-256 audience of links[1].
    let key = bincode::serialize(&p256_key()).unwrap();
    let at = find(&b, &key);
    let mut x = b.clone();
    x[at] = 2;
    assert!(refuses(&x).contains("malformed"));
}

#[test]
fn strictness() {
    let b = token().encode();
    let mut x = b.clone();
    x.push(0);
    assert!(refuses(&x).contains("malformed"), "trailing byte");
    assert!(refuses(&b[..b.len() - 1]).contains("malformed"), "truncated");
    // v != 3.
    let mut t = token();
    if let Link::V3 { cap, .. } = &mut t.links[1] {
        cap.v = 4;
    }
    assert!(refuses(&t.encode()).contains("link 1: not canonical"));
}

fn with_cap(f: impl FnOnce(&mut CapabilityV3)) -> String {
    let mut t = token();
    if let Link::V3 { cap, .. } = &mut t.links[2] {
        f(cap);
    }
    refuses(&t.encode())
}

#[test]
fn non_canonical_links_are_refused() {
    let nc = "link 2: not canonical";
    assert!(with_cap(|c| c.ext.swap(0, 1)).contains(nc));
    assert!(with_cap(|c| c.ext.push(Caveat::Uses { max: 1, per: UsePer::Link })).contains(nc));
    assert!(with_cap(|c| c.ext[0] = Caveat::Uses { max: 0, per: UsePer::Link }).contains(nc));
    assert!(with_cap(|c| c.ext[3] = Caveat::Programs(vec![])).contains(nc));
    assert!(with_cap(|c| c.ext[3] = Caveat::Programs(vec![[2; 32], [1; 32]])).contains(nc));
    assert!(with_cap(|c| c.resource = ResourceV3::Nodes(vec![[8; 32], [7; 32]])).contains(nc));
    assert!(with_cap(|c| c.resource = ResourceV3::Any).contains(nc), "counted link needs finite resource");
    assert!(with_cap(|c| c.caveats.not_after = 0).contains(nc), "counted link needs not_after");
    assert!(with_cap(|c| c.delegate = Some(Delegate { abilities: vec!["a".into()], audience: AudienceSet::Any, depth: 0 })).contains(nc));
    assert!(with_cap(|c| c.delegate = Some(Delegate { abilities: vec![], audience: AudienceSet::Any, depth: 1 })).contains(nc));
    assert!(with_cap(|c| c.delegate = Some(Delegate { abilities: vec!["a".into()], audience: AudienceSet::Keys(vec![]), depth: 1 })).contains(nc));
    assert!(with_cap(|c| {
        c.ext[0] = Caveat::Uses { max: 1, per: UsePer::Action };
        c.abilities = vec!["cell.install:*".into()];
    })
    .contains(nc));
    assert!(with_cap(|c| c.issuer = Key::P256([0x04; 33])).contains(nc));
    let mut t = token();
    if let Link::V3 { sig, .. } = &mut t.links[2] {
        *sig = Sig::P256([0xff; 64]); // high S
    }
    assert!(refuses(&t.encode()).contains(nc));
}

#[test]
fn size_bounds() {
    let mut t = token();
    t.programs = vec![program(); MAX_PROGRAMS + 1];
    assert!(refuses(&t.encode()).contains("programs"));
    let mut t = token();
    let leaf = t.links[0].clone();
    t.links = vec![leaf; MAX_LINKS + 1];
    assert!(refuses(&t.encode()).contains("links"));
    // The ability bound is per list, token-wide: a V1 head link is held to it too.
    let mut t = token();
    if let Link::V1(s) = &mut t.links[0] {
        s.cap.abilities = vec!["exec".into(); MAX_ABILITIES + 1];
    }
    assert!(refuses(&t.encode()).contains("link 0: not canonical"));
    assert!(with_cap(|c| c.abilities = vec!["exec".into(); MAX_ABILITIES + 1]).contains("link 2: not canonical"));
}
