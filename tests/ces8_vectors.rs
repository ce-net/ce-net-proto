//! CES-8 chain vectors (docs/standards/CES-8-nesting.md section 5): chains that carry a
//! capability across one and two box boundaries, and chains that must be refused, each with the
//! rule that refuses it (`v3` when cap v3 itself already does).
//!
//! `tests/ces8/vectors.json` is GENERATED here from fixed seeds (Ed25519 is deterministic). Every
//! run regenerates it in memory, asserts it equals the committed file, then re-runs every vector
//! from the FILE alone. Regenerate after an intentional change with
//! `CE_NET_PROTO_REGEN=1 cargo test --test ces8_vectors`.
use std::collections::BTreeMap;

use ce_net_proto::cap::Caveats;
use ce_net_proto::ces8::{DEFAULT_NEST_MAX, authorize_inner, box_resource};
use ce_net_proto::program::ResourceV3;
use ce_net_proto::v3::mint::{Grant, attenuate, mint_root};
use ce_net_proto::v3::sign::Signer;
use ce_net_proto::v3::{AudienceSet, CapabilityV3, Delegate, Key, Link, TokenV3};
use serde_json::{Value, json};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/ces8/vectors.json");
const T: u64 = 2_000_000_000;
const NOW: u64 = T - 10_000;

const LEIF: u8 = 1;
const OUTER: u8 = 2; // nest.outer, the holder
const DOOR_A: u8 = 3; // inner door of box a7
const CALC_RUN: u8 = 4; // calc.run inside a7, itself a holder
const DOOR_B: u8 = 5; // inner door of box a7/b2
const CALC_EXEC: u8 = 6; // calc.exec inside a7/b2
const NOTES_APP: u8 = 7; // notes.app inside a7
const OTHER_DOOR: u8 = 8; // the inner door of another instance of the same holder

fn s(seed: u8) -> Signer {
    Signer::ed25519(&[seed; 32])
}
fn k(seed: u8) -> Key {
    s(seed).key()
}
fn raw(seed: u8) -> [u8; 32] {
    match k(seed) {
        Key::Ed25519(b) => b,
        Key::P256(_) => unreachable!(),
    }
}
fn strs(a: &[&str]) -> Vec<String> {
    a.iter().map(|x| x.to_string()).collect()
}
fn grant(to: u8, abilities: &[&str], resource: ResourceV3, not_after: u64, delegate: Option<(&[&str], u8)>, nonce: u64) -> Grant {
    Grant {
        audience: k(to),
        abilities: strs(abilities),
        resource,
        caveats: Caveats { not_after, ..Caveats::default() },
        ext: vec![],
        delegate: delegate.map(|(a, depth)| Delegate { abilities: strs(a), audience: AudienceSet::Any, depth }),
        nonce,
    }
}
fn resign(by: u8, l: &Link, f: impl FnOnce(&mut CapabilityV3)) -> Link {
    let Link::V3 { cap, .. } = l else { unreachable!() };
    let mut cap = cap.clone();
    f(&mut cap);
    Link::V3 { sig: s(by).sign(&cap), cap }
}
fn reparent(by: u8, l: &Link, parent: &Link) -> Link {
    let id = parent.id();
    resign(by, l, |c| c.parent = Some(id))
}

const ALL: &[&str] = &["notes.app:add", "notes.app:list", "calc.exec:eval", "net:connect"];

fn a7() -> Vec<String> {
    strs(&["a7"])
}
fn b2() -> Vec<String> {
    strs(&["a7", "b2"])
}

/// Leif -> nest.outer -> door a7 (the one boundary) -> notes.app.
fn one(root_after: u64, l1_after: u64) -> [Link; 3] {
    let l0 = mint_root(&s(LEIF), grant(OUTER, &[], ResourceV3::Any, root_after, Some((ALL, 4)), 1)).unwrap();
    let l1 = attenuate(&s(OUTER), &l0, grant(DOOR_A, &[], box_resource(&a7()), l1_after, Some((&["notes.app:add", "calc.exec:eval"], 3)), 2)).unwrap();
    let l2 = attenuate(&s(DOOR_A), &l1, grant(NOTES_APP, &["notes.app:add"], box_resource(&a7()), l1_after.saturating_sub(100).max(if l1_after == 0 { 0 } else { 1 }), None, 3)).unwrap();
    [l0, l1, l2]
}

/// Leif -> nest.outer -> door a7 -> calc.run -> door a7/b2 (the second boundary) -> calc.exec.
fn two() -> [Link; 5] {
    let [l0, l1, _] = one(T, T - 100);
    let l2 = attenuate(&s(DOOR_A), &l1, grant(CALC_RUN, &[], box_resource(&a7()), T - 200, Some((&["calc.exec:eval"], 2)), 4)).unwrap();
    let l3 = attenuate(&s(CALC_RUN), &l2, grant(DOOR_B, &[], box_resource(&b2()), T - 300, Some((&["calc.exec:eval"], 1)), 5)).unwrap();
    let l4 = attenuate(&s(DOOR_B), &l3, grant(CALC_EXEC, &["calc.exec:eval"], box_resource(&b2()), T - 400, None, 6)).unwrap();
    [l0, l1, l2, l3, l4]
}

fn hex_token(links: &[Link]) -> String {
    TokenV3 { links: links.to_vec(), programs: vec![] }.to_hex()
}

struct Case {
    name: &'static str,
    links: Vec<Link>,
    door: u8,
    path: Vec<String>,
    requester: u8,
    ability: &'static str,
    nest_max: usize,
    declared: BTreeMap<String, Vec<String>>,
    expect: &'static str,
}

fn cases() -> Vec<Case> {
    let none = BTreeMap::new;
    let c = |name, links: Vec<Link>, door, path, requester, ability, expect| Case {
        name,
        links,
        door,
        path,
        requester,
        ability,
        nest_max: DEFAULT_NEST_MAX,
        declared: none(),
        expect,
    };
    let [l0, l1, l2] = one(T, T - 100);
    let two = two();
    let mut v = vec![
        c("one-boundary-pass", vec![l0.clone(), l1.clone(), l2.clone()], DOOR_A, a7(), NOTES_APP, "notes.app:add", "pass"),
        c("two-boundaries-pass", two.to_vec(), DOOR_B, b2(), CALC_EXEC, "calc.exec:eval", "pass"),
    ];
    // a right wider below than the holder delegated (re-signed past the minter)
    let wide = resign(DOOR_A, &l2, |c| c.abilities = strs(&["notes.app:add", "notes.app:delete"]));
    v.push(c("wider-right-below", vec![l0.clone(), l1.clone(), wide], DOOR_A, a7(), NOTES_APP, "notes.app:add", "v3"));
    // the link into the box carries no box scope
    let l1_any = resign(OUTER, &l1, |c| c.resource = ResourceV3::Any);
    let l2_any = resign(DOOR_A, &reparent(DOOR_A, &l2, &l1_any), |c| c.resource = ResourceV3::Any);
    v.push(c("missing-box-scope", vec![l0.clone(), l1_any, l2_any], DOOR_A, a7(), NOTES_APP, "notes.app:add", "B2"));
    // the inner link outlives the holder's
    let late = resign(DOOR_A, &l2, |c| c.caveats.not_after = T + 100);
    v.push(c("later-expiry-below", vec![l0.clone(), l1.clone(), late], DOOR_A, a7(), NOTES_APP, "notes.app:add", "v3"));
    // depth not reduced at the boundary
    let deep = resign(OUTER, &l1, |c| c.delegate.as_mut().unwrap().depth = 4);
    let deep2 = reparent(DOOR_A, &l2, &deep);
    v.push(c("depth-not-reduced", vec![l0.clone(), deep, deep2], DOOR_A, a7(), NOTES_APP, "notes.app:add", "v3"));
    // the same token replayed at another instance of the box
    v.push(c("replayed-in-another-box", vec![l0.clone(), l1.clone(), l2.clone()], OTHER_DOOR, strs(&["a8"]), NOTES_APP, "notes.app:add", "v3"));
    // a link for the outer box used directly by a cell inside the inner box
    let l2_out = attenuate(&s(DOOR_A), &l1, grant(CALC_EXEC, &["calc.exec:eval"], box_resource(&a7()), T - 200, None, 9)).unwrap();
    v.push(c("outer-box-link-used-inside", vec![l0.clone(), l1.clone(), l2_out], DOOR_B, b2(), CALC_EXEC, "calc.exec:eval", "B2"));
    // one link jumps two boundaries
    let jump = resign(OUTER, &l1, |c| c.resource = box_resource(&b2()));
    let jump2 = resign(DOOR_A, &reparent(DOOR_A, &l2, &jump), |c| c.resource = box_resource(&b2()));
    v.push(c("two-boundaries-in-one-link", vec![l0.clone(), jump, jump2], DOOR_B, b2(), NOTES_APP, "notes.app:add", "B1"));
    // no expiry anywhere: v3 allows it, CES-8 does not at a boundary
    let open = one(0, 0);
    v.push(c("boundary-without-expiry", open.to_vec(), DOOR_A, a7(), NOTES_APP, "notes.app:add", "B3"));
    // nest_max 1 refuses the second box
    let mut shallow = c("deeper-than-nest-max", two.to_vec(), DOOR_B, b2(), CALC_EXEC, "calc.exec:eval", "B5");
    shallow.nest_max = 1;
    v.push(shallow);
    // the holder declared that box a7 needs only notes.app:add; the link also hands in calc.exec:eval
    let mut undeclared = c("right-not-declared-for-the-op", vec![l0.clone(), l1.clone(), l2.clone()], DOOR_A, a7(), NOTES_APP, "notes.app:add", "B6");
    undeclared.declared.insert("a7".into(), strs(&["notes.app:add"]));
    v.push(undeclared);
    let mut declared = c("rights-declared-for-the-op", vec![l0, l1, l2], DOOR_A, a7(), NOTES_APP, "notes.app:add", "pass");
    declared.declared.insert("a7".into(), strs(&["notes.app:add", "calc.exec:eval"]));
    v.push(declared);
    v
}

fn run(token: &str, door: [u8; 32], path: &[String], root: [u8; 32], requester: [u8; 32], ability: &str, nest_max: usize, declared: &BTreeMap<String, Vec<String>>) -> String {
    let t = TokenV3::from_hex(token).unwrap();
    let decl = |p: &[String]| declared.get(&p.join("/")).cloned();
    match authorize_inner(door, path, &[Key::Ed25519(root)], NOW, &Key::Ed25519(requester), ability, &t, nest_max, &decl) {
        Ok(_) => "pass".into(),
        Err(e) if e.starts_with("CES-8 ") => e[6..8].to_string(),
        Err(_) => "v3".into(),
    }
}

fn generate() -> Value {
    let vs: Vec<Value> = cases()
        .into_iter()
        .map(|c| {
            let token = hex_token(&c.links);
            let got = run(&token, raw(c.door), &c.path, raw(LEIF), raw(c.requester), c.ability, c.nest_max, &c.declared);
            assert_eq!(got, c.expect, "{}: generator disagrees with the stated outcome", c.name);
            json!({
                "name": c.name, "token": token, "root": hex::encode(raw(LEIF)), "now": NOW,
                "door_key": hex::encode(raw(c.door)), "door_path": c.path, "requester": hex::encode(raw(c.requester)),
                "ability": c.ability, "nest_max": c.nest_max, "declared": c.declared, "expect": c.expect,
            })
        })
        .collect();
    json!({ "standard": "CES-8 v0.1", "outcomes": "pass | v3 (cap v3 refuses) | B1..B6 (the CES-8 rule)", "vectors": vs })
}

fn b32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

#[test]
fn ces8_vectors() {
    let text = serde_json::to_string_pretty(&generate()).unwrap() + "\n";
    if std::env::var_os("CE_NET_PROTO_REGEN").is_some() || !std::path::Path::new(PATH).exists() {
        std::fs::create_dir_all(std::path::Path::new(PATH).parent().unwrap()).unwrap();
        std::fs::write(PATH, &text).unwrap();
    }
    let on_disk = std::fs::read_to_string(PATH).unwrap();
    assert!(on_disk == text, "tests/ces8/vectors.json is stale; rerun with CE_NET_PROTO_REGEN=1");
    let v: Value = serde_json::from_str(&on_disk).unwrap();
    let vs = v["vectors"].as_array().unwrap();
    assert!(vs.iter().filter(|x| x["expect"] == "pass").count() >= 2 && vs.len() >= 10);
    for x in vs {
        let path: Vec<String> = x["door_path"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect();
        let declared: BTreeMap<String, Vec<String>> = serde_json::from_value(x["declared"].clone()).unwrap();
        let got = run(x["token"].as_str().unwrap(), b32(&x["door_key"]), &path, b32(&x["root"]), b32(&x["requester"]), x["ability"].as_str().unwrap(), x["nest_max"].as_u64().unwrap() as usize, &declared);
        assert_eq!(got, x["expect"].as_str().unwrap(), "{}", x["name"]);
    }
}
