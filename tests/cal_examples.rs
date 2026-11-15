//! The CAL examples (`examples/*.cal`), end to end:
//!
//! - each compiles with the examples' ref book, and its `explain` text equals the checked-in
//!   `examples/<name>.explain.txt` (regenerate after an intentional change with
//!   `CE_CAL_REGEN=1 cargo test --test cal_examples`);
//! - the Raspberry Pi, the long chain and the feed-cell install compile to exactly the links of
//!   the conformance vectors (`tests/v3/cases.rs`), and signed with the same test keys give the
//!   same token bytes;
//! - every example decompiles and compiles back to the same links, with and without the names;
//! - `check` allows what each rule allows and refuses, with the reason, what it forbids.

#[path = "v3/cases.rs"]
#[allow(dead_code)]
mod cases;

use ce_net_proto::cal::check::{Action, CheckRequest};
use ce_net_proto::cal::{self, Compiled, Labels, NoRefs, RefBook, Resolver};
use ce_net_proto::program::Program;
use ce_net_proto::v3::{Key, Link, Proof, TokenV3, UseRequest, cosign_bytes, via_bytes};
use sha2::{Digest, Sha256};

use cases::*;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples");
const EXAMPLES: &[&str] = &["raspberry-pi", "long-chain", "wechat-read", "printer-broker", "door-guard", "feed-cell-install"];

fn book() -> RefBook {
    RefBook::from_json(&std::fs::read_to_string(format!("{DIR}/cal.refs.json")).unwrap()).unwrap()
}

fn compile(name: &str, r: &dyn Resolver) -> Compiled {
    let src = std::fs::read_to_string(format!("{DIR}/{name}.cal")).unwrap();
    compile_src(&src, r).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn compile_src(src: &str, r: &dyn Resolver) -> Result<Compiled, cal::CalError> {
    let f = cal::parse(src)?;
    let mut next = || -> u64 { panic!("every example names its nonces") };
    cal::compile(&f, r, &mut cal::Options { now: T, nonce: &mut next, lenient: false })
}

/// The test key of a principal of the examples' book.
fn seed_of(k: &Key) -> u8 {
    KEYS.iter().map(|(_, s)| *s).find(|s| &key(*s) == k).expect("a test key")
}

fn sign_all(c: &Compiled) -> TokenV3 {
    let mut d = c.draft();
    for (cap, _) in d.links.clone() {
        d.sign(&signer(seed_of(&cap.issuer)));
    }
    d.token().unwrap()
}

fn labels(c: &Compiled, r: &dyn Resolver) -> Labels {
    let mut l = c.labels.clone();
    l.learn(&c.links, &c.programs, r);
    l
}

#[test]
fn every_example_explains_as_checked_in() {
    let b = book();
    let regen = std::env::var("CE_CAL_REGEN").is_ok();
    for name in EXAMPLES {
        let c = compile(name, &b);
        let text = cal::explain(&c.links, &c.programs, &labels(&c, &b));
        let path = format!("{DIR}/{name}.explain.txt");
        if regen {
            std::fs::write(&path, &text).unwrap();
        }
        let want = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{path} missing: run with CE_CAL_REGEN=1"));
        assert_eq!(text, want, "{name}: explain output changed; regenerate with CE_CAL_REGEN=1 if intended");
    }
}

#[test]
fn every_example_is_formatted() {
    for name in EXAMPLES {
        let src = std::fs::read_to_string(format!("{DIR}/{name}.cal")).unwrap();
        let f = cal::parse(&src).unwrap();
        let printed = cal::print::print(&f);
        // the canonical layout drops comments; it must parse to the same tree
        assert_eq!(cal::print::print(&cal::parse(&printed).unwrap()), printed, "{name}");
        let c1 = compile_src(&src, &book()).unwrap();
        let c2 = compile_src(&printed, &book()).unwrap();
        assert_eq!(c1.links, c2.links, "{name}");
    }
}

fn caps(links: &[&Link]) -> Vec<ce_net_proto::v3::CapabilityV3> {
    links.iter().map(|l| match l {
        Link::V3 { cap, .. } => cap.clone(),
        Link::V1(_) => unreachable!(),
    }).collect()
}

#[test]
fn the_pi_the_long_chain_and_the_feed_install_are_the_vectors() {
    let b = book();
    let pi = compile("raspberry-pi", &b);
    let (l0, l1) = pi_links();
    assert_eq!(pi.links, caps(&[&l0, &l1]));
    assert_eq!(pi.programs, vec![pi_program()]);
    assert_eq!(sign_all(&pi).encode(), pi_token(), "the signed CAL token is the vector's token, byte for byte");

    let long = compile("long-chain", &b);
    let [a, bb, c] = long_links();
    assert_eq!(long.links, caps(&[&a, &bb, &c]));
    assert_eq!(long.programs, vec![job_program()]);
    assert_eq!(sign_all(&long).encode(), token(&[&a, &bb, &c], &[&job_program()]));

    let feed = compile("feed-cell-install", &b);
    let root = first_root();
    let (leaf, p) = first_leaf(&root, "feed.view", AT_DESK, 102);
    assert_eq!(feed.links, caps(&[&root, &leaf]));
    assert_eq!(feed.programs, vec![p]);
}

#[test]
fn every_example_decompiles_to_cal_that_compiles_back() {
    let b = book();
    for name in EXAMPLES {
        let c = compile(name, &b);
        let t = sign_all(&c);
        // with names: refs and pins side by side, compiled again through the ref book
        let named = cal::decompile(&t, &labels(&c, &b)).unwrap();
        let again = compile_src(&named, &b).unwrap_or_else(|e| panic!("{name}: {e}\n{named}"));
        assert_eq!(again.links, c.links, "{name}\n{named}");
        assert_eq!(again.programs, c.programs, "{name}");
        // without any names: only pinned forms, compiled with no resolver at all
        let bare = cal::decompile(&t, &Labels::default()).unwrap();
        let again = compile_src(&bare, &NoRefs).unwrap_or_else(|e| panic!("{name}: {e}\n{bare}"));
        assert_eq!(again.links, c.links, "{name}\n{bare}");
        assert_eq!(again.programs, c.programs, "{name}");
        assert!(!bare.contains("person:") && !bare.contains("agent:"), "{bare}");
    }
}

struct Ask<'a> {
    t: &'a TokenV3,
    node: u8,
    host: &'static str,
    who: u8,
    action: Action,
    presented: Option<(UseRequest, Vec<Proof>, Vec<u8>)>,
    content: Option<Vec<u8>>,
}

fn ask(a: Ask, l: &Labels) -> cal::Verdict {
    let b = book();
    let cell = |api: &str| b.cell_keys(api);
    let req = CheckRequest {
        node: node(a.node),
        host: Some(a.host.to_string()),
        tags: vec![],
        requester: key(a.who),
        action: a.action,
        now: T + 60,
        roots: b.roots(),
        cell_keys: &cell,
        presented: a.presented,
        content: a.content,
    };
    cal::check(a.t, &req, l)
}

fn step0(p: &Program) -> Action {
    Action::Step { program: p.id(), run: 1, step: 0 }
}

fn refused_with(v: &cal::Verdict, reason: &str, why: &str) {
    assert!(!v.allowed, "allowed, expected {reason}");
    assert!(v.reason.as_deref().unwrap_or("").starts_with(reason), "{}", v.text());
    assert!(v.why.iter().any(|w| w.contains(why)), "why lacks {why:?}:\n{}", v.text());
}

#[test]
fn check_the_pi() {
    let b = book();
    let c = compile("raspberry-pi", &b);
    let t = sign_all(&c);
    let l = labels(&c, &b);
    let p = &c.programs[0];
    let base = || Ask { t: &t, node: PI, host: "pi-01", who: AGENT_B, action: step0(p), presented: None, content: Some(PI_SCRIPT.to_vec()) };
    let ok = ask(base(), &l);
    assert!(ok.allowed, "{}", ok.text());
    assert!(ok.text().contains("agent:agent-b"), "{}", ok.text());
    refused_with(&ask(Ask { content: Some(b"import os; os.system('rm -rf /')\n".to_vec()), ..base() }, &l), "content hash mismatch: the bytes are sha256:", "differ from the pinned hash");
    refused_with(&ask(Ask { who: WIN, ..base() }, &l), "leaf capability is not held by the request sender", "The chain is held by agent:agent-b");
    refused_with(&ask(Ask { node: BOX, host: "box-1", ..base() }, &l), "link 0: resource does not match this node", "Link 0 applies only on node:pi-01");
    refused_with(&ask(Ask { action: Action::Call("proc.spawn:run".into()), ..base() }, &l), "capability does not grant 'proc.spawn:run'", "none of them covers 'proc.spawn:run'");
    // [L0] alone: the planner may grant but not use.
    let root_only = TokenV3 { links: t.links[..1].to_vec(), programs: t.programs.clone() };
    refused_with(&ask(Ask { t: &root_only, who: WIN, ..base() }, &l), "program step 0: the capability does not grant 'cell.install:install-file'", "does not type under the leaf");
}

#[test]
fn check_a_chain_widened_after_compile_is_refused_with_why() {
    let b = book();
    let c = compile("raspberry-pi", &b);
    let mut t = sign_all(&c);
    // agent-b's link re-signed by the planner with one more ability than Leif lets it grant
    let Link::V3 { cap, .. } = &t.links[1] else { unreachable!() };
    let mut wide = cap.clone();
    wide.abilities.push("proc.spawn:run".into());
    t.links[1] = Link::V3 { sig: signer(WIN).sign(&wide), cap: wide };
    let l = labels(&c, &b);
    let v = ask(Ask { t: &t, node: PI, host: "pi-01", who: AGENT_B, action: step0(&c.programs[0]), presented: None, content: None }, &l);
    refused_with(&v, "link 1: abilities exceed the parent's grant", "it gives 'proc.spawn:run', which the parent does not let agent:planner grant");
    // and the decompiled chain shows the extra ability, so the refusal can be read
    assert!(cal::decompile(&t, &l).unwrap().contains("can cell.install:install-file, proc.spawn:run"));
}

fn use_request(t: &TokenV3, at: u8, who: u8, action: &str, body: &[u8]) -> UseRequest {
    UseRequest { leaf: t.links.last().unwrap().id(), node: node(at), requester: key(who), action: action.into(), body: Sha256::digest(body).into(), at: T + 60, nonce: 1 }
}

#[test]
fn check_the_wechat_rule() {
    let b = book();
    let c = compile("wechat-read", &b);
    let t = sign_all(&c);
    let l = labels(&c, &b);
    let call = || Action::Call("wechat.send:send".into());
    let bare = ask(Ask { t: &t, node: DESK, host: "leif-desk", who: WRITER, action: call(), presented: None, content: None }, &l);
    refused_with(&bare, "condition not met: requires", "cell:wechat.read@1 (whichever key the executing node trusts for it) must attest that the requester has read wechat thread family");
    let r = use_request(&t, DESK, WRITER, "wechat.send:send", b"hello family");
    let body = ce_net_proto::v3::AttestationBody {
        witness: key(WECHAT_CELL),
        subject: key(WRITER),
        claim: ce_net_proto::v3::Claim::ReadThrough { source: "wechat".into(), thread: "family".into(), upto_msg: Some("m42".into()) },
        at: T - 60,
    };
    let att = Proof::Attested(ce_net_proto::v3::Attestation { sig: signer(WECHAT_CELL).sign_bytes(&ce_net_proto::v3::attest_bytes(&body)), body });
    let ok = ask(Ask { t: &t, node: DESK, host: "leif-desk", who: WRITER, action: call(), presented: Some((r.clone(), vec![att.clone()], b"hello family".to_vec())), content: None }, &l);
    assert!(ok.allowed, "{}", ok.text());
    // eleven minutes old: refused
    let mut stale = body_of(&att);
    stale.at = T - 660;
    let old = Proof::Attested(ce_net_proto::v3::Attestation { sig: signer(WECHAT_CELL).sign_bytes(&ce_net_proto::v3::attest_bytes(&stale)), body: stale });
    let v = ask(Ask { t: &t, node: DESK, host: "leif-desk", who: WRITER, action: call(), presented: Some((r, vec![old], b"hello family".to_vec())), content: None }, &l);
    refused_with(&v, "condition not met: requires", "at most 10 minutes before the use");
}

fn body_of(p: &Proof) -> ce_net_proto::v3::AttestationBody {
    match p {
        Proof::Attested(a) => a.body.clone(),
        _ => unreachable!(),
    }
}

#[test]
fn check_the_3d_printer_rule() {
    let b = book();
    let c = compile("printer-broker", &b);
    let t = sign_all(&c);
    let l = labels(&c, &b);
    let call = || Action::Call("printer3d:print".into());
    let ask_with = |p: Option<(UseRequest, Vec<Proof>, Vec<u8>)>| ask(Ask { t: &t, node: PRINTER, host: "printer-1", who: AGENT_B, action: call(), presented: p, content: None }, &l);
    refused_with(&ask_with(None), "condition not met: via", "Every use must come through agent:printer-guard");
    let r = use_request(&t, PRINTER, AGENT_B, "printer3d:print", b"gear.gcode");
    let approved = Proof::Brokered { broker: key(PRINTER_AGENT), sig: signer(PRINTER_AGENT).sign_bytes(&via_bytes(&r)) };
    let ok = ask_with(Some((r.clone(), vec![approved], b"gear.gcode".to_vec())));
    assert!(ok.allowed, "{}", ok.text());
    let self_approved = Proof::Brokered { broker: key(AGENT_B), sig: signer(AGENT_B).sign_bytes(&via_bytes(&r)) };
    refused_with(&ask_with(Some((r, vec![self_approved], b"gear.gcode".to_vec()))), "condition not met: via", "agent:printer-guard");
}

#[test]
fn check_the_door_guard_rule() {
    let b = book();
    let c = compile("door-guard", &b);
    let t = sign_all(&c);
    let l = labels(&c, &b);
    let r = use_request(&t, BOX, AGENT_B, "door.gate:pass", b"open door 2");
    let g = signer(GUARDIAN);
    let both = vec![Proof::CoSigned { by: g.key(), sig: g.sign_bytes(&cosign_bytes(&r)) }, Proof::Brokered { broker: g.key(), sig: g.sign_bytes(&via_bytes(&r)) }];
    let a = |p: Vec<Proof>| ask(Ask { t: &t, node: BOX, host: "box-1", who: AGENT_B, action: Action::Call("door.gate:pass".into()), presented: Some((r.clone(), p, b"open door 2".to_vec())), content: None }, &l);
    assert!(a(both.clone()).allowed);
    refused_with(&a(vec![both[1].clone()]), "condition not met: cosign", "co-signed by agent:auth-guard");
    refused_with(&a(vec![both[0].clone()]), "condition not met: via", "come through agent:auth-guard");
}

#[test]
fn check_the_feed_install_and_the_long_chain() {
    let b = book();
    let feed = compile("feed-cell-install", &b);
    let t = sign_all(&feed);
    let l = labels(&feed, &b);
    let v = ask(Ask { t: &t, node: DESK, host: "leif-desk", who: INSTALLER, action: step0(&feed.programs[0]), presented: None, content: None }, &l);
    assert!(v.allowed, "{}", v.text());
    refused_with(&ask(Ask { t: &t, node: MAC, host: "macbook", who: INSTALLER, action: step0(&feed.programs[0]), presented: None, content: None }, &l), "link 1: resource does not match this node", "this request is at node:macbook");

    let long = compile("long-chain", &b);
    let t = sign_all(&long);
    let l = labels(&long, &b);
    // the process key may only connect: installing is refused, typed under its leaf
    let v = ask(Ask { t: &t, node: BOX, host: "box-1", who: PROCESS, action: step0(&long.programs[0]), presented: None, content: None }, &l);
    refused_with(&v, "program step 0: the capability does not grant 'cell.install:install-file'", "net.egress:connect");
    // the friend's agent, holding [L0, L1], installs and runs the job
    let two = TokenV3 { links: t.links[..2].to_vec(), programs: t.programs.clone() };
    let job = long.programs[0].clone();
    let v = ask(Ask { t: &two, node: BOX, host: "box-1", who: FRIEND_AGENT, action: step0(&job), presented: None, content: None }, &l);
    assert!(v.allowed, "{}", v.text());
    let v = ask(Ask { t: &two, node: BOX, host: "box-1", who: FRIEND_AGENT, action: Action::Step { program: job.id(), run: 1, step: 1 }, presented: None, content: Some(b"import urllib.request\nurllib.request.urlopen('https://api.example.org/')\n".to_vec()) }, &l);
    assert!(v.allowed, "{}", v.text());
}

#[test]
fn the_first_example_of_the_doc_compiles() {
    let doc = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/CAL.md")).unwrap();
    let block = doc.split("```\n").nth(1).unwrap();
    assert!(block.contains("spawn repo:huey-scripts/run.py@3f2a1c sha256:9b1e… on node:pi-01 once"));
    // shortened on the page: refused as such, with the whole hash as the suggestion
    let e = compile_src(block, &book()).map(|_| ()).unwrap_err();
    assert!(e.msg.contains("only the start of a hash"), "{e}");
    let whole = block.replace("sha256:9b1e…", &format!("sha256:{}", hex::encode(Sha256::digest(PI_SCRIPT))));
    let f = cal::parse(&whole).unwrap();
    let mut n = || 7u64;
    let c = cal::compile(&f, &book(), &mut cal::Options { now: T, nonce: &mut n, lenient: false }).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c.links.len(), 1);
    assert_eq!(c.programs[0].steps.len(), 2);
    assert_eq!(c.links[0].ext.iter().filter(|x| x.is_condition()).count(), 3);
}
