//! CAL unit tests: the grammar, the printer, and every refusal of an ambiguous or unpinned ref.

use super::refs::{FileInfo, RefBook};
use super::*;

const RUN_SHA: &str = "3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51";
const PI: &str = "db995fe25169d141cab9bbba92baa01f9f2e1ece7df4cb2ac05190f37fcc1f9d";
const PI2: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
const LEIF: &str = "ed25519:1111111111111111111111111111111111111111111111111111111111111111";
const B: &str = "ed25519:2222222222222222222222222222222222222222222222222222222222222222";

fn book() -> RefBook {
    let mut b = RefBook::default();
    b.principals.insert("person:leif".into(), vec![LEIF.into()]);
    b.principals.insert("agent:b".into(), vec![B.into()]);
    b.nodes.insert("pi-01".into(), vec![PI.into()]);
    b.repos.insert("huey-scripts".into(), vec!["https://github.com/example/huey-scripts".into()]);
    let (id, _) = refs::origin_id("https://github.com/example/huey-scripts").unwrap();
    b.files.insert(refs::portable(&id, "run.py").unwrap(), vec![FileInfo { sha256: RUN_SHA.into(), size: 26, commit: "3f2a1c7e9d4b".into() }]);
    b
}

fn link(body: &str) -> String {
    format!("person:leif grants agent:b {{\n{body}\n}}\n")
}

fn pi_program(file: &str) -> String {
    format!(
        "program p {{\n  install {file} to /opt/x/run.py on node:pi-01 mode 755\n}}\n{}",
        link("can cell.install:install-file\non node:pi-01\nuntil 2027-01-22\nfiles under /opt/x\nonce\nonly p\nnonce 1")
    )
}

fn compile_with(src: &str, r: &dyn Resolver) -> Result<Compiled, CalError> {
    let f = parse(src)?;
    let mut n = 0u64;
    let mut next = || {
        n += 1;
        n
    };
    compile(&f, r, &mut Options { now: 1_800_000_000, nonce: &mut next, lenient: false })
}

fn refused(src: &str, r: &dyn Resolver, msg: &str, hint: &str) {
    let e = compile_with(src, r).map(|_| ()).unwrap_err();
    assert!(e.msg.contains(msg), "message {:?} lacks {msg:?}", e.msg);
    assert!(e.hint.as_deref().unwrap_or("").contains(hint), "suggestion {:?} lacks {hint:?}", e.hint);
}

fn parse_refused(src: &str, msg: &str) {
    let e = parse(src).unwrap_err();
    assert!(e.to_string().contains(msg), "{e} lacks {msg:?}");
}

#[test]
fn a_pinned_repo_file_compiles_to_its_hash_and_size() {
    let c = compile_with(&pi_program(&format!("repo:huey-scripts/run.py@3f2a1c sha256:{RUN_SHA}")), &book()).unwrap();
    let crate::program::Step::Install { sha256, size, on, .. } = &c.programs[0].steps[0] else { panic!() };
    assert_eq!(hex::encode(sha256), RUN_SHA);
    assert_eq!(*size, 26);
    assert_eq!(hex::encode(on), PI);
    assert_eq!(c.labels.files[sha256], "repo:huey-scripts/run.py@3f2a1c");
    assert!(c.labels.portable[sha256].starts_with("ce-ref://repo/b47ae729"));
}

#[test]
fn bare_names_and_paths_are_refused() {
    parse_refused("friend grants agent:b { on node:pi-01 }", "'friend' is a bare name; write person:friend or agent:friend");
    parse_refused(&link("on pi-01"), "write node:pi-01");
    parse_refused(&pi_program("run.py"), "'run.py' is a bare path");
    parse_refused(&pi_program("/opt/x/run.py"), "bare path");
    parse_refused(&link("on node:pi-01\nvia printer3d.gate"), "a principal is a ce-ref");
}

#[test]
fn an_unpinned_file_is_refused_with_its_hash_as_the_suggestion() {
    refused(&pi_program("repo:huey-scripts/run.py@3f2a1c"), &book(), "unpinned: repo:huey-scripts/run.py@3f2a1c has no content hash", RUN_SHA);
    refused(&pi_program(&format!("repo:huey-scripts/run.py sha256:{RUN_SHA}")), &book(), "names no commit", "repo:huey-scripts/run.py@<commit>");
}

#[test]
fn a_hash_prefix_is_refused_with_the_full_hash() {
    for pre in ["sha256:3f9b", "sha256:3f9b…", "sha256:3f9b..."] {
        refused(&pi_program(&format!("repo:huey-scripts/run.py@3f2a1c {pre}")), &book(), "only the start of a hash", &format!("sha256:{RUN_SHA}"));
    }
}

#[test]
fn a_hash_the_resolver_contradicts_is_refused() {
    let other = "9b1e".repeat(16);
    refused(&pi_program(&format!("repo:huey-scripts/run.py@3f2a1c sha256:{other}")), &book(), &format!("content hash mismatch: repo:huey-scripts/run.py@3f2a1c pins sha256:{other}, but the file is sha256:{RUN_SHA}"), "pin the hash");
    refused(&pi_program(&format!("repo:huey-scripts/run.py@3f2a1c sha256:{RUN_SHA} size 27")), &book(), "size mismatch", "");
}

#[test]
fn an_unknown_repo_or_file_is_refused() {
    refused(&pi_program(&format!("repo:nowhere/run.py@3f2a1c sha256:{RUN_SHA}")), &book(), "no repository named 'nowhere'", "ce-ref://repo/");
    refused(&pi_program(&format!("repo:huey-scripts/other.py@3f2a1c sha256:{RUN_SHA}")), &book(), "is not known to the resolver", "ce-blob:sha256:");
}

#[test]
fn an_ambiguous_repo_is_refused_with_both_portable_refs() {
    let mut b = book();
    b.repos.insert("huey-scripts".into(), vec!["https://github.com/example/huey-scripts".into(), "https://github.com/fork/huey-scripts".into()]);
    let (a, _) = refs::origin_id("https://github.com/example/huey-scripts").unwrap();
    let (f, _) = refs::origin_id("https://github.com/fork/huey-scripts").unwrap();
    let e = compile_with(&pi_program(&format!("repo:huey-scripts/run.py@3f2a1c sha256:{RUN_SHA}")), &b).map(|_| ()).unwrap_err();
    assert!(e.msg.contains("ambiguous: repo:huey-scripts/run.py names 2 different files"), "{e}");
    let hint = e.hint.unwrap();
    assert!(hint.contains(&format!("ce-ref://repo/{a}/run.py")) && hint.contains(&format!("ce-ref://repo/{f}/run.py")), "{hint}");
    // Written as the portable ref, it is unambiguous.
    let ok = compile_with(&pi_program(&format!("ce-ref://repo/{a}/run.py sha256:{RUN_SHA}")), &b).unwrap();
    assert_eq!(ok.programs.len(), 1);
}

#[test]
fn a_repo_name_with_a_slash_splits_where_the_resolver_knows_a_repository() {
    let mut b = book();
    b.repos.insert("ws/tools".into(), vec!["https://github.com/example/tools".into()]);
    let (id, _) = refs::origin_id("https://github.com/example/tools").unwrap();
    b.files.insert(refs::portable(&id, "bin/run.py").unwrap(), vec![FileInfo { sha256: RUN_SHA.into(), size: 26, commit: String::new() }]);
    compile_with(&pi_program(&format!("repo:ws/tools/bin/run.py@abcd sha256:{RUN_SHA}")), &b).unwrap();
    // "ws" alone is another repository: the same text now names two files.
    b.repos.insert("ws".into(), vec!["https://github.com/example/ws".into()]);
    refused(&pi_program(&format!("repo:ws/tools/bin/run.py@abcd sha256:{RUN_SHA}")), &b, "ambiguous", "ce-ref://repo/");
}

#[test]
fn an_ambiguous_node_name_is_refused_and_a_full_id_is_not() {
    let mut b = book();
    b.nodes.insert("pi-01".into(), vec![PI.into(), PI2.into()]);
    let src = link("can x:y\non node:pi-01");
    refused(&src, &b, "ambiguous: 2 nodes are named 'pi-01'", &format!("node:{PI}"));
    compile_with(&link(&format!("can x:y\non node:{PI}")), &b).unwrap();
    compile_with(&link(&format!("can x:y\non node:pi-01 ed25519:{PI}")), &b).unwrap();
    refused(&link("can x:y\non node:pi-02"), &b, "no node named 'pi-02'", "node:<64 hex>");
}

#[test]
fn principals_resolve_to_one_key_or_are_refused() {
    let src = "person:leif grants agent:nobody {\n can x:y\n on any node\n}";
    refused(src, &book(), "unpinned: agent:nobody is not in the ref book", "agent:nobody ed25519:<64 hex>");
    let pinned = format!("person:leif grants agent:nobody {B} {{\n can x:y\n on any node\n}}");
    assert_eq!(compile_with(&pinned, &book()).unwrap().links[0].audience, refs::parse_key(B).unwrap());
    let wrong = format!("person:leif {B} grants agent:b {{\n can x:y\n on any node\n}}");
    refused(&wrong, &book(), "pin mismatch: person:leif", LEIF);
    let mut b = book();
    b.principals.insert("person:leif".into(), vec![LEIF.into(), B.into()]);
    refused(&link("can x:y\non any node"), &b, "ambiguous: person:leif has 2 keys", &format!("person:leif {LEIF}"));
    // A bare key needs no resolver.
    compile_with(&format!("{LEIF} grants {B} {{\n can x:y\n on any node\n}}"), &NoRefs).unwrap();
}

#[test]
fn a_cell_party_must_name_its_major_version() {
    refused(&link("can x:y\non node:pi-01\nvia cell:printer3d.gate"), &book(), "unpinned: cell:printer3d.gate names no major version", "cell:printer3d.gate@1");
    let c = compile_with(&link("can x:y\non node:pi-01\nvia cell:printer3d.gate@1"), &book()).unwrap();
    assert_eq!(c.links[0].ext, vec![crate::v3::Caveat::Via(vec![crate::v3::Party::Cell("printer3d.gate@1".into())])]);
}

#[test]
fn require_read_needs_a_witness() {
    parse_refused(&link("on node:pi-01\nrequire read wechat:thread/123 within 10m"), "by cell:wechat.read@1");
    let c = compile_with(&link("can wechat.send:send\non node:pi-01\nrequire read wechat:thread/123@m42 by cell:wechat.read@1 within 10m"), &book()).unwrap();
    let crate::v3::Caveat::Requires(rs) = &c.links[0].ext[0] else { panic!() };
    assert_eq!(rs[0].fresh_within_s, Some(600));
    assert_eq!(rs[0].claim, crate::v3::Claim::ReadThrough { source: "wechat".into(), thread: "123".into(), upto_msg: Some("m42".into()) });
}

#[test]
fn a_doc_thread_compiles_to_its_portable_ref() {
    let c = compile_with(&link("can doc:write\non node:pi-01\nrequire read doc:huey-scripts/README by agent:b"), &book()).unwrap();
    let crate::v3::Caveat::Requires(rs) = &c.links[0].ext[0] else { panic!() };
    let crate::v3::Claim::ReadThrough { source, thread, .. } = &rs[0].claim else { panic!() };
    assert_eq!(source, "doc");
    assert!(thread.starts_with("ce-ref://repo/b47ae729") && thread.ends_with("/README.md"), "{thread}");
}

#[test]
fn a_child_inherits_and_may_only_narrow() {
    let src = "person:leif grants agent:b {\n may grant x:y to anyone depth 1\n on node:pi-01\n for 7d\n uses 5\n egress *.example.org:443\n limit net.egress.bytes_out 50MB\n}\nagent:b grants person:leif {\n can x:y\n uses 6\n}\n";
    refused(src, &book(), "link 1 is refused by every verifier: caveats are broader than the parent", "it allows 6 uses, more than the parent's 5");
    let ok = src.replace("uses 6", "uses 2\n egress api.example.org:443");
    let c = compile_with(&ok, &book()).unwrap();
    let (p, k) = (&c.links[0], &c.links[1]);
    assert_eq!(k.resource, p.resource);
    assert_eq!(k.caveats.not_after, 1_800_000_000 + 7 * 86_400);
    assert_eq!(k.ext.len(), 3);
    let wide = src.replace("uses 6", "egress *.org:443");
    refused(&wide, &book(), "caveats are broader", "is not covered by the parent's");
    let drop = src.replace("can x:y\n uses 6", "inherit nothing\n can x:y\n on node:pi-01");
    refused(&drop, &book(), "caveats are broader", "drops");
}

#[test]
fn a_child_must_be_issued_by_the_parents_audience() {
    let src = "person:leif grants agent:b {\n may grant x:y to anyone\n on node:pi-01\n}\nperson:leif grants agent:b {\n can x:y\n}\n";
    refused(src, &book(), "the issuer person:leif is not link 0's audience agent:b", "start this one with agent:b grants");
}

#[test]
fn a_counted_link_must_expire_and_name_its_nodes() {
    refused(&link("can x:y\non node:pi-01\nonce"), &book(), "not canonical", "must expire");
    refused(&link("can x:y\non any node\nonce\nfor 1d"), &book(), "not canonical", "must name its nodes");
    refused(&link("can x:y"), &book(), "does not say where it applies", "on any node");
}

#[test]
fn spawn_finds_the_installed_file_or_says_where_it_is() {
    let file = format!("repo:huey-scripts/run.py@3f2a1c sha256:{RUN_SHA}");
    let src = format!("program p {{\n  spawn {file} on node:pi-01\n}}\n{}", link("can proc.spawn:run\non node:pi-01\nonly p"));
    refused(&src, &book(), "is not installed earlier in this program", "spawn repo:huey-scripts/run.py@3f2a1c");
    let at = src.replace("on node:pi-01\n}", "at /opt/x/run.py on node:pi-01 once { time 1h; egress api.example.org:443 }\n}");
    let c = compile_with(&at, &book()).unwrap();
    let crate::program::Step::Run { exe, argv, sandbox, .. } = &c.programs[0].steps[0] else { panic!() };
    assert!(matches!(exe, crate::program::Exe::Path { path, .. } if path == "/opt/x/run.py"));
    assert_eq!(argv, &vec!["run.py".to_string()]);
    assert_eq!(sandbox.wall_s, 3600);
}

#[test]
fn parse_errors_name_the_line() {
    let e = parse("cal 1\n\nperson:leif grants agent:b {\n  can x:y\n  sometimes\n}\n").unwrap_err();
    assert_eq!(e.line, 5);
    assert!(e.msg.contains("unknown clause 'sometimes'"));
    assert_eq!(parse("cal 2\n").unwrap_err().line, 1);
    assert!(parse("person:leif grants agent:b {\n can x:y\n").unwrap_err().msg.contains("never closed"));
    assert!(parse("person:leif grant agent:b {}").unwrap_err().msg.contains("grants, with an s"));
    assert!(parse(&link("until 2026-02-30")).unwrap_err().msg.contains("not a time"));
    assert!(parse(&link("memory 1GB")).unwrap_err().msg.contains("in MB"));
}

#[test]
fn print_is_canonical_and_parse_inverts_it() {
    let src = format!(
        "program p {{ install repo:huey-scripts/run.py@3f2a1c sha256:{RUN_SHA} to /opt/x/run.py on node:pi-01 mode 755; spawn repo:huey-scripts/run.py@3f2a1c sha256:{RUN_SHA} on node:pi-01 keep {{ args \"run.py\" \"--fast\"; env A \"1\"; egress 10.0.0.0/8:22, dns.example:53/udp, [2001:db8::]/32:443+80 }} }}\n\
         person:leif grants agent:b {{ may grant a:b, c:d to agent:b, person:leif depth 3; on nodes tagged all of x, y; not before 2027-01-01; until 2027-02-01T10:30Z; cpu 2; memory 256MB; credits 9; ports 22, 443; files under /srv; uses 3 per action; limit net.egress.bytes_out 1GB; limit proc.spawn.wall_s 90s; egress none; only p, program:{}; require fact door.code_ok = \"yes\" by agent:b within 30s; cosign agent:b; via cell:printer3d.gate@2; nonce 7 }}\n",
        "ab".repeat(32)
    );
    let once = print::print(&parse(&src).unwrap());
    let twice = print::print(&parse(&once).unwrap());
    assert_eq!(once, twice);
    assert!(once.contains("  spawn repo:huey-scripts/run.py@3f2a1c sha256:"), "{once}");
    assert!(once.contains("    egress 10.0.0.0/8:22, dns.example:53/udp, [2001:db8::]/32:443+80\n"), "{once}");
    assert!(once.contains("  until 2027-02-01T10:30Z\n"), "{once}");
    assert!(once.contains("  limit net.egress.bytes_out 1GB\n  limit proc.spawn.wall_s 90s\n"), "{once}");
}

#[test]
fn drafts_round_trip_through_json_and_sign_per_issuer() {
    let leif = crate::v3::sign::Signer::ed25519(&[0x11; 32]);
    let mut b = book();
    b.principals.insert("person:leif".into(), vec![refs::fmt_key(&leif.key())]);
    let c = compile_with(&pi_program(&format!("repo:huey-scripts/run.py@3f2a1c sha256:{RUN_SHA}")), &b).unwrap();
    let mut d = c.draft();
    let j = d.to_json();
    assert_eq!(Draft::from_json(&j).unwrap(), d);
    assert!(d.token().is_err());
    let wrong = crate::v3::sign::Signer::ed25519(&[0x22; 32]);
    assert_eq!(d.sign(&wrong), 0);
    assert_eq!(d.sign(&leif), 1);
    let t = d.token().unwrap();
    assert_eq!(crate::v3::TokenV3::from_hex(&t.to_hex()).unwrap().encode(), t.encode());
}

#[test]
fn the_executor_refuses_bytes_that_differ_from_the_pin() {
    let c = compile_with(&pi_program(&format!("repo:huey-scripts/run.py@3f2a1c sha256:{RUN_SHA}")), &book()).unwrap();
    let steps = &c.programs[0].steps;
    check_content(&steps[0], steps, b"print('hello from pi-01')\n").unwrap();
    let e = check_content(&steps[0], steps, b"print('pwned')\n").unwrap_err();
    assert!(e.starts_with("content hash mismatch"), "{e}");
}

#[test]
fn the_json_api_reports_errors_with_their_suggestion() {
    let out: serde_json::Value = serde_json::from_str(&api::call("compile", &serde_json::json!({ "source": pi_program("repo:huey-scripts/run.py@3f2a1c sha256:3f9b"), "refs": book() }).to_string())).unwrap();
    assert_eq!(out["ok"], false);
    assert!(out["error"]["suggestion"].as_str().unwrap().contains(RUN_SHA));
    let out: serde_json::Value = serde_json::from_str(&api::call("parse", r#"{"source":"person:leif grants agent:b { can x:y; on any node }"}"#)).unwrap();
    assert_eq!(out["ok"], true);
    assert_eq!(out["formatted"], "cal 1\n\nperson:leif grants agent:b {\n  can x:y\n  on any node\n}\n");
}
