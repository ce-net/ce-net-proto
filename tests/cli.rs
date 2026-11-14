//! End-to-end tests of the `ce-cap-verify` binary against the golden vectors.

use std::process::Command;

fn vectors() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json")).unwrap())
        .unwrap()
}

fn run(args: &[&str]) -> (i32, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_ce-cap-verify")).args(args).output().unwrap();
    (o.status.code().unwrap(), String::from_utf8_lossy(&o.stdout).into_owned())
}

#[test]
fn cli_agrees_with_every_vector() {
    let v = vectors();
    for c in v["chains"].as_array().unwrap() {
        let now = c["now"].as_u64().unwrap().to_string();
        let mut args = vec![c["chain_hex"].as_str().unwrap().to_string(), "--root".into(), c["root"].as_str().unwrap().into(), "--now".into(), now];
        for r in c["revoked"].as_array().unwrap() {
            args.push("--revoked".into());
            args.push(format!("{}:{}", r["issuer"].as_str().unwrap(), r["nonce"]));
        }
        let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let (code, out) = run(&a);
        let ok = c["verify_chain"]["ok"].as_bool().unwrap();
        assert_eq!(code, if ok { 0 } else { 1 }, "{}: {out}", c["name"]);
        if !ok {
            assert!(out.contains(c["verify_chain"]["error"].as_str().unwrap()), "{}: {out}", c["name"]);
        }
    }
}

#[test]
fn cli_action_and_holder_checks() {
    let v = vectors();
    let d = v["chains"].as_array().unwrap().iter().find(|c| c["name"] == "delegated").unwrap();
    let (tok, root) = (d["chain_hex"].as_str().unwrap(), d["root"].as_str().unwrap());
    let holder = d["authorize"]["requester"].as_str().unwrap();
    let (code, out) = run(&[tok, "--root", root, "--now", "1700000100", "--action", "app:spawn:wasm", "--holder", holder]);
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("VALID") && out.contains("links:     2"), "{out}");
    let (code, out) = run(&[tok, "--root", root, "--now", "1700000100", "--action", "exec"]);
    assert_eq!(code, 1);
    assert!(out.contains("does not grant 'exec'"));
    let (code, _) = run(&[tok, "--root", root, "--now", "1700000100", "--holder", root]);
    assert_eq!(code, 1);
    let (code, _) = run(&[tok]);
    assert_eq!(code, 2, "missing --root is a usage error");
    let (code, out) = run(&["deadbeef", "--root", root]);
    assert_eq!(code, 1);
    assert!(out.contains("malformed"));
}
