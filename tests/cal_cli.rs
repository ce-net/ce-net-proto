//! End-to-end tests of the `ce-cal` binary: compile and sign an example, explain, decompile and
//! check the token, and the exit codes and messages of a refusal.

use std::process::Command;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples");

fn run(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_ce-cal")).args(args).output().unwrap();
    (o.status.code().unwrap(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn tmp(name: &str) -> String {
    let d = std::env::temp_dir().join(format!("ce-cal-cli-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name).to_string_lossy().into_owned()
}

fn pi_token() -> String {
    let (leif, planner) = (tmp("leif.key"), tmp("planner.key"));
    std::fs::write(&leif, format!("p256:{}\n", "11".repeat(32))).unwrap();
    std::fs::write(&planner, format!("ed25519:{}\n", "21".repeat(32))).unwrap();
    let refs = format!("{DIR}/cal.refs.json");
    let (code, out, err) = run(&["compile", &format!("{DIR}/raspberry-pi.cal"), "--refs", &refs, "--key", &leif, "--key", &planner]);
    assert_eq!(code, 0, "{err}");
    out.trim().to_string()
}

#[test]
fn compile_sign_explain_decompile_check() {
    let refs = format!("{DIR}/cal.refs.json");
    let token = pi_token();
    assert!(token.starts_with("43454333"), "{token}");
    // a draft signed in two steps gives the same token
    let draft = tmp("pi.draft.json");
    let (code, _, err) = run(&["compile", &format!("{DIR}/raspberry-pi.cal"), "--refs", &refs, "-o", &draft]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("still to sign: p256:020217e6"), "{err}");
    let (_, signed_once, _) = run(&["sign", &draft, "--key", &tmp("leif.key")]);
    std::fs::write(&draft, signed_once).unwrap();
    let (_, signed, _) = run(&["sign", &draft, "--key", &tmp("planner.key")]);
    assert_eq!(signed.trim(), token);

    let (code, text, _) = run(&["explain", &token, "--refs", &refs]);
    assert_eq!(code, 0);
    assert!(text.contains("Link 1: agent:planner grants agent:agent-b"), "{text}");
    assert!(text.contains("content sha256:3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51 (26 bytes)"), "{text}");

    let (code, src, _) = run(&["decompile", &token, "--refs", &refs]);
    assert_eq!(code, 0);
    assert!(src.contains("person:leif p256:020217e6"), "{src}");

    let script = tmp("run.py");
    std::fs::write(&script, "print('hello from pi-01')\n").unwrap();
    let ask = ["check", &token, "--refs", &refs, "--node", "node:pi-01", "--program", "b94f", "--now", "1800000060"];
    let (code, out, _) = run(&[&ask[..], &["--as", "agent:agent-b", "--content", &script]].concat());
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("ALLOWED"), "{out}");
    std::fs::write(&script, "print('something else')\n").unwrap();
    let (code, out, _) = run(&[&ask[..], &["--as", "agent:agent-b", "--content", &script]].concat());
    assert_eq!(code, 1, "{out}");
    assert!(out.starts_with("REFUSED: content hash mismatch"), "{out}");
    let (code, out, _) = run(&[&ask[..], &["--as", "agent:planner"]].concat());
    assert_eq!(code, 1);
    assert!(out.contains("The chain is held by agent:agent-b"), "{out}");
}

#[test]
fn refusals_name_the_line_and_suggest_the_pin() {
    let refs = format!("{DIR}/cal.refs.json");
    let src = std::fs::read_to_string(format!("{DIR}/raspberry-pi.cal")).unwrap();
    let f = tmp("short.cal");
    std::fs::write(&f, src.replace("sha256:3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51", "sha256:3f9b…")).unwrap();
    let (code, _, err) = run(&["compile", &f, "--refs", &refs]);
    assert_eq!(code, 1);
    assert!(err.contains("line 8: 'sha256:3f9b…' is only the start of a hash"), "{err}");
    assert!(err.contains("suggestion: the file's hash is sha256:3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51"), "{err}");
    std::fs::write(&f, src.replace("repo:huey-scripts/run.py@3f2a1c sha256:3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51", "run.py")).unwrap();
    let (code, _, err) = run(&["compile", &f, "--refs", &refs]);
    assert_eq!(code, 1);
    assert!(err.contains("'run.py' is a bare path"), "{err}");
    let (code, _, _) = run(&["frobnicate"]);
    assert_eq!(code, 2);
}

#[test]
fn fmt_prints_the_canonical_layout() {
    let (code, out, _) = run(&["fmt", &format!("{DIR}/printer-broker.cal")]);
    assert_eq!(code, 0);
    assert!(out.starts_with("cal 1\n\nperson:leif grants agent:planner {\n  may grant printer3d:print to anyone depth 1\n"), "{out}");
}
