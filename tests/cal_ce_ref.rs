//! `ce-cal --ce-ref`: repository files the ref book does not know are pinned through the live ce.ref
//! resolver (cell ref.index). A stand-in `ce` (CE_CAL_CE) answers with the cell's wire shapes, so
//! every verdict is exercised: PASS pins, FAIL is unknown, and anything ce.ref cannot vouch for
//! (no content hash, an answer about another ref, an unreadable index) refuses instead of pinning.
#![cfg(unix)]

use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples");
const BODY: &[u8] = b"print(1)\n";

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ce-cal-ceref-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

fn hexsha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// The portable ref of `run.py` in github.com/example/tools.
fn portable() -> String {
    format!("ce-ref://repo/{}/run.py", hexsha(b"github.com/example/tools"))
}

fn repos(origins: &[&str]) -> String {
    let list: Vec<String> = origins
        .iter()
        .map(|o| format!(r#"{{"repo":"tools","origin":"{o}","files":1,"observed":0,"ambiguous":false}}"#))
        .collect();
    format!(r#"{{"Ok":{{"repos":[{}],"coverage":{{"verdict":"PASS","repositories":1,"files":1,"age_s":1,"report_json":""}}}}}}"#, list.join(","))
}

fn pass(reference: &str, digest: &str) -> String {
    format!(
        r#"{{"Ok":{{"verdict":"PASS","reason":"","file":{{"reference":"{reference}","repo":"tools","path":"run.py","origin":"github.com/example/tools","commit_id":"abcdef1234","digest":"{digest}","size":{},"title":"","observed":0,"node":"n"}},"links":[],"backlinks":[]}}}}"#,
        BODY.len()
    )
}

/// Compile one install of `file` with a stand-in `ce` that answers Repositories and Resolve as given.
fn compile(case: &str, file: &str, repositories: &str, resolve: &str) -> (i32, String) {
    let ce = tmp(&format!("ce-{case}"));
    let (rp, sp) = (tmp(&format!("{case}.repos.json")), tmp(&format!("{case}.resolve.json")));
    std::fs::write(&rp, repositories).unwrap();
    std::fs::write(&sp, resolve).unwrap();
    std::fs::write(&ce, format!("#!/bin/sh\ncase \"$4\" in Repositories) cat '{}';; Resolve) cat '{}';; esac\n", rp.display(), sp.display())).unwrap();
    std::fs::set_permissions(&ce, std::fs::Permissions::from_mode(0o755)).unwrap();
    let src = tmp(&format!("{case}.cal"));
    std::fs::write(
        &src,
        format!(
            "person:leif grants agent:installer {{\n  may grant cell.install:install-file to anyone\n  on node:pi-01\n  until 2026-12-01\n  once\n  only {{\n    install {file} to /opt/x/run.py on node:pi-01\n  }}\n}}\n"
        ),
    )
    .unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_ce-cal"))
        .args(["compile", src.to_str().unwrap(), "--refs", &format!("{DIR}/cal.refs.json"), "--ce-ref"])
        .env("CE_CAL_CE", &ce)
        .output()
        .unwrap();
    (o.status.code().unwrap(), String::from_utf8_lossy(&o.stderr).into_owned())
}

#[test]
fn live_ce_ref_pins_only_what_it_can_vouch_for() {
    let h = hexsha(BODY);
    let one = repos(&["https://github.com/example/tools"]);
    let by_repo = format!("repo:tools/run.py@abcdef1 sha256:{h}");

    // PASS with the hash pinned: compiles, by repo name and by portable ref.
    let (code, err) = compile("pass", &by_repo, &one, &pass(&portable(), &h));
    assert_eq!(code, 0, "{err}");
    let (code, err) = compile("portable", &format!("{} sha256:{h}", portable()), &one, &pass(&portable(), &h));
    assert_eq!(code, 0, "{err}");

    // A different pinned hash is a mismatch, and no hash at all suggests the one ce.ref sees.
    let (code, err) = compile("wrong", &format!("repo:tools/run.py@abcdef1 sha256:{}", hexsha(b"x")), &one, &pass(&portable(), &h));
    assert_eq!(code, 1);
    assert!(err.contains("content hash mismatch"), "{err}");
    let (code, err) = compile("nohash", "repo:tools/run.py@abcdef1", &one, &pass(&portable(), &h));
    assert_eq!(code, 1);
    assert!(err.contains(&format!("ce.ref sees sha256:{h}")), "{err}");

    // FAIL: the file is not there.
    let fail = r#"{"Ok":{"verdict":"FAIL","reason":"no such file","file":null,"links":[],"backlinks":[]}}"#;
    let (code, err) = compile("fail", &by_repo, &one, fail);
    assert_eq!(code, 1);
    assert!(err.contains("is not known to the resolver"), "{err}");

    // Indexed but never hashed (unreadable or too large): cannot determine, never "sha256:" of nothing.
    let (code, err) = compile("nodigest", &by_repo, &one, &pass(&portable(), ""));
    assert_eq!(code, 1);
    assert!(err.contains("CANNOT DETERMINE") && err.contains("no content hash"), "{err}");
    assert!(!err.contains("is sha256: "), "{err}");

    // An answer about another ref is not an answer.
    let other = format!("ce-ref://repo/{}/run.py", hexsha(b"github.com/other/tools"));
    let (code, err) = compile("otherref", &by_repo, &one, &pass(&other, &h));
    assert_eq!(code, 1);
    assert!(err.contains("answered for"), "{err}");

    // An unreadable index refuses; it is never read as "no such file".
    let down = r#"{"Err":{"Unavailable":"index unreadable, nothing was checked"}}"#;
    let (code, err) = compile("down", &by_repo, down, down);
    assert_eq!(code, 1);
    assert!(err.contains("cannot determine repository 'tools'") && err.contains("index unreadable"), "{err}");

    // "tools" in two places: ambiguous, and the answer names each portable ref.
    let two = repos(&["https://github.com/example/tools", "https://github.com/other/tools"]);
    let (code, err) = compile("amb", &by_repo, &two, &pass(&portable(), &h));
    assert_eq!(code, 1);
    assert!(err.contains("ambiguous") && err.contains(&portable()) && err.contains(&other), "{err}");
}
