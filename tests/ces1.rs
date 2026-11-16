//! CES-1 conformance vectors (docs/standards/CES-1-budget.md section 6): every manifest in
//! `tests/ces1/manifests.json` gets the stated verdict and line, every sample in
//! `tests/ces1/samples.json` the stated outcome for C1.3 to C1.7. The Python reference
//! (`docs/reference/ces1_check.py`) runs the same files.
use ce_net_proto::ces1::{Outcome, Sample, check_manifest, judge_sample};
use serde_json::Value;

fn load(name: &str) -> Vec<Value> {
    let p = format!("{}/tests/ces1/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn manifests() {
    let vs = load("manifests.json");
    assert!(vs.len() >= 10);
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let got = check_manifest(v["toml"].as_str().unwrap());
        match (&v["expect"], &got) {
            (Value::String(s), Ok(None)) if s == "absent" => {}
            (Value::String(s), Ok(Some(_))) if s == "valid" => {}
            (Value::Object(o), Err(vs)) => {
                let (check, line) = (o["fail"].as_str().unwrap(), o["line"].as_u64().unwrap() as usize);
                assert!(vs.iter().any(|x| x.check == check && x.line == line), "{name}: want {check} at line {line}, got {vs:?}");
            }
            (e, g) => panic!("{name}: expected {e}, got {g:?}"),
        }
    }
}

#[test]
fn samples() {
    for v in load("samples.json") {
        let name = v["name"].as_str().unwrap();
        let b = check_manifest(v["budget"].as_str().unwrap()).unwrap().unwrap();
        let s: Sample = serde_json::from_value(v["sample"].clone()).unwrap();
        for verdict in judge_sample(&b, &s) {
            let want = v["expect"][&verdict.check].as_str().unwrap();
            let got = match verdict.outcome {
                Outcome::Pass => "pass",
                Outcome::Warn => "warn",
                Outcome::Fail => "fail",
                Outcome::Skip => "skip",
            };
            assert_eq!(got, want, "{name} {}: {}", verdict.check, verdict.msg);
        }
    }
}
