//! CES-2 conformance vectors (docs/standards/CES-2-lifecycle.md section 6).
use ce_net_proto::ces1::Outcome;
use ce_net_proto::ces2::{Event, Lifecycle, Run, State, check_lifecycle, check_system, judge_run, lease_due, step};
use serde_json::Value;

fn load(name: &str) -> Vec<Value> {
    let p = format!("{}/tests/ces2/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn manifests() {
    let vs = load("manifests.json");
    assert!(vs.len() >= 10);
    for v in vs {
        let name = v["name"].as_str().unwrap();
        match (&v["expect"], check_lifecycle(v["toml"].as_str().unwrap())) {
            (Value::String(s), Ok(_)) if s == "valid" => {}
            (Value::Object(o), Err(vs)) => {
                let (c, l) = (o["fail"].as_str().unwrap(), o["line"].as_u64().unwrap() as usize);
                assert!(vs.iter().any(|x| x.check == c && x.line == l), "{name}: want {c} at {l}, got {vs:?}");
            }
            (e, g) => panic!("{name}: expected {e}, got {g:?}"),
        }
    }
}

#[test]
fn transitions() {
    for v in load("transitions.json") {
        let name = v["name"].as_str().unwrap();
        let lc: Lifecycle = serde_json::from_value(v["lifecycle"].clone()).unwrap();
        let from: State = serde_json::from_value(v["from"].clone()).unwrap();
        let ev: Event = serde_json::from_value(v["event"].clone()).unwrap();
        let got = step(&lc, from, &ev);
        match v["expect"].as_str().unwrap() {
            "refused" => assert!(got.is_err(), "{name}: expected refused, got {got:?}"),
            s => assert_eq!(got, Ok(serde_json::from_value::<State>(Value::String(s.into())).unwrap()), "{name}"),
        }
    }
}

#[test]
fn systems() {
    for v in load("systems.json") {
        let name = v["name"].as_str().unwrap();
        let members: Vec<&str> = v["members"].as_array().unwrap().iter().map(|m| m.as_str().unwrap()).collect();
        let got = check_system(v["system"].as_str().unwrap(), &members);
        match (v["expect"]["C2.4"].as_str().unwrap(), &got) {
            ("pass", Ok(s)) => {
                let due = lease_due(s, v["renewed_s"].as_u64().unwrap(), v["now_s"].as_u64().unwrap(), v["today"].as_str().unwrap());
                assert_eq!(due, v["expect"]["due"].as_bool().unwrap(), "{name}: due");
            }
            ("fail", Err(_)) => {}
            (e, g) => panic!("{name}: expected {e}, got {g:?}"),
        }
    }
}

#[test]
fn runs() {
    for v in load("runs.json") {
        let name = v["name"].as_str().unwrap();
        let lc: Lifecycle = serde_json::from_value(v["lifecycle"].clone()).unwrap();
        let r: Run = serde_json::from_value(v["run"].clone()).unwrap();
        for verdict in judge_run(&lc, &r) {
            let got = match verdict.outcome {
                Outcome::Pass => "pass",
                Outcome::Warn => "warn",
                Outcome::Fail => "fail",
                Outcome::Skip => "skip",
            };
            assert_eq!(got, v["expect"][&verdict.check].as_str().unwrap(), "{name} {}: {}", verdict.check, verdict.msg);
        }
    }
}
