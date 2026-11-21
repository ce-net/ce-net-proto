//! CES-4 conformance vectors (docs/standards/CES-4-container.md section 5).
use ce_net_proto::ces4::{Answer, AnswerLimits, Class, Launch, Policy, check_answer, choose};
use serde_json::Value;

fn load(name: &str) -> Vec<Value> {
    serde_json::from_str(&std::fs::read_to_string(format!("{}/tests/ces4/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
}

#[test]
fn choose_fails_closed() {
    for v in load("choose.json") {
        let name = v["name"].as_str().unwrap();
        let l: Launch = serde_json::from_value(v["launch"].clone()).unwrap();
        let node: Vec<Class> = serde_json::from_value(v["node"].clone()).unwrap();
        let p: Policy = serde_json::from_value(v["policy"].clone()).unwrap();
        let got = choose(&l, &node, &p);
        match &v["expect"] {
            Value::String(c) => assert_eq!(got, Ok(serde_json::from_value::<Class>(Value::String(c.clone())).unwrap()), "{name}"),
            e => assert_eq!(got.as_ref().map_err(|e| e.kind()), Err(e["error"].as_str().unwrap()), "{name}: {got:?}"),
        }
    }
}

#[test]
fn boundary() {
    for v in load("boundary.json") {
        let lim: AnswerLimits = serde_json::from_value(v["limits"].clone()).unwrap();
        let a: Answer = serde_json::from_value(v["answer"].clone()).unwrap();
        let got = check_answer(&lim, &a).map_err(|e| e.kind()).err().unwrap_or("ok");
        assert_eq!(got, v["expect"].as_str().unwrap(), "{}", v["name"]);
    }
}
