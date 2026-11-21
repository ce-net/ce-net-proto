//! CES-7 conformance vectors (docs/standards/CES-7-wrapped.md section 4).
use ce_net_proto::ces7::{Detect, plan};
use serde_json::Value;

#[test]
fn plans() {
    let vs: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(format!("{}/tests/ces7/plan.json", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap();
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let d: Detect = serde_json::from_value(v["detect"].clone()).unwrap();
        match (&v["expect"], plan(&d)) {
            (Value::String(s), Err(_)) if s == "refused" => {}
            (w, Ok(p)) if w.is_object() => {
                let ops: Vec<(String, String)> = p.ops.iter().map(|o| (o.name.clone(), o.right.clone())).collect();
                let want: Vec<(String, String)> = serde_json::from_value(w["ops"].clone()).unwrap();
                assert_eq!(ops, want, "{name}");
                assert_eq!(p.budget, w["budget"].as_str().unwrap(), "{name}");
                assert!(ce_net_proto::ces1::check_manifest(&p.budget).is_ok(), "{name}: C1.1");
                assert_eq!(serde_json::to_value(&p.egress_to_grant).unwrap(), w["egress_to_grant"], "{name}");
            }
            (w, g) => panic!("{name}: want {w}, got {g:?}"),
        }
    }
}
