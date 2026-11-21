//! CES-3 conformance vectors (docs/standards/CES-3-observability.md section 5).
use ce_net_proto::ces1::check_manifest;
use ce_net_proto::ces3::{CellStat, Trace, filter_rows, gate_events, pass_on, rank};
use serde_json::Value;

fn load(name: &str) -> Vec<Value> {
    let p = format!("{}/tests/ces3/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn rows(v: &Value) -> Vec<CellStat> {
    v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let mut s: CellStat = serde_json::from_value(r.clone()).unwrap();
            if let Some(t) = v["budget"][&s.cell].as_str() {
                s.budget = check_manifest(t).unwrap().unwrap();
            }
            s
        })
        .collect()
}

#[test]
fn ranked() {
    for v in load("rows.json") {
        let name = v["name"].as_str().unwrap();
        let got = rank(&rows(&v));
        let want = v["expect"].as_array().unwrap();
        assert_eq!(got.len(), want.len(), "{name}");
        for (g, w) in got.iter().zip(want) {
            assert_eq!(g.cell, w["cell"].as_str().unwrap(), "{name}: order");
            assert!((g.excess - w["excess"].as_f64().unwrap()).abs() < 5e-4, "{name} {}: excess {}", g.cell, g.excess);
            let over: Vec<String> = serde_json::from_value(w["over"].clone()).unwrap();
            assert_eq!(g.over, over, "{name} {}", g.cell);
        }
    }
}

#[test]
fn filtered() {
    for v in load("filter.json") {
        let name = v["name"].as_str().unwrap();
        let rights: Vec<String> = serde_json::from_value(v["rights"].clone()).unwrap();
        let rs = rows(&v);
        let got: Vec<&str> = filter_rows(v["caller"].as_str().unwrap(), &rights, &rs).iter().map(|s| s.cell.as_str()).collect();
        let want: Vec<String> = serde_json::from_value(v["expect"].clone()).unwrap();
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn events() {
    for v in load("events.json") {
        let t: Vec<u64> = serde_json::from_value(v["times_ms"].clone()).unwrap();
        let want: Vec<(u64, u64)> = serde_json::from_value(v["expect"].clone()).unwrap();
        assert_eq!(gate_events(&t), want, "{}", v["name"]);
    }
}

#[test]
fn hops() {
    for v in load("hops.json") {
        let t: Trace = serde_json::from_value(v["trace"].clone()).unwrap();
        let got = pass_on(&t, v["now_ms"].as_u64().unwrap());
        match &v["expect"] {
            Value::String(s) => assert_eq!(serde_json::to_value(got.unwrap_err()).unwrap(), Value::String(s.clone()), "{}", v["name"]),
            w => assert_eq!(got.unwrap(), serde_json::from_value::<Trace>(w.clone()).unwrap(), "{}", v["name"]),
        }
    }
}
