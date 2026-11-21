//! CES-5 conformance vectors (docs/standards/CES-5-run-records.md section 4).
use ce_net_proto::ces5::{RunRecord, Signed, ZERO, canonical, check_chain, public_of, record_hash, sign};
use serde_json::Value;

fn file() -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{}/tests/ces5/records.json", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
}

#[test]
fn golden_hash_matches_the_python_reference() {
    let f = file();
    let r: RunRecord = serde_json::from_value(f["golden"]["record"].clone()).unwrap();
    assert_eq!(canonical(&r), f["golden"]["canonical"].as_str().unwrap());
    assert_eq!(record_hash(&r), f["golden"]["hash"].as_str().unwrap());
}

#[test]
fn chains() {
    let f = file();
    let (ps, cs) = ([1u8; 32], [2u8; 32]);
    let base: RunRecord = serde_json::from_value(f["golden"]["record"].clone()).unwrap();
    for c in f["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let mut chain: Vec<Signed> = vec![];
        let mut prev = ZERO.to_string();
        for i in 0..c["n"].as_u64().unwrap() {
            let mut r = base.clone();
            r.start_ms += i * 1000;
            r.end_ms += i * 1000;
            r.caller = public_of(&cs);
            r.provider = public_of(&ps);
            r.parent = prev.clone();
            for t in c["tamper"].as_array().unwrap().iter().filter(|t| t["index"].as_u64() == Some(i)) {
                match t["op"].as_str().unwrap() {
                    "parent_zero" => r.parent = ZERO.into(),
                    "wall_ms_100000" => r.meter.wall_ms = 100_000,
                    _ => {}
                }
            }
            prev = record_hash(&r);
            let mut s = Signed { provider_sig: sign(&ps, &r), caller_sig: sign(&cs, &r), record: r };
            for t in c["tamper"].as_array().unwrap().iter().filter(|t| t["index"].as_u64() == Some(i)) {
                match t["op"].as_str().unwrap() {
                    "drop_caller_sig" => s.caller_sig.clear(),
                    "provider_signs_with_caller_key" => s.provider_sig = sign(&cs, &s.record),
                    "edit_meter_after_sign" => s.record.meter.cpu_usec += 1,
                    _ => {}
                }
            }
            chain.push(s);
        }
        let got: Vec<(String, usize)> = check_chain(&chain, c["need_caller"].as_bool().unwrap()).into_iter().map(|f| (f.check, f.index)).collect();
        let mut want: Vec<(String, usize)> = c["expect"].as_array().unwrap().iter().map(|e| (e["check"].as_str().unwrap().to_string(), e["index"].as_u64().unwrap() as usize)).collect();
        want.sort();
        let mut g = got.clone();
        g.sort();
        g.dedup();
        assert_eq!(g, want, "{name}: {got:?}");
    }
}
