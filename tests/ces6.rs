//! CES-6 conformance vectors (docs/standards/CES-6-market.md section 5).
use ce_net_proto::ces6::{Entry, Need, Offer, Spend, SpendError, find, net};
use serde_json::Value;

fn load(name: &str) -> Vec<Value> {
    serde_json::from_str(&std::fs::read_to_string(format!("{}/tests/ces6/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
}

#[test]
fn spend() {
    for v in load("spend.json") {
        let name = v["name"].as_str().unwrap();
        let mut s = Spend::root(v["root"].as_u64().unwrap());
        for (i, (step, want)) in v["steps"].as_array().unwrap().iter().zip(v["expect"].as_array().unwrap()).enumerate() {
            let r = if let Some(n) = step["charge"].as_u64() {
                s.charge(n)
            } else if let Some(n) = step["delegate"].as_u64() {
                s.delegate(n)
            } else {
                s.pop();
                Ok(())
            };
            match (want, r) {
                (Value::String(e), Err(got)) => assert_eq!(e, if got == SpendError::Widen { "widen" } else { "no_spend" }, "{name} step {i}"),
                (Value::Array(left), Ok(())) => {
                    let got: Vec<u64> = s.links.iter().map(|l| l.left()).collect();
                    let want: Vec<u64> = left.iter().map(|x| x.as_u64().unwrap()).collect();
                    assert_eq!(got, want, "{name} step {i}");
                }
                (w, r) => panic!("{name} step {i}: want {w}, got {r:?}"),
            }
        }
    }
}

#[test]
fn finds() {
    for v in load("find.json") {
        let offers: Vec<Offer> = serde_json::from_value(v["offers"].clone()).unwrap();
        let need: Need = serde_json::from_value(v["need"].clone()).unwrap();
        let got: Vec<&str> = find(&offers, &need, v["now_ms"].as_u64().unwrap()).iter().map(|o| o.id.as_str()).collect();
        let want: Vec<String> = serde_json::from_value(v["expect"].clone()).unwrap();
        assert_eq!(got, want, "{}", v["name"]);
    }
}

#[test]
fn nets() {
    for v in load("net.json") {
        let e: Vec<Entry> = serde_json::from_value(v["entries"].clone()).unwrap();
        let got = net(&e, v["caller"].as_str().unwrap(), v["provider"].as_str().unwrap(), v["from_ms"].as_u64().unwrap(), v["to_ms"].as_u64().unwrap());
        assert_eq!(got, v["expect"].as_u64().unwrap(), "{}", v["name"]);
    }
}
