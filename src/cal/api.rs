//! One JSON-in, JSON-out entry point for the language SDKs (`docs/CAL.md` section 8). The
//! TypeScript (wasm) and Python (C ABI) packages are thin wrappers over [`call`], so every SDK
//! gives the same answers as the Rust crate and the `ce-cal` CLI.
//!
//! `call(op, request_json) -> response_json`. Every response is `{"ok": true, ...}` or
//! `{"ok": false, "error": {"line": n, "message": "...", "suggestion": "..."|null}}`.
//!
//! | op | request | response |
//! |---|---|---|
//! | `parse` | `{source}` | `{formatted}` |
//! | `compile` | `{source, refs?, now?, nonces?}` | `{draft, ids, programs}` |
//! | `sign` | `{draft, key}` | `{draft, signed, token}` (`token` null until every link is signed) |
//! | `explain` | `{source \| token \| draft, refs?, now?, nonces?}` | `{text}` |
//! | `decompile` | `{token \| draft, refs?}` | `{source}` |
//! | `verify` | `{token, refs?, node, as, do \| program+step+run?, now?, request?, proofs?, body?, content?}` | `{allowed, reason, why, text}` |
//!
//! `refs` is a ref book (`docs/CAL.md` 3.3) as a JSON object. Hex fields are lowercase hex.
//! `nonces` are the link nonces to use, in order, for links without a `nonce` clause (strings or
//! numbers; the wrappers fill them from the platform's CSPRNG). u64 values may be strings.

use serde_json::{Value, json};

use super::check::{Action, CheckRequest};
use super::{CalError, Draft, Labels, RefBook, Resolver, compile, parse, print};
use crate::v3::{Link, TokenV3, UseRequest, decode_proofs};

fn err(e: CalError) -> Value {
    json!({ "ok": false, "error": { "line": e.line, "message": e.msg, "suggestion": e.hint } })
}

fn fail(msg: impl Into<String>) -> Value {
    err(CalError::at(0, msg))
}

fn u64_of(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn book(req: &Value) -> Result<RefBook, Value> {
    match req.get("refs") {
        None | Some(Value::Null) => Ok(RefBook::default()),
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| fail(format!("refs: {e}"))),
    }
}

fn now_of(req: &Value) -> u64 {
    req.get("now").and_then(u64_of).unwrap_or(0)
}

/// Compile `req.source` with `req.nonces` (or 1, 2, 3... when `allow_counter`).
pub fn compile_req(req: &Value, r: &dyn Resolver, allow_counter: bool) -> Result<super::Compiled, Value> {
    let src = req.get("source").and_then(Value::as_str).ok_or_else(|| fail("missing \"source\""))?;
    let f = parse(src).map_err(err)?;
    let given: Vec<u64> = req.get("nonces").and_then(Value::as_array).map(|a| a.iter().filter_map(u64_of).collect()).unwrap_or_default();
    let mut it = given.into_iter();
    let mut counter = 0u64;
    let mut missing = false;
    let mut next = || match it.next() {
        Some(n) => n,
        None => {
            counter += 1;
            missing = true;
            counter
        }
    };
    let mut o = super::Options { now: now_of(req), nonce: &mut next, lenient: req.get("lenient").and_then(Value::as_bool).unwrap_or(false) };
    let c = compile(&f, r, &mut o).map_err(err)?;
    if missing && !allow_counter {
        return Err(fail("a link has no 'nonce' clause and \"nonces\" ran out: pass one random u64 per such link (nonces name links for revocation)"));
    }
    Ok(c)
}

fn token_of(req: &Value) -> Result<Option<TokenV3>, Value> {
    match req.get("token").and_then(Value::as_str) {
        None => Ok(None),
        Some(h) => TokenV3::from_hex(h).map(Some).map_err(|e| fail(e.0)),
    }
}

fn draft_of(req: &Value) -> Result<Option<Draft>, Value> {
    match req.get("draft") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => Draft::from_json(v).map(Some).map_err(fail),
    }
}

fn caps(t: &TokenV3) -> Result<Vec<crate::v3::CapabilityV3>, Value> {
    t.links.iter().enumerate().map(|(i, l)| match l {
        Link::V3 { cap, .. } => Ok(cap.clone()),
        Link::V1(_) => Err(fail(format!("link {i} is a v1 link: CAL explains v3 links"))),
    }).collect()
}

fn hex_bytes(req: &Value, k: &str) -> Result<Option<Vec<u8>>, Value> {
    match req.get(k).and_then(Value::as_str) {
        None => Ok(None),
        Some(h) => hex::decode(h.trim()).map(Some).map_err(|_| fail(format!("\"{k}\" is not hex"))),
    }
}

/// The program a `verify` request names: a 64-hex id, a unique id prefix, or `prog_<8 hex>`.
pub fn find_program(t: &TokenV3, name: &str) -> Result<crate::program::Hash, String> {
    let pre = name.strip_prefix("program:").or_else(|| name.strip_prefix("prog_")).unwrap_or(name);
    let hits: Vec<_> = t.programs.iter().map(|p| p.id()).filter(|id| hex::encode(id).starts_with(pre)).collect();
    match hits.as_slice() {
        [id] => Ok(*id),
        [] => match super::refs::hex32(pre) {
            Some(id) => Ok(id),
            None => Err(format!("the token carries no program '{name}'")),
        },
        _ => Err(format!("'{name}' matches {} programs: give more of the id", hits.len())),
    }
}

/// Build a `check` request from JSON and run it.
pub fn verify_req(req: &Value, t: &TokenV3, r: &dyn Resolver, labels: &Labels) -> Result<super::Verdict, Value> {
    let s = |k: &str| req.get(k).and_then(Value::as_str);
    let node_ref = super::parse::node_text(s("node").ok_or_else(|| fail("missing \"node\" (node:<name>)"))?).map_err(err)?;
    let node = super::compile::resolve_node(&node_ref, r).map_err(err)?;
    let who = super::parse::principal_text(s("as").ok_or_else(|| fail("missing \"as\" (the requester, e.g. agent:b)"))?).map_err(err)?;
    let requester = super::compile::resolve_principal(&who, r).map_err(err)?;
    let action = match (s("do"), s("program")) {
        (Some(a), None) => Action::Call(a.to_string()),
        (None, Some(p)) => Action::Step {
            program: find_program(t, p).map_err(fail)?,
            run: req.get("run").and_then(u64_of).unwrap_or(1) as u32,
            step: req.get("step").and_then(u64_of).unwrap_or(0) as u32,
        },
        _ => return Err(fail("say what is asked: \"do\": \"<ability>\" for a call, or \"program\" (+ \"step\", \"run\") for a program step")),
    };
    let presented = match hex_bytes(req, "request")? {
        None => None,
        Some(b) => {
            let ur: UseRequest = super::decode_exact(&b, "use request").map_err(fail)?;
            let proofs = match hex_bytes(req, "proofs")? {
                Some(p) => decode_proofs(&p).map_err(|e| fail(e.0))?,
                None => Vec::new(),
            };
            Some((ur, proofs, hex_bytes(req, "body")?.unwrap_or_default()))
        }
    };
    let host = r.name_of_node(&node).or_else(|| (!node_ref.name.is_empty()).then(|| node_ref.name.clone()));
    let cell = |api: &str| r.cell_keys(api);
    let creq = CheckRequest {
        node,
        host,
        tags: req.get("tags").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
        requester,
        action,
        now: req.get("now").and_then(u64_of).unwrap_or_else(unix_now),
        roots: r.roots(),
        cell_keys: &cell,
        presented,
        content: hex_bytes(req, "content")?,
    };
    Ok(super::check(t, &creq, labels))
}

/// The current unix time (0 where the platform has no clock).
pub fn unix_now() -> u64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }
    #[cfg(target_arch = "wasm32")]
    {
        0
    }
}

fn run(op: &str, req: &Value) -> Result<Value, Value> {
    let refs = book(req)?;
    match op {
        "parse" => {
            let src = req.get("source").and_then(Value::as_str).ok_or_else(|| fail("missing \"source\""))?;
            let f = parse(src).map_err(err)?;
            Ok(json!({ "formatted": print::print(&f) }))
        }
        "compile" => {
            let c = compile_req(req, &refs, false)?;
            let ids: Vec<String> = c.links.iter().map(|l| hex::encode(crate::v3::cap_id(l))).collect();
            let programs: Vec<String> = c.programs.iter().map(|p| hex::encode(p.id())).collect();
            Ok(json!({ "draft": c.draft().to_json(), "ids": ids, "programs": programs }))
        }
        "sign" => {
            let mut d = draft_of(req)?.ok_or_else(|| fail("missing \"draft\""))?;
            let key = req.get("key").and_then(Value::as_str).ok_or_else(|| fail("missing \"key\" (ed25519:<64 hex> or p256:<64 hex>)"))?;
            let signer = super::signer_from_text(key).map_err(fail)?;
            let n = d.sign(&signer);
            let token = d.token().ok().map(|t| t.to_hex());
            Ok(json!({ "draft": d.to_json(), "signed": n, "token": token }))
        }
        "explain" => {
            let (links, programs, mut labels) = if req.get("source").is_some() {
                let c = compile_req(req, &refs, true)?;
                (c.links, c.programs, c.labels)
            } else if let Some(t) = token_of(req)? {
                (caps(&t)?, t.programs, Labels::default())
            } else if let Some(d) = draft_of(req)? {
                (d.links.into_iter().map(|x| x.0).collect(), d.programs, Labels::default())
            } else {
                return Err(fail("give \"source\", \"token\" or \"draft\""));
            };
            labels.learn(&links, &programs, &refs);
            Ok(json!({ "text": super::explain(&links, &programs, &labels) }))
        }
        "decompile" => {
            let t = match (token_of(req)?, draft_of(req)?) {
                (Some(t), _) => t,
                (None, Some(d)) => TokenV3 { links: d.links.into_iter().map(|(cap, _)| Link::V3 { cap, sig: crate::v3::Sig::Ed25519([0; 64]) }).collect(), programs: d.programs },
                _ => return Err(fail("give \"token\" or \"draft\"")),
            };
            let mut labels = Labels::default();
            labels.learn(&caps(&t)?, &t.programs, &refs);
            Ok(json!({ "source": super::decompile(&t, &labels).map_err(fail)? }))
        }
        "verify" | "check" => {
            let t = token_of(req)?.ok_or_else(|| fail("missing \"token\""))?;
            let mut labels = Labels::default();
            if let Ok(cs) = caps(&t) {
                labels.learn(&cs, &t.programs, &refs);
            }
            let v = verify_req(req, &t, &refs, &labels)?;
            Ok(json!({ "allowed": v.allowed, "reason": v.reason, "why": v.why, "text": v.text() }))
        }
        _ => Err(fail(format!("unknown op '{op}' (parse, compile, sign, explain, decompile, verify)"))),
    }
}

/// The SDK entry point: `op` and a JSON request, a JSON response.
pub fn call(op: &str, request: &str) -> String {
    let out = match serde_json::from_str::<Value>(request) {
        Err(e) => fail(format!("request is not JSON: {e}")),
        Ok(req) => match run(op, &req) {
            Ok(mut v) => {
                v["ok"] = json!(true);
                v
            }
            Err(e) => e,
        },
    };
    out.to_string()
}
