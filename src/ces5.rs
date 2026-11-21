//! CES-5 v0.1, run records and metering receipts (docs/standards/CES-5-run-records.md).
//!
//! - [`canonical`] and [`record_hash`]: SHA-256 over the record's canonical JSON (keys sorted, no whitespace).
//! - [`sign`], [`verify`]: Ed25519 over the hash, provider and caller.
//! - [`check_chain`]: C5.1 to C5.3 over one caller and provider chain.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Rule 3: countersign or dispute within this long after `end_ms`.
pub const DISPUTE_WINDOW_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Meter {
    pub cpu_usec: u64,
    pub mem_peak: u64,
    pub mem_byte_seconds: u64,
    pub io_bytes: u64,
    pub egress_bytes: u64,
    pub wall_ms: u64,
    pub calls: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub v: u32,
    pub image_digest: String,
    pub contract_hash: String,
    pub request_hash: String,
    pub answer_hash: String,
    pub class: String,
    pub meter: Meter,
    pub start_ms: u64,
    pub end_ms: u64,
    pub caller: String,
    pub provider: String,
    pub cap_chain_hash: String,
    pub parent: String,
    pub evidence: String,
}

/// A record with its signatures (hex). `caller_sig` empty: not countersigned yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub record: RunRecord,
    pub provider_sig: String,
    #[serde(default)]
    pub caller_sig: String,
}

fn canon(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                canon(&m[*k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canon(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Canonical JSON: keys sorted at every level, no whitespace.
pub fn canonical(r: &RunRecord) -> String {
    let mut s = String::new();
    canon(&serde_json::to_value(r).unwrap_or(Value::Null), &mut s);
    s
}

pub fn record_hash(r: &RunRecord) -> String {
    hex::encode(Sha256::digest(canonical(r).as_bytes()))
}

/// The public key (hex) of a 32-byte seed.
pub fn public_of(seed: &[u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// Sign a record's hash with a seed; hex signature.
pub fn sign(seed: &[u8; 32], r: &RunRecord) -> String {
    hex::encode(SigningKey::from_bytes(seed).sign(record_hash(r).as_bytes()).to_bytes())
}

/// Does `sig_hex` verify over the record's hash with `pub_hex`?
pub fn verify(pub_hex: &str, r: &RunRecord, sig_hex: &str) -> bool {
    let (Ok(p), Ok(s)) = (hex::decode(pub_hex), hex::decode(sig_hex)) else { return false };
    let (Ok(p), Ok(s)): (Result<[u8; 32], _>, Result<[u8; 64], _>) = (p.try_into(), s.try_into()) else { return false };
    let Ok(k) = VerifyingKey::from_bytes(&p) else { return false };
    k.verify(record_hash(r).as_bytes(), &Signature::from_bytes(&s)).is_ok()
}

/// Rule 6 (C5.3).
pub fn consistent(r: &RunRecord) -> Result<(), String> {
    if r.end_ms < r.start_ms {
        return Err("end_ms before start_ms".into());
    }
    if r.meter.wall_ms > r.end_ms - r.start_ms + 1000 {
        return Err(format!("wall_ms {} is longer than the run {} ms", r.meter.wall_ms, r.end_ms - r.start_ms));
    }
    if !matches!(r.class.as_str(), "W" | "I1" | "I2" | "I3") {
        return Err(format!("class {}", r.class));
    }
    Ok(())
}

/// One failed check, with the index of the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub check: String,
    pub index: usize,
    pub msg: String,
}

/// C5.1 to C5.3 over one chain in order. `need_caller`: countersignatures are required (rule 3, inside the window).
pub fn check_chain(rs: &[Signed], need_caller: bool) -> Vec<Finding> {
    let mut out = vec![];
    let f = |check: &str, index, msg: String| Finding { check: check.into(), index, msg };
    let mut prev = ZERO.to_string();
    let mut parents = std::collections::HashSet::new();
    for (i, s) in rs.iter().enumerate() {
        let r = &s.record;
        if !parents.insert(r.parent.clone()) {
            out.push(f("C5.1", i, format!("a second record with parent {}: a fork", r.parent)));
        } else if r.parent != prev {
            out.push(f("C5.1", i, format!("parent {} is not the previous record {prev}", r.parent)));
        }
        if !verify(&r.provider, r, &s.provider_sig) {
            out.push(f("C5.2", i, "provider_sig does not verify".into()));
        }
        if (need_caller || !s.caller_sig.is_empty()) && !verify(&r.caller, r, &s.caller_sig) {
            out.push(f("C5.2", i, "caller_sig does not verify".into()));
        }
        if let Err(e) = consistent(r) {
            out.push(f("C5.3", i, e));
        }
        prev = record_hash(r);
    }
    out
}

/// Rule 3 and 4: is this record settled-countable at `now_ms`? Countersigned, or past its window undisputed.
pub fn accepted(s: &Signed, disputed: bool, now_ms: u64) -> bool {
    !disputed && (!s.caller_sig.is_empty() || now_ms > s.record.end_ms.saturating_add(DISPUTE_WINDOW_MS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_sorts_keys() {
        let m = Meter { calls: 1, ..Meter::default() };
        let r = RunRecord { v: 1, image_digest: "a".into(), contract_hash: "b".into(), request_hash: "c".into(), answer_hash: "d".into(), class: "W".into(), meter: m, start_ms: 1, end_ms: 2, caller: "e".into(), provider: "f".into(), cap_chain_hash: "g".into(), parent: ZERO.into(), evidence: "none".into() };
        let c = canonical(&r);
        assert!(c.starts_with("{\"answer_hash\":\"d\",\"caller\":\"e\",\"cap_chain_hash\":\"g\",\"class\":\"W\",\"contract_hash\":\"b\","), "{c}");
        assert!(c.contains("\"meter\":{\"calls\":1,\"cpu_usec\":0,"));
    }
}
