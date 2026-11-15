//! CAL, the cell auth language (`docs/CAL.md`): a small readable text that compiles to v3 links
//! and programs (`docs/CAPABILITY-PROGRAMS.md`) and decompiles back.
//!
//! ```text
//! person:leif grants person:friend {
//!   on node:box-1
//!   until 2026-12-01
//!   may grant proc.spawn:run, net.egress:connect to anyone depth 2
//!   egress api.example.org:443
//!   limit net.egress.bytes_out 10MB
//! }
//! ```
//!
//! - [`parse`] text to a syntax tree ([`ast::File`]); [`print::print`] writes it back canonically.
//! - [`compile()`] pins every ref through a [`Resolver`] (keys, full node ids, content hashes) and
//!   builds the unsigned links and program bodies; it refuses an ambiguous or unpinned ref with
//!   a message and a suggestion, and a link the verifier would refuse.
//! - [`Draft`] holds the compiled links until each issuer signs its own ([`Draft::sign`]).
//! - [`decompile()`] turns a token back into CAL; [`explain()`] says in plain English what a chain
//!   allows and requires, link by link; [`check()`] runs the verifier for one request and says
//!   why it is refused.
//!
//! Every name in a CAL file is a ce-ref ([`refs`]); the compiled link stores only pinned forms,
//! so a link means the same thing wherever it is read.

pub mod api;
pub mod ast;
pub mod check;
pub mod compile;
pub mod decompile;
pub mod explain;
pub mod parse;
pub mod print;
pub mod refs;
pub mod units;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

pub use check::{CheckRequest, Verdict, check, check_content};
pub use compile::{Compiled, Options, compile};
pub use decompile::decompile;
pub use explain::explain;
pub use parse::parse;
pub use refs::{NoRefs, RefBook, Resolver};

use crate::program::{Hash, NodeKey, Program};
use crate::v3::sign::Signer;
use crate::v3::{CapabilityV3, Key, Link, Sig, TokenV3};

/// A CAL error: the line it is on (0 when it is not about one line), what is wrong, and when
/// one is known, what to write instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalError {
    pub line: usize,
    pub msg: String,
    pub hint: Option<String>,
}

impl CalError {
    pub fn at(line: usize, msg: impl Into<String>) -> CalError {
        CalError { line, msg: msg.into(), hint: None }
    }
    pub fn hint(mut self, h: impl Into<String>) -> CalError {
        self.hint = Some(h.into());
        self
    }
}

impl std::fmt::Display for CalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line > 0 {
            write!(f, "line {}: ", self.line)?;
        }
        f.write_str(&self.msg)?;
        if let Some(h) = &self.hint {
            write!(f, "\n  suggestion: {h}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CalError {}

/// Readable names for pinned values, shown beside them by `explain` and `decompile`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Labels {
    /// `fmt_key(key)` -> its ref (`person:leif`).
    pub keys: BTreeMap<String, String>,
    pub nodes: BTreeMap<NodeKey, String>,
    /// Content hash -> the readable file ref (`repo:huey-scripts/run.py@3f2a1c`).
    pub files: BTreeMap<Hash, String>,
    /// Content hash -> its portable ref (`ce-ref://repo/<id>/<path>`), when it came from a repo.
    pub portable: BTreeMap<Hash, String>,
    /// Program id -> its name in the source.
    pub programs: BTreeMap<Hash, String>,
}

impl Labels {
    /// The name of `k`, if one is known.
    pub fn key(&self, k: &Key) -> Option<&str> {
        self.keys.get(&refs::fmt_key(k)).map(String::as_str)
    }

    /// Fill in, from `r`'s reverse lookups, a name for every key, node and file hash of `t`
    /// that has none yet.
    pub fn learn(&mut self, links: &[CapabilityV3], programs: &[Program], r: &dyn Resolver) {
        let mut keys = Vec::new();
        let mut nodes = Vec::new();
        let mut hashes = Vec::new();
        for c in links {
            keys.push(c.issuer);
            keys.push(c.audience);
            if let Some(crate::v3::Delegate { audience: crate::v3::AudienceSet::Keys(ks), .. }) = &c.delegate {
                keys.extend(ks.iter().copied());
            }
            for cv in &c.ext {
                match cv {
                    crate::v3::Caveat::CoSign(cs) => keys.extend(cs.iter().map(|x| x.by)),
                    crate::v3::Caveat::Via(ps) => keys.extend(ps.iter().filter_map(party_key)),
                    crate::v3::Caveat::Requires(rs) => keys.extend(rs.iter().filter_map(|x| party_key(&x.witness))),
                    _ => {}
                }
            }
            nodes.extend(resource_nodes(&c.resource));
        }
        for p in programs {
            for s in &p.steps {
                use crate::program::{Exe, Step};
                match s {
                    Step::Install { on, sha256, .. } => {
                        nodes.push(*on);
                        hashes.push(*sha256);
                    }
                    Step::InstallCell { on, .. } | Step::Call { on, .. } => nodes.push(*on),
                    Step::Run { on, exe, .. } => {
                        nodes.extend(resource_nodes(on));
                        if let Exe::Path { sha256, .. } = exe {
                            hashes.push(*sha256);
                        }
                    }
                    Step::Sub { .. } => {}
                }
            }
        }
        for k in keys {
            let id = refs::fmt_key(&k);
            if !self.keys.contains_key(&id) {
                if let Some(n) = r.name_of_key(&k) {
                    self.keys.insert(id, n);
                }
            }
        }
        for n in nodes {
            if !self.nodes.contains_key(&n) {
                if let Some(name) = r.name_of_node(&n) {
                    self.nodes.insert(n, name);
                }
            }
        }
        for h in hashes {
            if !self.files.contains_key(&h) {
                if let Some(name) = r.name_of_file(&h) {
                    self.files.insert(h, name);
                }
            }
        }
    }
}

fn party_key(p: &crate::v3::Party) -> Option<Key> {
    match p {
        crate::v3::Party::Key(k) => Some(*k),
        crate::v3::Party::Cell(_) => None,
    }
}

fn resource_nodes(r: &crate::program::ResourceV3) -> Vec<NodeKey> {
    match r {
        crate::program::ResourceV3::Node(n) => vec![*n],
        crate::program::ResourceV3::Nodes(ns) => ns.clone(),
        _ => vec![],
    }
}

/// Compiled links waiting for their signatures: each issuer signs its own link, on its own
/// machine ([`Draft::sign`]); once every link is signed, [`Draft::token`] is the v3 token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub links: Vec<(CapabilityV3, Option<Sig>)>,
    pub programs: Vec<Program>,
}

fn strict() -> impl bincode::Options {
    use bincode::Options;
    bincode::DefaultOptions::new().with_fixint_encoding().with_little_endian().reject_trailing_bytes().with_limit(crate::v3::MAX_TOKEN as u64)
}

pub(crate) fn decode_exact<T: serde::de::DeserializeOwned + serde::Serialize>(b: &[u8], what: &str) -> Result<T, String> {
    use bincode::Options;
    let v: T = strict().deserialize(b).map_err(|e| format!("{what}: {e}"))?;
    if bincode::serialize(&v).map_err(|e| e.to_string())? != b {
        return Err(format!("{what}: not canonical"));
    }
    Ok(v)
}

impl Draft {
    /// Sign every unsigned link whose issuer is `signer`'s key; answers how many were signed.
    pub fn sign(&mut self, signer: &Signer) -> usize {
        let me = signer.key();
        let mut n = 0;
        for (cap, sig) in &mut self.links {
            if sig.is_none() && cap.issuer == me {
                *sig = Some(signer.sign(cap));
                n += 1;
            }
        }
        n
    }

    /// The issuers whose signature is still missing, in link order.
    pub fn unsigned(&self) -> Vec<Key> {
        self.links.iter().filter(|(_, s)| s.is_none()).map(|(c, _)| c.issuer).collect()
    }

    /// The token, once every link is signed.
    pub fn token(&self) -> Result<TokenV3, String> {
        let mut links = Vec::new();
        for (i, (cap, sig)) in self.links.iter().enumerate() {
            let Some(sig) = sig else { return Err(format!("link {i} is not signed yet (its issuer is {})", refs::fmt_key(&cap.issuer))) };
            links.push(Link::V3 { cap: cap.clone(), sig: sig.clone() });
        }
        Ok(TokenV3 { links, programs: self.programs.clone() })
    }

    /// The draft as JSON: `{"cal_draft": 1, "links": [{"cap": hex, "sig": hex|null, "id": hex}], "programs": [hex]}`.
    pub fn to_json(&self) -> serde_json::Value {
        let links: Vec<_> = self
            .links
            .iter()
            .map(|(c, s)| {
                serde_json::json!({
                    "id": hex::encode(crate::v3::cap_id(c)),
                    "issuer": refs::fmt_key(&c.issuer),
                    "cap": hex::encode(bincode::serialize(c).expect("bincode to a Vec is infallible")),
                    "sig": s.as_ref().map(|s| hex::encode(bincode::serialize(s).expect("bincode to a Vec is infallible"))),
                })
            })
            .collect();
        let programs: Vec<_> = self.programs.iter().map(|p| serde_json::json!(hex::encode(p.encode()))).collect();
        serde_json::json!({ "cal_draft": 1, "links": links, "programs": programs })
    }

    pub fn from_json(v: &serde_json::Value) -> Result<Draft, String> {
        if v.get("cal_draft").and_then(|x| x.as_u64()) != Some(1) {
            return Err("not a CAL draft (no \"cal_draft\": 1)".into());
        }
        let hexb = |x: &serde_json::Value, what: &str| -> Result<Vec<u8>, String> {
            hex::decode(x.as_str().ok_or(format!("{what} is not a string"))?).map_err(|_| format!("{what} is not hex"))
        };
        let mut links = Vec::new();
        for (i, l) in v.get("links").and_then(|x| x.as_array()).ok_or("draft has no links")?.iter().enumerate() {
            let cap: CapabilityV3 = decode_exact(&hexb(&l["cap"], "cap")?, &format!("link {i}"))?;
            let sig = match &l["sig"] {
                serde_json::Value::Null => None,
                s => Some(decode_exact::<Sig>(&hexb(s, "sig")?, &format!("link {i} signature"))?),
            };
            links.push((cap, sig));
        }
        let mut programs = Vec::new();
        for p in v.get("programs").and_then(|x| x.as_array()).cloned().unwrap_or_default() {
            programs.push(Program::decode(&hexb(&p, "program")?)?);
        }
        Ok(Draft { links, programs })
    }
}

/// A signer from a key file's text: `ed25519:<64 hex seed>` or `p256:<64 hex scalar>`.
pub fn signer_from_text(s: &str) -> Result<Signer, String> {
    let s = s.trim();
    let (kind, h) = s.split_once(':').ok_or("a key file holds ed25519:<64 hex> or p256:<64 hex>")?;
    let secret = refs::hex32(h).ok_or("a secret key is 64 lowercase hex digits")?;
    match kind {
        "ed25519" => Ok(Signer::ed25519(&secret)),
        "p256" => Signer::p256(&secret).map_err(|e| e.0),
        _ => Err("a key file holds ed25519:<64 hex> or p256:<64 hex>".into()),
    }
}
