//! Conditions (`docs/CAPABILITY-PROGRAMS.md` section 4.1): caveats that demand something be
//! proved at each use, on top of the chain itself.
//!
//! - `Requires`: something was done first, attested by a witness ([`Requirement`], [`Attestation`]).
//! - `CoSign`: a named principal signs the exact request of every use ([`CoSigner`], [`UseRequest`]).
//! - `Via`: the call arrives through a broker carrying the broker's signed approval ([`Party`]).
//!
//! This module holds the types, the bytes each party signs (one domain per statement, so no
//! signature made for one verifies as another or as a link) and the canonical form. Narrowing along
//! a chain and the checks at use belong to mint and verify. Every list is a conjunction: each entry
//! must be satisfied, and a child link may add entries but never drop one.

use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::types::{Key, Sig};
use crate::program::{Hash, sorted_unique_by_encoding};
use crate::{Error, Result};

/// Domain of [`attest_bytes`]: what a witness signs.
pub const ATTEST_DOMAIN: &[u8] = b"ce-cap-v3-attest";
/// Domain of [`cosign_bytes`]: what a co-signer signs.
pub const COSIGN_DOMAIN: &[u8] = b"ce-cap-v3-cosign";
/// Domain of [`via_bytes`]: what a broker signs.
pub const VIA_DOMAIN: &[u8] = b"ce-cap-v3-via";
/// Domain of [`request_id`]: names one use for replay refusal.
pub const REQUEST_DOMAIN: &[u8] = b"ce-cap-v3-request";
/// Entries per condition list.
pub const MAX_CONDITIONS: usize = 16;
/// Bytes per string or opaque value inside a condition.
pub const MAX_COND_STR: usize = 256;
/// Proofs presented with one use.
pub const MAX_PROOFS: usize = 64;

/// Who must vouch: a fixed key, or whichever key the executing node holds for a cell api.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Party {
    /// 0: exactly this principal.
    Key(Key),
    /// 1: the cell serving this api (e.g. `"printer3d.gate"`). The executing node resolves the api
    /// to the keys it trusts for it; a verifier that cannot resolve it refuses.
    Cell(String),
}

/// A typed predicate about something done. In a [`Requirement`] it is what must be proved; in an
/// [`Attestation`] it is what the witness states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Claim {
    /// 0: the subject has read `thread` of `source` (e.g. `"wechat"`) through message `upto_msg`.
    /// In a requirement `None` means "through whatever was the newest message when attested"
    /// (bound it with `fresh_within_s`); an attestation always names the message.
    ReadThrough { source: String, thread: String, upto_msg: Option<String> },
    /// 1: a cell-defined fact, `name` = `"<api>.<name>"`, `value` matched byte for byte.
    Fact { name: String, value: Vec<u8> },
}

impl Claim {
    /// Does the witness's `stated` claim prove this required claim? Same variant and fields; a
    /// required `upto_msg: None` accepts any message, `Some(m)` exactly `m`.
    pub fn proved_by(&self, stated: &Claim) -> bool {
        match (self, stated) {
            (
                Claim::ReadThrough { source, thread, upto_msg },
                Claim::ReadThrough { source: s, thread: t, upto_msg: Some(m) },
            ) => source == s && thread == t && upto_msg.as_ref().is_none_or(|want| want == m),
            (Claim::Fact { name, value }, Claim::Fact { name: n, value: v }) => name == n && value == v,
            _ => false,
        }
    }

    fn check(&self) -> Result<(), String> {
        match self {
            Claim::ReadThrough { source, thread, upto_msg } => {
                check_str(source)?;
                check_str(thread)?;
                upto_msg.as_ref().map_or(Ok(()), |m| check_str(m))
            }
            Claim::Fact { name, value } => {
                check_str(name)?;
                if value.len() > MAX_COND_STR { Err("condition value too long".into()) } else { Ok(()) }
            }
        }
    }
}

/// One `Requires` entry: proof, signed by `witness`, that `claim` holds of the requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirement {
    pub witness: Party,
    pub claim: Claim,
    /// `Some(n)`, `n >= 1`: the attestation is at most `n` seconds old at use. `None`: any age.
    pub fresh_within_s: Option<u64>,
}

/// When a co-signature is due.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoSignPer {
    /// 0: every use carries its own signature over that use's [`UseRequest`].
    Use,
}

/// One `CoSign` entry: `by` (e.g. a system's guardian agent) signs each use. What it checks before
/// signing (an auth code, a human's yes) is its own business; without its signature nothing runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoSigner {
    pub by: Key,
    pub per: CoSignPer,
}

/// What a witness states: `subject` did `claim`, observed at `at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBody {
    pub witness: Key,
    /// Who did it; at use this must be the requester.
    pub subject: Key,
    pub claim: Claim,
    /// Unix seconds.
    pub at: u64,
}

/// An [`AttestationBody`] and the witness's signature over [`attest_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub body: AttestationBody,
    pub sig: Sig,
}

/// The exact request of one use: what a co-signer and a broker sign. It pins the chain (`leaf`),
/// the executing node, the requester, the action and the request body, so a signature made for
/// one call approves no other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseRequest {
    /// `cap_id` of the leaf link the requester wields.
    pub leaf: Hash,
    /// The executing node.
    pub node: [u8; 32],
    pub requester: Key,
    /// The action being authorized, as passed to `authorize_v3`.
    pub action: String,
    /// SHA-256 of the request body, as the called cell defines its bytes.
    pub body: Hash,
    /// Unix seconds the request was made.
    pub at: u64,
    /// Chosen by the requester; with the rest it makes [`request_id`] unique per use.
    pub nonce: u64,
}

/// One proof presented with a use. Proofs travel beside the token and are not part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proof {
    /// 0: for a `Requires` entry.
    Attested(Attestation),
    /// 1: for a `CoSign` entry: `by` signed [`cosign_bytes`] of this use.
    CoSigned { by: Key, sig: Sig },
    /// 2: for a `Via` entry: `broker` signed [`via_bytes`] of this use.
    Brokered { broker: Key, sig: Sig },
}

fn tagged<T: Serialize>(domain: &[u8], v: &T) -> Vec<u8> {
    bincode::serialize(&(domain, v)).expect("bincode of a v3 condition statement to a Vec is infallible")
}

/// `len(16) || "ce-cap-v3-attest" || AttestationBody`.
pub fn attest_bytes(b: &AttestationBody) -> Vec<u8> {
    tagged(ATTEST_DOMAIN, b)
}

/// `len(16) || "ce-cap-v3-cosign" || UseRequest`.
pub fn cosign_bytes(r: &UseRequest) -> Vec<u8> {
    tagged(COSIGN_DOMAIN, r)
}

/// `len(13) || "ce-cap-v3-via" || UseRequest`.
pub fn via_bytes(r: &UseRequest) -> Vec<u8> {
    tagged(VIA_DOMAIN, r)
}

/// `SHA-256(len(17) || "ce-cap-v3-request" || UseRequest)`: a node refuses an id it has executed.
pub fn request_id(r: &UseRequest) -> Hash {
    Sha256::digest(tagged(REQUEST_DOMAIN, r)).into()
}

fn check_str(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_COND_STR { Err(format!("condition strings must hold 1..={MAX_COND_STR} bytes")) } else { Ok(()) }
}

fn check_party(p: &Party) -> Result<(), String> {
    match p {
        Party::Key(k) if !k.canonical() => Err("malformed key".into()),
        Party::Key(_) => Ok(()),
        Party::Cell(api) => check_str(api),
    }
}

fn check_list<T: Serialize>(name: &str, v: &[T]) -> Result<(), String> {
    if v.is_empty() || v.len() > MAX_CONDITIONS || !sorted_unique_by_encoding(v) {
        return Err(format!("{name} must hold 1..={MAX_CONDITIONS} entries, sorted by encoding, unique"));
    }
    Ok(())
}

/// Canonical `Requires`: a bounded, sorted, unique, non-empty list; one entry per
/// `(witness, claim)` (so freshness has one value); `fresh_within_s` is never `Some(0)`.
pub fn check_requires(rs: &[Requirement]) -> Result<(), String> {
    check_list("Requires", rs)?;
    for r in rs {
        check_party(&r.witness)?;
        r.claim.check()?;
        if r.fresh_within_s == Some(0) {
            return Err("Requires.fresh_within_s must be >= 1".into());
        }
    }
    if rs.windows(2).any(|w| w[0].witness == w[1].witness && w[0].claim == w[1].claim) {
        return Err("Requires holds one entry per witness and claim".into());
    }
    Ok(())
}

/// Canonical `CoSign`: a bounded, sorted, unique, non-empty list of well-formed keys.
pub fn check_cosign(cs: &[CoSigner]) -> Result<(), String> {
    check_list("CoSign", cs)?;
    if cs.iter().all(|c| c.by.canonical()) { Ok(()) } else { Err("malformed key".into()) }
}

/// Canonical `Via`: a bounded, sorted, unique, non-empty list of brokers.
pub fn check_via(bs: &[Party]) -> Result<(), String> {
    check_list("Via", bs)?;
    bs.iter().try_for_each(check_party)
}

impl UseRequest {
    /// Well-formed: a real key and a non-empty action.
    pub fn check(&self) -> Result<(), String> {
        if !self.requester.canonical() {
            return Err("malformed key".into());
        }
        if self.action.is_empty() { Err("use request names no action".into()) } else { Ok(()) }
    }
}

impl Proof {
    /// Well-formed: real keys, a low-S signature, and an attestation that states a concrete claim
    /// (a `ReadThrough` names its message).
    pub fn check(&self) -> Result<(), String> {
        let (keys, sig): (&[&Key], &Sig) = match self {
            Proof::Attested(a) => {
                a.body.claim.check()?;
                if matches!(a.body.claim, Claim::ReadThrough { upto_msg: None, .. }) {
                    return Err("an attestation must name the message read through".into());
                }
                (&[&a.body.witness, &a.body.subject], &a.sig)
            }
            Proof::CoSigned { by, sig } => (&[by], sig),
            Proof::Brokered { broker, sig } => (&[broker], sig),
        };
        if !keys.iter().all(|k| k.canonical()) {
            return Err("malformed key".into());
        }
        if sig.canonical() { Ok(()) } else { Err("P-256 signature is not low-S".into()) }
    }
}

/// Canonical bytes of the proofs of one use: bincode of `seq<Proof>`.
pub fn encode_proofs(ps: &[Proof]) -> Vec<u8> {
    bincode::serialize(ps).expect("bincode of proofs to a Vec is infallible")
}

/// Strict decode of [`encode_proofs`]: no trailing bytes, no unknown variant, re-encoding to the
/// same bytes, at most [`MAX_PROOFS`], every proof well-formed. Any failure is a refusal.
pub fn decode_proofs(b: &[u8]) -> Result<Vec<Proof>> {
    let ps: Vec<Proof> = super::strict().deserialize(b).map_err(|e| Error(format!("malformed proofs: {e}")))?;
    if encode_proofs(&ps) != b {
        return Err(Error("proofs are not canonical".into()));
    }
    if ps.len() > MAX_PROOFS {
        return Err(Error(format!("more than {MAX_PROOFS} proofs")));
    }
    for (i, p) in ps.iter().enumerate() {
        p.check().map_err(|why| Error(format!("proof {i}: not canonical ({why})")))?;
    }
    Ok(ps)
}
