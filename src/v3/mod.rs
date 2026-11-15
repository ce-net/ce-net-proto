//! Token format v3 (`docs/CAPABILITY-PROGRAMS.md`): recursive delegation, typed caveats, programs.
//!
//! This module holds the types ([`types`]), the signed bytes ([`cap_bytes`], [`cap_id`]), the wire
//! form ([`TokenV3`]: magic `CEC3`, links, program bodies) and the canonical-form rules of section
//! 3.4 ([`canon`]). Decoding is strict, unlike v1: trailing bytes, unknown variants, invalid bools
//! and non-canonical values are refused. [`mint`] signs root and attenuated links ([`sign`], Ed25519
//! and P-256) and refuses any child wider than its parent ([`narrow`]). [`verify`] checks a chain
//! (section 5.1) and authorizes one request at one node (section 5.2), WebAuthn included
//! ([`webauthn`]). [`uses`] is the node-local burn log of section 7 behind `authorize_v3`'s
//! `burn` callback.
//!
//! Nothing here touches v1: a byte string without the magic is not a v3 token ([`is_v3`]) and is
//! verified by the v1 code alone.

pub mod canon;
pub mod mint;
pub mod narrow;
pub mod sign;
pub mod types;
pub mod uses;
pub mod verify;
pub mod webauthn;

#[cfg(test)]
mod mint_guard_tests;
#[cfg(test)]
mod mint_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod uses_tests;
#[cfg(test)]
mod verify_tests;

use bincode::Options;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub use types::*;

use crate::program::{Hash, Program};
use crate::{Error, Result};

/// Domain tag of [`cap_bytes`] (9 ASCII bytes, length-prefixed on the wire).
pub const CAP3_DOMAIN: &[u8] = b"ce-cap-v3";
/// The 4 bytes a v3 token starts with, no length prefix.
pub const MAGIC: [u8; 4] = *b"CEC3";
/// Parser bound on links per token (policy depth is `Delegate::depth`).
pub const MAX_LINKS: usize = 64;
/// Abilities per list.
pub const MAX_ABILITIES: usize = 64;
/// Program bodies per token.
pub const MAX_PROGRAMS: usize = 16;
/// Token size in bytes (binary, after hex decoding).
pub const MAX_TOKEN: usize = 1 << 20;

/// `len(9) || "ce-cap-v3" || CapabilityV3(c)`: the bytes the issuer signs.
///
/// Encoding in-memory values to a `Vec` cannot fail (no size limit, every length known). Should it
/// ever, this panics: an empty byte string would give every such link the same id and signed bytes.
pub fn cap_bytes(c: &CapabilityV3) -> Vec<u8> {
    bincode::serialize(&(CAP3_DOMAIN, c)).expect("bincode of a v3 capability to a Vec is infallible")
}

/// `SHA-256(cap_bytes(c))`: names the link as a parent.
pub fn cap_id(c: &CapabilityV3) -> Hash {
    Sha256::digest(cap_bytes(c)).into()
}

impl Link {
    /// The link's id as a child names it: the v1 `cap_id` for a V1 link, [`cap_id`] for V3.
    pub fn id(&self) -> Hash {
        match self {
            Link::V1(s) => s.id(),
            Link::V3 { cap, .. } => cap_id(cap),
        }
    }
}

/// The wire form: `"CEC3" || seq<Link> || seq<Program>`. `programs` is not signed; a body counts
/// only if the signed chain names its id.
#[derive(Debug, Clone)]
pub struct TokenV3 {
    /// Root first.
    pub links: Vec<Link>,
    /// Bodies of the programs the leaf binds; may be empty.
    pub programs: Vec<Program>,
}

/// Does `b` carry the v3 magic? A byte string that does not is a v1 chain.
pub fn is_v3(b: &[u8]) -> bool {
    b.starts_with(&MAGIC)
}

fn strict() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().with_little_endian().reject_trailing_bytes().with_limit(MAX_TOKEN as u64)
}

fn body<T: Serialize>(links: &T, programs: &[Program]) -> Vec<u8> {
    bincode::serialize(&(links, programs)).expect("bincode of a v3 token to a Vec is infallible")
}

impl TokenV3 {
    /// Canonical bytes: the magic, then bincode of `(links, programs)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend(body(&self.links, &self.programs));
        out
    }

    /// Lowercase hex of [`encode`](Self::encode).
    pub fn to_hex(&self) -> String {
        hex::encode(self.encode())
    }

    /// Strict decode (section 3.4): the magic, then exactly one `(links, programs)` with no trailing
    /// bytes, no unknown variant, re-encoding to the same bytes, every size bound and every link
    /// canonical. Any failure is a refusal.
    pub fn decode(b: &[u8]) -> Result<TokenV3> {
        if b.len() > MAX_TOKEN {
            return Err(Error("capability token is too large".into()));
        }
        let Some(rest) = b.strip_prefix(&MAGIC) else {
            return Err(Error("not a v3 capability token".into()));
        };
        let (links, programs): (Vec<Link>, Vec<Program>) =
            strict().deserialize(rest).map_err(|e| Error(format!("malformed v3 capability token: {e}")))?;
        let t = TokenV3 { links, programs };
        if t.encode() != b {
            return Err(Error("v3 capability token is not canonical".into()));
        }
        canon::check_token(&t)?;
        Ok(t)
    }

    /// [`decode`](Self::decode) of a hex token. Section 3.2: the token is lowercase hex, so an
    /// uppercase digit is refused (one token, one spelling); whitespace around it (a trailing
    /// newline in a file) is trimmed. The size bound is applied before any byte is decoded.
    pub fn from_hex(s: &str) -> Result<TokenV3> {
        let s = s.trim_matches(|c: char| c.is_ascii_whitespace());
        if s.len() > 2 * MAX_TOKEN {
            return Err(Error("capability token is too large".into()));
        }
        if !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(Error("capability token is not lowercase hex".into()));
        }
        let b = hex::decode(s).map_err(|_| Error("capability token is not valid hex".into()))?;
        TokenV3::decode(&b)
    }
}
