//! Signing a v3 statement and checking a raw signature (`docs/CAPABILITY-PROGRAMS.md` section 2).
//!
//! Ed25519 is pure RFC 8032 over `cap_bytes`, through the same path as v1. P-256 is ECDSA with
//! SHA-256 over `cap_bytes` (RFC 6979 deterministic nonces), `r || s` big-endian, and always
//! emitted low-S. `WebAuthn` assertions are made by an authenticator, not here, and need the
//! owner roots' `rp_id` to check, so [`verify_sig`] refuses them; the chain verifier handles them.

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as P256Sig, SigningKey as P256Key, VerifyingKey as P256Vk};

use super::{CapabilityV3, Key, Sig, cap_bytes};
use crate::{Error, Identity, Result, identity};

/// A key that can sign a v3 link: an Ed25519 node or lane key, or a P-256 key.
pub enum Signer {
    Ed25519(Identity),
    P256(P256Key),
}

impl Signer {
    /// From a 32-byte Ed25519 seed.
    pub fn ed25519(secret: &[u8; 32]) -> Signer {
        Signer::Ed25519(Identity::from_secret_bytes(secret))
    }

    /// From a 32-byte P-256 scalar (big-endian); refuses zero and values `>= n`.
    pub fn p256(secret: &[u8; 32]) -> Result<Signer> {
        P256Key::from_slice(secret).map(Signer::P256).map_err(|_| Error("invalid P-256 secret key".into()))
    }

    /// The public key, as a link's `issuer` names it (P-256: SEC1 compressed).
    pub fn key(&self) -> Key {
        match self {
            Signer::Ed25519(id) => Key::Ed25519(id.node_id()),
            Signer::P256(k) => {
                let point = k.verifying_key().to_encoded_point(true);
                let mut out = [0u8; 33];
                out.copy_from_slice(point.as_bytes());
                Key::P256(out)
            }
        }
    }

    /// Sign `cap_bytes(cap)`. The caller makes `cap.issuer == self.key()`.
    pub fn sign(&self, cap: &CapabilityV3) -> Sig {
        self.sign_bytes(&cap_bytes(cap))
    }

    /// Sign `msg` as it stands. The caller passes domain-tagged bytes (`cap_bytes`, or the
    /// `attest_bytes`, `cosign_bytes`, `via_bytes` of section 4.1), never a bare payload.
    pub fn sign_bytes(&self, msg: &[u8]) -> Sig {
        match self {
            Signer::Ed25519(id) => Sig::Ed25519(id.sign(msg)),
            Signer::P256(k) => {
                let s: P256Sig = k.sign(msg);
                let s = s.normalize_s().unwrap_or(s);
                let mut out = [0u8; 64];
                out.copy_from_slice(&s.to_bytes());
                Sig::P256(out)
            }
        }
    }
}

/// Does `sig` by `cap.issuer` verify over `cap_bytes(cap)`? `Ed25519` and raw `P256` only.
pub fn verify_sig(cap: &CapabilityV3, sig: &Sig) -> Result<(), String> {
    verify_bytes(&cap.issuer, &cap_bytes(cap), sig)
}

/// Does `sig` by `key` verify over `msg`? `Ed25519` and raw `P256` only; the variant must match
/// the key (section 2).
pub fn verify_bytes(key: &Key, msg: &[u8], sig: &Sig) -> Result<(), String> {
    match (key, sig) {
        (Key::Ed25519(k), Sig::Ed25519(s)) => identity::verify(k, msg, s).map_err(|_| "invalid signature".into()),
        (Key::P256(k), Sig::P256(rs)) => {
            if !sig.canonical() {
                return Err("P-256 signature is not low-S".into());
            }
            let vk = P256Vk::from_sec1_bytes(k).map_err(|_| "malformed P-256 issuer key".to_string())?;
            let s = P256Sig::from_slice(rs).map_err(|_| "invalid signature".to_string())?;
            vk.verify(msg, &s).map_err(|_| "invalid signature".into())
        }
        (Key::P256(_), Sig::WebAuthn { .. }) => Err("a WebAuthn signature needs the owner roots' rp_id".into()),
        _ => Err("signature type does not match the issuer key".into()),
    }
}
