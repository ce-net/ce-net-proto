//! Minimal Ed25519 identity: a [`NodeId`] is a 32-byte Ed25519 public key; [`sign`](Identity::sign)
//! and [`verify`] are plain RFC 8032 Ed25519 with no prehash and no context.
//!
//! This is a deliberately small mirror of `ce-identity` (no VRF, no key files, no RNG): keys are
//! constructed from 32 secret bytes the caller supplies. Signatures are byte-identical to
//! `ce-identity` for the same secret (Ed25519 signing is deterministic), and [`verify`] uses the
//! same `ed25519-dalek` 2.x `Verifier::verify` path, so the two accept exactly the same signatures.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::Error;

/// A node's identity on ce-net: its 32-byte Ed25519 public key.
pub type NodeId = [u8; 32];

/// An Ed25519 signing key. Construct with [`Identity::from_secret_bytes`].
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Build an identity from 32 raw secret-key bytes (the RFC 8032 seed). Deterministic.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Identity { signing_key: SigningKey::from_bytes(secret) }
    }

    /// The public key, which is the node id.
    pub fn node_id(&self) -> NodeId {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Lowercase hex of [`node_id`](Self::node_id).
    pub fn node_id_hex(&self) -> String {
        hex::encode(self.node_id())
    }

    /// Ed25519-sign `data`.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing_key.sign(data).to_bytes()
    }

    /// The 32 secret bytes (seed).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// Verify an Ed25519 signature by `node_id` over `data`.
pub fn verify(node_id: &NodeId, data: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(node_id).map_err(|e| Error(format!("bad public key: {e}")))?;
    let signature = Signature::from_bytes(sig);
    key.verify(data, &signature).map_err(|e| Error(format!("bad signature: {e}")))
}

/// Parse a 64-hex-char public key into a [`NodeId`].
pub fn node_id_from_hex(s: &str) -> Result<NodeId, Error> {
    let b = hex::decode(s.trim()).map_err(|_| Error("public key is not valid hex".into()))?;
    b.try_into().map_err(|_| Error("public key must be 32 bytes (64 hex chars)".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8032_test_vector_1() {
        // RFC 8032 section 7.1, TEST 1 (empty message).
        let sk: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap().try_into().unwrap();
        let id = Identity::from_secret_bytes(&sk);
        assert_eq!(id.node_id_hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig = id.sign(b"");
        assert_eq!(
            hex::encode(sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(verify(&id.node_id(), b"", &sig).is_ok());
        assert!(verify(&id.node_id(), b"x", &sig).is_err());
    }
}
