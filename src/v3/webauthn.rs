//! `Sig::WebAuthn` verification (`docs/CAPABILITY-PROGRAMS.md` section 2): a passkey assertion
//! over a v3 link, valid only for a P-256 key whose `rp_id` the node's owner roots record.
//!
//! All of: `client_data` is JSON with `type == "webauthn.get"` and `challenge` equal to
//! base64url-no-pad of `cap_id`; the first 32 bytes of `auth_data` are SHA-256 of `rp_id`; flags
//! UP and UV are set; the DER ECDSA signature verifies over `auth_data || SHA-256(client_data)`.

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256Vk};
use sha2::{Digest, Sha256};

use super::{CapabilityV3, cap_id};

/// User present.
pub const FLAG_UP: u8 = 0x01;
/// User verified.
pub const FLAG_UV: u8 = 0x04;

/// RFC 4648 section 5 base64url, no padding.
pub fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for chunk in b.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &x)| n | (x as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// The assertion of `key` over `cap`, against the `rp_id` recorded for `key` (`None`: refused).
pub fn verify(
    cap: &CapabilityV3,
    key: &[u8; 33],
    rp_id: Option<&str>,
    auth_data: &[u8],
    client_data: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    verify_challenge(&cap_id(cap), key, rp_id, auth_data, client_data, sig)
}

/// The assertion of `key` whose challenge is `challenge`: a link's `cap_id`, or for a proof of
/// section 4.1 the SHA-256 of the bytes it signs (domain tag included).
pub fn verify_challenge(
    challenge: &[u8; 32],
    key: &[u8; 33],
    rp_id: Option<&str>,
    auth_data: &[u8],
    client_data: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    let Some(rp_id) = rp_id else {
        return Err("no rp_id is recorded for this key".into());
    };
    let cd: serde_json::Value = serde_json::from_slice(client_data).map_err(|_| "clientDataJSON is not JSON".to_string())?;
    if cd.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err("clientDataJSON type is not webauthn.get".into());
    }
    if cd.get("challenge").and_then(|v| v.as_str()) != Some(b64url(challenge).as_str()) {
        return Err("challenge is not the hash of the signed bytes".into());
    }
    if auth_data.len() < 37 || auth_data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err("authenticatorData is not for the recorded rp_id".into());
    }
    if auth_data[32] & (FLAG_UP | FLAG_UV) != FLAG_UP | FLAG_UV {
        return Err("authenticatorData lacks user presence or verification".into());
    }
    let vk = P256Vk::from_sec1_bytes(key).map_err(|_| "malformed P-256 issuer key".to_string())?;
    let s = P256Sig::from_der(sig).map_err(|_| "malformed DER signature".to_string())?;
    let mut msg = auth_data.to_vec();
    msg.extend_from_slice(&Sha256::digest(client_data));
    vk.verify(&msg, &s).map_err(|_| "invalid signature".into())
}

#[cfg(test)]
mod tests {
    use super::b64url;

    #[test]
    fn base64url_rfc4648_vectors() {
        for (i, o) in [("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"), ("foob", "Zm9vYg"), ("fooba", "Zm9vYmE"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(b64url(i.as_bytes()), o);
        }
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }
}
