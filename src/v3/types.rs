//! The v3 data types of `docs/CAPABILITY-PROGRAMS.md` sections 2 to 4, in declared (wire) order.
//!
//! Every type encodes with bincode 1 (fixint, little-endian, `u64` lengths, `u32` variant tags),
//! exactly as the spec's grammar reads. Fixed-size byte strings (`bytes33`, `bytes64`) carry no
//! length prefix. Serde's derived decoders refuse an unknown variant index, so an old verifier
//! refuses a token that uses a variant it does not know.

use serde::{Deserialize, Serialize};

use crate::cap::{Caveats, SignedCapability};
use crate::program::{EgressRule, Hash, Limit, ResourceV3};

/// Serde for `[u8; N]` as N raw bytes (a bincode tuple: no length prefix). serde's own array
/// impls stop at 32.
pub(crate) mod raw {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(a: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        let mut t = s.serialize_tuple(N)?;
        for b in a {
            t.serialize_element(b)?;
        }
        t.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
        struct V<const N: usize>;
        impl<'de, const N: usize> Visitor<'de> for V<N> {
            type Value = [u8; N];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{N} raw bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; N], A::Error> {
                let mut out = [0u8; N];
                for (i, o) in out.iter_mut().enumerate() {
                    *o = seq.next_element()?.ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(N, V::<N>)
    }
}

/// A principal: a public key and nothing else (section 2). A person, an agent lane, a machine and
/// a spawned process are all a `Key`; names are labels kept beside it, never verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Key {
    /// 0: RFC 8032 public key; the same bytes as a v1 `NodeId`.
    Ed25519([u8; 32]),
    /// 1: SEC1 compressed P-256 point (`02`/`03` || X).
    P256(#[serde(with = "raw")] [u8; 33]),
}

/// The spec's name for a [`Key`] when it stands for who may act.
pub type Principal = Key;

impl Key {
    /// A v1 `NodeId` is `Key::Ed25519` of the same bytes (section 3.3).
    pub fn from_node_id(id: crate::NodeId) -> Key {
        Key::Ed25519(id)
    }

    /// Structurally valid: a P-256 point names its parity in the first byte.
    pub fn canonical(&self) -> bool {
        match self {
            Key::Ed25519(_) => true,
            Key::P256(p) => p[0] == 0x02 || p[0] == 0x03,
        }
    }
}

/// A signature over `cap_bytes` (section 2). The variant must match the issuer's [`Key`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sig {
    /// 0: pure Ed25519.
    Ed25519(#[serde(with = "raw")] [u8; 64]),
    /// 1: ECDSA P-256 / SHA-256, `r || s` big-endian, low-S.
    P256(#[serde(with = "raw")] [u8; 64]),
    /// 2: a passkey assertion with challenge `cap_id`; the key is P-256.
    WebAuthn { auth_data: Vec<u8>, client_data: Vec<u8>, sig: Vec<u8> },
}

/// Big-endian `n / 2` of P-256 (`n` the group order): a low-S signature has `s <= P256_HALF_N`.
pub const P256_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

impl Sig {
    /// Canonical form: a raw P-256 signature is low-S. (WebAuthn's DER signature is checked by
    /// the verifier, which must parse it anyway.)
    pub fn canonical(&self) -> bool {
        match self {
            Sig::P256(rs) => rs[32..] <= P256_HALF_N[..],
            _ => true,
        }
    }
}

/// Who a child link may be addressed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AudienceSet {
    Any,
    /// Sorted by encoding, unique, non-empty.
    Keys(Vec<Key>),
}

/// The delegation right of a link: what its audience may grant, to whom, how many links deep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegate {
    /// What the audience may put in a child link; non-empty.
    pub abilities: Vec<String>,
    /// Who a child link may be addressed to.
    pub audience: AudienceSet,
    /// How many links may follow below this one; `>= 1`.
    pub depth: u8,
}

/// What a `Uses` counter counts per.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsePer {
    Link,
    Action,
}

/// One typed caveat (section 4). At most one per variant in a link's `ext`, ascending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Caveat {
    /// 0: counted use at each executing node; `max >= 1`.
    Uses { max: u32, per: UsePer },
    /// 1: named ceilings, sorted by name, unique.
    Limits(Vec<Limit>),
    /// 2: allowed outbound destinations, sorted by encoding, unique; empty = no network at all.
    Egress(Vec<EgressRule>),
    /// 3: program ids this subtree may only execute; sorted, unique, non-empty.
    Programs(Vec<Hash>),
}

impl Caveat {
    /// The variant index on the wire.
    pub fn index(&self) -> u32 {
        match self {
            Caveat::Uses { .. } => 0,
            Caveat::Limits(_) => 1,
            Caveat::Egress(_) => 2,
            Caveat::Programs(_) => 3,
        }
    }
}

/// The unsigned v3 capability statement (section 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityV3 {
    /// Always 3.
    pub v: u8,
    pub issuer: Key,
    pub audience: Key,
    /// What the audience may itself do; may be empty ("may grant, may not use").
    pub abilities: Vec<String>,
    /// Applies to use and to everything delegated.
    pub resource: ResourceV3,
    /// The v1 struct, unchanged.
    pub caveats: Caveats,
    pub ext: Vec<Caveat>,
    /// `None` = final: nothing may be minted below this link.
    pub delegate: Option<Delegate>,
    /// Names the link for revocation as `(issuer, nonce)`.
    pub nonce: u64,
    /// `cap_id` of the previous link (v1 or v3); `None` on the root link.
    pub parent: Option<Hash>,
}

impl CapabilityV3 {
    /// The caveat of variant `index` in `ext`, if present.
    pub fn ext_get(&self, index: u32) -> Option<&Caveat> {
        self.ext.iter().find(|c| c.index() == index)
    }
}

/// One link of a v3 token (section 3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Link {
    /// 0: exactly a v1 `SignedCapability` (TOKEN-FORMAT.md section 4).
    V1(SignedCapability),
    /// 1: a v3 statement and its signature.
    V3 { cap: CapabilityV3, sig: Sig },
}
