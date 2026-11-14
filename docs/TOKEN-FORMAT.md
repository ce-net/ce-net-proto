# ce-net capability token format, v1

This document specifies the exact bytes of a ce-net capability chain, so that the token can be
issued and verified in any language without this crate. It is normative for `ce-net-proto` 0.1 and
for `ce-cap` (the in-tree crate in `ce`), which produce identical bytes. `tests/vectors.json` holds
golden vectors; an implementation is conformant when it reproduces every `cap_bytes`, `cap_id`,
`sig` and `chain_hex` there and gets the same `verify_chain` / `authorize` result for each vector.
`docs/reference/ce_cap_verify.py` is an independent Python check written from this document alone.

## 1. Primitives

| Name | Encoding |
|---|---|
| `u8`, `u16`, `u32`, `u64` | fixed width, **little-endian** |
| `len` | `u64` little-endian (8 bytes) |
| `bytes32` | 32 raw bytes, **no length prefix** (a Rust `[u8; 32]`) |
| `string` | `len` (byte count) then UTF-8 bytes. Invalid UTF-8 is a decode error. |
| `seq<T>` | `len` (element count) then each element |
| `option<T>` | one byte `0x00` (None) or `0x01` (Some) followed by `T`. Any other tag byte is a decode error. |
| `enum` | `u32` variant index, then the variant's fields |
| struct / tuple | fields concatenated in declared order, no tags, no padding |

This is bincode 1.x with its default configuration (`bincode::serialize` / `bincode::deserialize`):
fixed-width integers, little-endian, `u64` lengths, no size limit.

**Trailing bytes**: bincode 1's top-level `deserialize` ignores bytes after a complete value. A
conformant decoder MUST therefore accept and ignore trailing bytes after the chain (or the
revocation) to agree with the reference. Nothing after the value is covered by any signature.

`NodeId` = `bytes32`: the Ed25519 public key (RFC 8032 encoding). It is the only identity.

## 2. Types

```
Resource = enum {
  0 Any                     -- no fields
  1 Node(NodeId)            -- bytes32
  2 Tag(string)
  3 AllOf(seq<string>)
}

Caveats = struct {
  not_before    : u64            -- unix seconds; 0 = no lower bound
  not_after     : u64            -- unix seconds; 0 = never expires
  max_cpu       : option<u32>
  max_mem_mb    : option<u32>
  max_credits   : option<u64>
  allowed_ports : option<seq<u16>>
  path_prefix   : option<string>
}

Capability = struct {
  issuer    : NodeId             -- the signer
  audience  : NodeId             -- the holder
  abilities : seq<string>        -- opaque action strings, see section 6
  resource  : Resource
  caveats   : Caveats
  nonce     : u64                -- unique per issuer; names the link for revocation
  parent    : option<bytes32>    -- CapId of the previous link; None on the root link
}

CapId = bytes32
```

## 3. What is signed

```
CAP_DOMAIN = "ce-cap-v1"         -- 9 ASCII bytes

cap_bytes(c) =
     len(9) || "ce-cap-v1"       -- 09 00 00 00 00 00 00 00 63 65 2d 63 61 70 2d 76 31
  || c.issuer || c.audience || seq<string>(c.abilities) || Resource(c.resource)
  || Caveats(c.caveats) || u64(c.nonce) || option<bytes32>(c.parent)

sig       = Ed25519_sign(issuer_secret, cap_bytes(c))       -- RFC 8032 pure Ed25519, no prehash, no context
cap_id(c) = SHA-256(cap_bytes(c))
```

`cap_bytes` is exactly the `Capability` encoding with the length-prefixed domain tag in front.

## 4. Wire form (the token)

```
SignedCapability = struct {
  cap : Capability               -- NO domain tag here
  sig : len(64) || 64 bytes      -- 40 00 00 00 00 00 00 00 then the signature
}

chain bytes = seq<SignedCapability>        -- root first, holder's link last
token       = lowercase hex(chain bytes)   -- decoders accept either case and trim surrounding whitespace
```

A decoder MUST reject a `sig` whose length prefix is not 64. Verifiers recompute `cap_bytes` from
the decoded `Capability`; the encoding is canonical (one value has one encoding), so this is the
same byte string the issuer signed.

### Worked example (vector `issued`)

Keys: root seed `01`x32 -> public `8a88e3dd…0f6f5c`; audience seed `02`x32 -> public `8139770e…c9b394`.
`Capability { issuer: root, audience: a, abilities: ["exec","sync"], resource: Any, caveats: default, nonce: 1, parent: None }`:

```
09000000 00000000 63652d6361702d7631             len 9, "ce-cap-v1"   (cap_bytes only)
8a88e3dd…b40f6f5c                                 issuer (32)
8139770e…8fc9b394                                 audience (32)
02000000 00000000                                 2 abilities
04000000 00000000 65786563                        "exec"
04000000 00000000 73796e63                        "sync"
00000000                                          Resource::Any
00000000 00000000 00000000 00000000               not_before 0, not_after 0
00 00 00 00 00                                    five None options
01000000 00000000                                 nonce 1
00                                                parent None
```

`cap_id` = `f7929567c12bb7600130b8a0a97c370c6e5af04114f57f0d32412d73c1cca920`. The token is
`01000000 00000000` (one link) + the capability bytes without the domain tag + `40000000 00000000` +
the 64-byte signature; the full hex is `chains[0].chain_hex` in `tests/vectors.json`.

## 5. Revocation

```
REVOKE_DOMAIN = "ce-cap-revoke-v1"         -- 16 ASCII bytes

Revocation = struct { issuer: NodeId, nonce: u64, not_after: u64 }   -- not_after 0 = retain forever

revoke_bytes(r) = len(16) || "ce-cap-revoke-v1" || r.issuer || u64(r.nonce) || u64(r.not_after)
sig             = Ed25519_sign(issuer_secret, revoke_bytes(r))
wire            = Revocation || len(64) || sig                       -- SignedRevocation, no domain tag
```

A revocation is valid iff its signature verifies under `r.issuer`: only an issuer can revoke its own
`(issuer, nonce)`. Revoking `(issuer, nonce)` kills every chain containing a link with that issuer
and nonce, and therefore the whole subtree delegated from it. Revocation is keyed by the pair: the
same nonce under a different issuer is unaffected. How a verifier learns revocations (a directed
`SignedRevocation`, an on-chain set) is outside the token; verifiers take an `is_revoked(issuer,
nonce)` predicate.

## 6. Ability matching

`covers(granted, needed)` is true iff one of:

1. `granted == needed` (byte equality);
2. `granted == "*"`;
3. `granted` ends in `":*"`; let `p = granted` without the final `*` (so `p` ends in `:`); then
   `needed` starts with `p` and is strictly longer than `p`. (`app:spawn:*` covers `app:spawn:wasm`,
   not `app:spawn` and not `app:spawnx`; `app:sp*` is not a wildcard.)

`abilities_subset(child, parent)` = every child ability is covered by some parent ability.

## 7. Attenuation predicates

`resource_subset(child, parent)`:

| parent | child is a subset iff |
|---|---|
| `Any` | always |
| `Node(p)` | child is `Node(p)` |
| `Tag(t)` | child is `Tag(t)`, or `AllOf(s)` with `t` in `s` |
| `AllOf(ps)` | child is `AllOf(s)` with every `p` in `s`, or `Tag(s)` with every `p == s` |

`caveats_narrower_or_equal(child, parent)`, all of:

- if `parent.not_after != 0`: `child.not_after != 0` and `child.not_after <= parent.not_after`;
- `child.not_before >= parent.not_before`;
- for each of `max_cpu`, `max_mem_mb`, `max_credits`: parent None, or child Some and `child <= parent`;
- if parent `allowed_ports` is Some: child is Some and every child port is in the parent's list;
- if parent `path_prefix` is Some: child is Some and `within(child, parent)`, where both have
  trailing `/` stripped and then `parent == ""`, or `child == parent`, or `child` starts with `parent + "/"`.

Temporal validity at `now`: invalid if `not_before != 0 && now < not_before` ("not yet valid") or
`not_after != 0 && now > not_after` ("has expired"). `not_after` is inclusive.

## 8. Verification algorithms

### `verify_chain(chain, root, now, is_revoked)` (offline, node-independent; the CLI)

1. chain non-empty, else `"no capability presented"`;
2. `chain[0].issuer == root`, else `"capability chain does not root at an accepted authority"`;
3. for each link `i` in order, stopping at the first failure:
   1. Ed25519 signature by `issuer` over `cap_bytes` -> `"link i: invalid signature"`;
   2. temporal validity at `now` -> `"link i: capability not yet valid"` / `"link i: capability has expired"`;
   3. `is_revoked(issuer, nonce)` -> `"link i: capability revoked"`;
   4. `i == 0`: `parent` must be None -> `"root capability must not name a parent"`;
   5. `i > 0`, with `P = chain[i-1]`: `issuer == P.audience` -> `"link i: issuer is not the parent's audience"`;
      `parent == cap_id(P)` -> `"link i: parent hash does not match the chain"`;
      `abilities_subset` -> `"link i: abilities exceed the parent"`;
      `resource_subset` -> `"link i: resource is broader than the parent"`;
      `caveats_narrower_or_equal` -> `"link i: caveats are broader than the parent"`.

On success the leaf's `audience` is the holder and its `abilities`/`resource`/`caveats` are what the
holder may use.

### `authorize(self_id, accepted_roots, self_tags, now, requester, action, chain, is_revoked)` (the node)

As `verify_chain`, with these differences: the root check accepts `chain[0].issuer == self_id` or
`chain[0].issuer` in `accepted_roots`; after step 3.3 each link's `resource` must match the node
(`Any`; `Node(n)` with `n == self_id`; `Tag(t)` with `t` in `self_tags`; `AllOf(ts)` with all in
`self_tags`) -> `"link i: resource does not match this node"`; and at the end the leaf's `audience`
must equal `requester` -> `"leaf capability is not held by the request sender"`, and some leaf
ability must cover `action` -> `"capability does not grant '<action>'"`.

Resource ceilings (`max_*`), `allowed_ports` and `path_prefix` are not checked by either algorithm;
the action that consumes them enforces them and must refuse rather than exceed them.

## 9. Ed25519 verification semantics

The reference uses `ed25519-dalek` 2.x `VerifyingKey::from_bytes` + `Verifier::verify` (not
`verify_strict`): the public key must decompress to a curve point, `S` must be canonical (`S < L`),
and the check is the cofactorless RFC 8032 equation. Small-order public keys and `R` values are not
rejected. For signatures made by an honest RFC 8032 signer every conformant verifier agrees; an
implementation that wants bit-exact agreement on adversarial edge cases should use the same rules.

## 10. Versioning

The domain tags (`ce-cap-v1`, `ce-cap-revoke-v1`) are the format version. Any change to a byte
layout in this document requires new domain tags, new vectors, and a new version of this document.
