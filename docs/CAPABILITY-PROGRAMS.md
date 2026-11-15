# ce-net capability programs: recursive delegation, token format v3

Status: **specification, not yet implemented** (2026-11-15, planner). Nothing in this document changes a byte
of [TOKEN-FORMAT.md](TOKEN-FORMAT.md) (v1): every v1 token, revocation and golden vector in `tests/vectors.json` stays
valid and is verified exactly as today. The design and the reasons are in `repo:ce-fleet/docs/AUTH-TREE.md`, section
"Recursive capability programs". Conformance vectors (`tests/vectors-v3.json`) and the Python reference verifier are
written with the implementation; until they exist this text is the only normative source and may still change.

Leif, 2026-11-15: "one permission from me must be able to allow you to once install a permission elsewhere. permissions
are recursive. this is a must. you must be able to chain permissions otherwise this system doesn't scale. i must be able
to allow you to allow another agent to install a python script on my raspberry pi. through code. and nothing else is
allowed. ... through the auth we design and define pipelines like a programming language of what needs to happen. like a
solana script. like rust." And: "it doesn't stop at one layer either. we can define entire long chains of me giving the
capability to a friend to give his agent the ability to spawn a python script with the ability to access the internet."

What v3 adds to v1:

1. keys other than Ed25519 (Leif's P-256 device key can sign a link);
2. a **delegation right** on every link: who may be granted what, and how many links deep;
3. typed caveats that can grow: counted use, limits, egress, program binding;
4. **programs**: a hash-addressed, typed list of steps, bound into a link so the executing cell runs that and nothing else;
5. use counters burned at the executing node.

## 1. Primitives

As TOKEN-FORMAT.md section 1 (bincode 1.x, little-endian, `u64` lengths), plus:

| Name | Encoding |
|---|---|
| `bytes33` | 33 raw bytes, no length prefix |
| `bytes` | `len` then raw bytes |
| `bool` | one byte `0x00` or `0x01`; any other value is a decode error |

Unlike v1, a v3 decoder MUST reject trailing bytes, unknown enum variants and non-canonical encodings (section 3.4).
An unknown variant is a refusal, never something to skip: that is what makes new caveats fail closed on old verifiers.

## 2. Keys and signatures

```
Key = enum {
  0 Ed25519(bytes32)        -- RFC 8032 public key; the same bytes as a v1 NodeId
  1 P256(bytes33)           -- SEC1 compressed point (02/03 || X)
}

Sig = enum {
  0 Ed25519(bytes64)        -- pure Ed25519 over cap_bytes, verification rules of TOKEN-FORMAT.md section 9
  1 P256(bytes64)           -- ECDSA P-256 with SHA-256 over cap_bytes; r || s, big-endian, low-S required
  2 WebAuthn {              -- a passkey assertion; the key is P256
      auth_data   : bytes   -- authenticatorData
      client_data : bytes   -- clientDataJSON, exact bytes
      sig         : bytes   -- ASN.1 DER ECDSA signature over auth_data || SHA-256(client_data)
    }
}
```

The `Sig` variant must match the `Key` variant of the issuer (`Ed25519`/`Ed25519`; `P256`/`P256` or `WebAuthn`), else
`"link i: signature type does not match the issuer key"`.

`WebAuthn` verification, all of: `client_data` parses as JSON with `type == "webauthn.get"` and `challenge` equal to
base64url-no-pad of `cap_id` (32 bytes); the first 32 bytes of `auth_data` equal SHA-256 of the `rp_id` recorded for
that key in the node's owner roots (section 9); flags UP and UV are set; the ECDSA signature verifies. A key with no
recorded `rp_id` never verifies a `WebAuthn` signature.

A principal is a key and nothing else. A person (Leif, a friend), an agent lane, a machine and a spawned process are
all a `Key`; names such as `person:leif` or `agent:planner` are labels kept beside the key (owner roots,
ce-iam wallet), never part of what is verified.

## 3. The v3 link

```
ResourceV3 = enum {
  0 Any
  1 Node(bytes32)
  2 Tag(string)
  3 AllOf(seq<string>)
  4 Nodes(seq<bytes32>)     -- a finite list of nodes; sorted ascending, unique, non-empty
}

AudienceSet = enum {
  0 Any
  1 Keys(seq<Key>)          -- sorted by encoding, unique, non-empty
}

Delegate = struct {
  abilities : seq<string>   -- what the audience may put in a child link (section 5); non-empty
  audience  : AudienceSet   -- who a child link may be addressed to
  depth     : u8            -- how many links may follow below this one; >= 1
}

CapabilityV3 = struct {
  v         : u8            -- always 3
  issuer    : Key
  audience  : Key
  abilities : seq<string>   -- what the audience may itself do; may be empty ("may grant, may not use")
  resource  : ResourceV3    -- applies to use and to everything delegated
  caveats   : Caveats       -- the v1 struct, unchanged (TOKEN-FORMAT.md section 2)
  ext       : seq<Caveat>   -- section 4
  delegate  : option<Delegate>   -- None = this link is final: nothing may be minted below it
  nonce     : u64           -- random; names the link for revocation as (issuer, nonce)
  parent    : option<bytes32>    -- cap id of the previous link (v1 or v3); None on the root link
}
```

A sentence of the form "may grant `<ability set>` on `<resource set>` to `<audience>`, depth <= n, uses <= k, until t"
is exactly one link: `delegate.abilities`, `resource`, `delegate.audience`, `delegate.depth`, `Caveat::Uses`,
`caveats.not_after`.

### 3.1 What is signed

```
CAP3_DOMAIN = "ce-cap-v3"                                  -- 9 ASCII bytes

cap_bytes(c) = len(9) || "ce-cap-v3" || CapabilityV3(c)
cap_id(c)    = SHA-256(cap_bytes(c))
sig          = issuer signs cap_bytes(c)                   -- Ed25519 pure, or ECDSA P-256/SHA-256
                                                           -- (whose message digest is therefore cap_id), or
                                                           -- WebAuthn with challenge cap_id
```

The v1 domain (`ce-cap-v1`) and the v2 hash-cap domain of `ce-gate` differ from `ce-cap-v3`, so no signature made for
one format verifies as another.

### 3.2 Wire form

```
Link = enum {
  0 V1(SignedCapability)                 -- exactly TOKEN-FORMAT.md section 4
  1 V3 { cap: CapabilityV3, sig: Sig }
}

TokenV3 = struct {
  magic    : 4 bytes "CEC3"              -- 43 45 43 33, no length prefix
  links    : seq<Link>                   -- root first
  programs : seq<Program>                -- the bodies of programs the leaf binds (section 6); may be empty
}

token = lowercase hex(TokenV3)
```

A v1 token starts with a `u64` link count; `CEC3` read as the low bytes of that count is over 800 million links, so a
v1 decoder fails on a v3 token and refuses it. A v3 decoder that does not see the magic decodes the bytes as a v1 chain
and verifies it by TOKEN-FORMAT.md alone. `programs` is not signed: a program counts only if its id is named by the
signed chain (section 6.3).

### 3.3 Mixed chains

V1 links may only come first: after the first `V3` link every later link must be `V3`
(`"link i: a v1 link cannot follow a v3 link"`), because a v1 link cannot carry the parent's `ext` caveats or its
delegation right. A V3 link whose parent is V1 names the parent by its v1 `cap_id`. For the checks of section 5 a v1
parent counts as `resource` mapped variant for variant, `ext` empty, and
`delegate = { abilities: parent.abilities, audience: Any, depth: 255 }`, which is what v1 allows today (any holder may
re-delegate). A v1 `NodeId` is `Key::Ed25519` of the same bytes.

### 3.4 Canonical form

A link is refused (`"link i: not canonical"`) unless: `v == 3`; `ext` holds at most one caveat per variant, in
ascending variant order; every list this document calls sorted is sorted and unique; `delegate`, when present, has
`depth >= 1` and non-empty `abilities`; the condition lists of section 4.1 are canonical; P-256 signatures are low-S;
the token has at most `MAX_LINKS = 64` links,
`MAX_ABILITIES = 64` abilities per list, `MAX_PROGRAMS = 16` programs and `MAX_TOKEN = 1 MiB` bytes. The link limit is
a parser bound, not a policy: policy depth is `delegate.depth`.

## 4. Caveats

```
Caveat = enum {
  0 Uses    { max: u32, per: UsePer }           -- counted use, section 7; max >= 1
  1 Limits  (seq<Limit>)                        -- sorted by name, unique
  2 Egress  (seq<EgressRule>)                   -- sorted, unique; an empty list = no network at all
  3 Programs(seq<bytes32>)                      -- program ids, sorted, unique, non-empty; section 6
  4 Requires(seq<Requirement>)                  -- conditions, section 4.1
  5 CoSign  (seq<CoSigner>)                     -- conditions, section 4.1
  6 Via     (seq<Party>)                        -- conditions, section 4.1
}

UsePer = enum { 0 Link, 1 Action }

Limit = struct { name: string, max: u64 }       -- name is "<api>.<name>", e.g. "media.store.quota_gb"

EgressRule = struct {
  host  : HostPat
  ports : seq<u16>                              -- sorted, unique, non-empty
  proto : enum { 0 Tcp, 1 Udp }
}

HostPat = enum {
  0 Name(string)                                -- one exact DNS name, lowercase, no trailing dot
  1 Suffix(string)                              -- ".example.org": any name ending in it, not example.org itself
  2 Cidr { addr: bytes, prefix: u8 }            -- addr is 4 or 16 bytes, host bits zero
}
```

A caveat on a link binds that link's own use and every link below it.

**Narrowing** (`ext_narrower_or_equal(child, parent)`): for every variant the parent carries, the child carries the
same variant and:

| Variant | Child is no looser iff |
|---|---|
| `Uses` | `child.max <= parent.max` and `child.per == parent.per` |
| `Limits` | every parent name appears in the child with `child.max <= parent.max` (the child may add names) |
| `Egress` | every child rule is covered by one parent rule: same `proto`, child ports a subset, and host covered (`Name` by an equal `Name`, by a `Suffix` it ends with, or by a `Cidr` never; `Suffix` by an equal or shorter matching `Suffix`; `Cidr` by a `Cidr` that contains it) |
| `Programs` | every child id is in the parent's list |
| `Requires` | every parent entry appears in the child with the same `witness` and `claim` and a freshness no looser: `child.fresh_within_s <= parent.fresh_within_s`, where `None` (any age) is looser than every `Some` (the child may add entries) |
| `CoSign` | every parent entry appears in the child unchanged (the child may add co-signers) |
| `Via` | every parent broker appears in the child unchanged (the child may add brokers) |

A child may add a variant the parent lacks. Because every link's counters are charged on every use (section 7), a
child that adds its own `Uses` only tightens. The three condition variants are lists of things that must ALL hold, so
for them narrowing runs the other way round from `Programs`: a longer list is narrower, and a child that leaves out one
inherited entry is refused (`"link i: caveats are broader than the parent"`).

**Limit names** defined here (a cell defines the names under its own api, and refuses a name under its api it does not
know):

| Name | Meaning | Kind |
|---|---|---|
| `net.egress.bytes_out`, `net.egress.bytes_in` | bytes a process tree may send / receive | cumulative, counted like `Uses` |
| `net.egress.conns` | connections opened | cumulative |
| `proc.spawn.wall_s` | wall-clock seconds a spawned process may live | per run |
| `proc.spawn.procs` | live processes in the sandbox at once | ceiling |
| any other `<api>.<name>` | set by that cell | ceiling unless the cell documents otherwise |

### 4.1 Conditions: `Requires`, `CoSign`, `Via`

Leif, 2026-11-15: "not just this 4 link chain also chains like 'have you read the wechat chat before writing' and
'always verify the auth code and talk to this all through the same systems agent before you can pass through and do
this' and 'always talk to this agent if you want to access the 3d printer'".

A condition is a caveat that the chain alone cannot satisfy: each use must bring a signed **proof** from someone else.
Conditions are signed into the link like every caveat, are checked at verify like everything else, and only narrow
along a chain (the table above): whoever holds a link below a condition can add conditions and can never drop one.

```
Party = enum {
  0 Key(Key)                 -- exactly this principal
  1 Cell(string)             -- the cell serving this api, e.g. "printer3d.gate": the executing node resolves the
                             -- api to the keys it trusts for it; a verifier that cannot resolve it refuses
}

Claim = enum {               -- a typed predicate about something done
  0 ReadThrough { source: string, thread: string, upto_msg: option<string> }
                             -- the subject has read `thread` of `source` through message `upto_msg`. In a
                             -- Requirement, None = through whatever was newest when attested (bound it with
                             -- fresh_within_s); an attestation always names the message
  1 Fact { name: string, value: bytes }
                             -- cell-defined, name is "<api>.<name>"; value is matched byte for byte
}

Requirement = struct {       -- Requires: proof that something was done first
  witness        : Party     -- who must have signed the attestation
  claim          : Claim     -- what it must state
  fresh_within_s : option<u64>   -- Some(n), n >= 1: at most n seconds old at use; None: any age
}

CoSignPer = enum { 0 Use }   -- every use carries its own signature

CoSigner = struct {          -- CoSign: a second signature on every use
  by  : Key                  -- e.g. a system's guardian agent
  per : CoSignPer
}
                             -- Via(seq<Party>): each entry is a broker every use must pass through
```

Canonical form (section 3.4): each list holds 1 to `MAX_CONDITIONS = 16` entries, sorted ascending by encoding, unique;
`Requires` holds one entry per `(witness, claim)`; `fresh_within_s` is never `Some(0)`; every string holds 1 to
`MAX_COND_STR = 256` bytes and a `Fact.value` at most 256; keys are well-formed.

**What is signed at use.** The proofs travel beside the token (they are made per use, the token is not):

```
AttestationBody = struct { witness: Key, subject: Key, claim: Claim, at: u64 }   -- `subject` did `claim`, seen at `at`
Attestation     = struct { body: AttestationBody, sig: Sig }

UseRequest = struct {        -- the exact request of one use
  leaf      : bytes32        -- cap id of the leaf link
  node      : bytes32        -- the executing node
  requester : Key
  action    : string         -- as passed to authorize_v3; non-empty
  body      : bytes32        -- SHA-256 of the request body, as the called cell defines its bytes
  at        : u64            -- unix seconds
  nonce     : u64            -- chosen by the requester
}

Proof = enum {
  0 Attested(Attestation)                -- for a Requires entry
  1 CoSigned { by: Key, sig: Sig }       -- for a CoSign entry
  2 Brokered { broker: Key, sig: Sig }   -- for a Via entry
}

attest_bytes(b) = len(16) || "ce-cap-v3-attest"  || AttestationBody(b)    -- the witness signs
cosign_bytes(r) = len(16) || "ce-cap-v3-cosign"  || UseRequest(r)         -- the co-signer signs
via_bytes(r)    = len(13) || "ce-cap-v3-via"     || UseRequest(r)         -- the broker signs
request_id(r)   = SHA-256(len(17) || "ce-cap-v3-request" || UseRequest(r))

proofs = seq<Proof>          -- at most MAX_PROOFS = 64; decoded strictly, like the token
```

The four domains differ from each other and from `ce-cap-v3`, so an attestation is never an approval, a co-signature
is never a broker approval, and none of them is a link. Signatures follow section 2 (`Sig`, low-S; a WebAuthn
signature has as its challenge the SHA-256 of the signed bytes). An attestation's `ReadThrough` names its message.

**What the executing node checks** (`authorize_v3`, section 5.2), for the conditions of **every link of the chain**
(by narrowing the leaf carries them all), given the `UseRequest` and the proofs of this use:

- the `UseRequest` is this use: `leaf`, `node`, `requester`, `action` equal what is being authorized, `body` is the
  hash of the request received, `at` is within 300 s of `now`, and `request_id` has not been executed here before;
- `Requires` entry `R`: some `Attested(a)` has a valid signature by `a.body.witness`, that witness is `R.witness`
  (`Key`: equal; `Cell(api)`: one of the node's keys for `api`), `a.body.subject == requester`,
  `R.claim` is proved by `a.body.claim` (same variant and fields; a required `upto_msg: None` accepts any message),
  `a.body.at <= now`, and `now - a.body.at <= fresh_within_s` when that is set -> else `"condition not met: requires"`;
- `CoSign` entry `C`: some `CoSigned { by: C.by, sig }` verifies over `cosign_bytes` of this `UseRequest` -> else
  `"condition not met: cosign"`. What the co-signer checks before it signs (an auth code, a human's yes) is its own
  business; the verifier checks only that it signed this exact request;
- `Via` entry `B`: some `Brokered { broker, sig }` verifies over `via_bytes` of this `UseRequest` with `broker`
  matching `B` as a witness matches -> else `"condition not met: via"`. The resource executes nothing that does not
  carry it, so the broker cannot be walked around even by a holder of a valid chain.

`verify_chain_v3` (offline, no request) checks the conditions' canonical form and narrowing and reports them; it cannot
say whether they will be met.

**The three examples**, each as the `ext` of the link that sets the rule (a child link repeats it or is refused):

| Rule | Caveat |
|---|---|
| "have you read the wechat chat before writing" | `Requires([{ witness: Cell("wechat.read"), claim: ReadThrough { source: "wechat", thread: "<thread id>", upto_msg: None }, fresh_within_s: Some(600) }])` on the link that grants `wechat.send:send`: the wechat cell attests the agent's key read the thread through its newest message at most 10 minutes ago |
| "always verify the auth code and talk to this all through the same systems agent before you can pass through and do this" | `CoSign([{ by: <the system's guardian agent>, per: Use }])` together with `Via([Key(<the same agent>)])`: the agent checks the auth code, then signs the exact request both as approval and as broker; the same key in both makes it "the same systems agent" |
| "always talk to this agent if you want to access the 3d printer" | `Via([Cell("printer3d.gate")])` (or `Key(<the 3D-printer agent>)`) on the link that grants `printer3d:*`: the printer accepts a job only with the printer agent's signed approval of that job |

## 5. Verification

### 5.1 `verify_chain_v3(token, roots, now, is_revoked)`

1. Decode. No magic: verify as v1 and stop. Non-canonical, too large, or unknown variant: refuse.
2. `links` non-empty; `links[0].parent` is None; `links[0].issuer` is in `roots` (section 9), else
   `"capability chain does not root at an accepted authority"`.
3. For each link `i`, in order, stopping at the first failure:
   1. signature by `issuer` over `cap_bytes` (v1 rules for a V1 link) -> `"link i: invalid signature"`;
   2. temporal validity of `caveats` at `now` (v1 rule);
   3. `is_revoked(issuer, nonce)` -> `"link i: capability revoked"`;
   4. for `i > 0`, with `P = links[i-1]` and `D = P.delegate` (section 3.3 for a v1 parent):
      - `issuer == P.audience` -> `"link i: issuer is not the parent's audience"`;
      - `parent == cap_id(P)` -> `"link i: parent hash does not match the chain"`;
      - `D` is Some -> `"link i: the parent may not delegate"`;
      - `audience` is in `D.audience` -> `"link i: audience is outside the parent's grant"`;
      - `abilities_subset(abilities, D.abilities)` -> `"link i: abilities exceed the parent's grant"`;
      - if `delegate` is Some (`E`): `E.depth <= D.depth - 1` and `D.depth >= 2` -> `"link i: delegation depth exceeds the parent"`;
        `abilities_subset(E.abilities, D.abilities)` -> `"link i: grantable abilities exceed the parent"`;
        `E.audience` a subset of `D.audience` (`Any` only under `Any`) -> `"link i: grantable audience exceeds the parent"`;
      - `resource_subset(resource, P.resource)` -> `"link i: resource is broader than the parent"`, where
        `Nodes(s)` is a subset of `Any`, of `Nodes(t)` when `s` is a subset of `t`, and of `Node(n)` when `s == [n]`;
        `Node(n)` is a subset of `Nodes(t)` when `n` is in `t`; other pairs as TOKEN-FORMAT.md section 7;
      - `caveats_narrower_or_equal` (v1) and `ext_narrower_or_equal` -> `"link i: caveats are broader than the parent"`.

Ability matching is `covers` of TOKEN-FORMAT.md section 6, unchanged. Note the child's `abilities` are checked against
the parent's **grant** (`D.abilities`), not the parent's own `abilities`: holding a right and being allowed to pass it
on are separate, and a link may carry either without the other.

Narrowing is strict in the sense that matters: every link's depth is lower than its parent's, so a chain ends, and no
field of a child can exceed the same field of any ancestor (the predicates are transitive).

### 5.2 `authorize_v3(self_id, roots, self_tags, now, requester, action, token, is_revoked, burn)`

As 5.1, plus:

- each link's `resource` matches this node (`Nodes(s)`: `self_id` in `s`);
- the leaf's `audience == requester` (the requester proved that key in the transport handshake);
- some **leaf `abilities`** entry covers `action` (the leaf's `delegate.abilities` never authorize a call);
- if the effective caveats carry `Programs`: the call is a program execution (section 6.4), else
  `"capability is bound to a program"`;
- counters are charged (section 7), else `"capability used up"`.

The **effective caveats** handed to the cell are the leaf's (by narrowing they are the tightest in the chain), together
with the list of every link id carrying `Uses` or a cumulative limit.

### 5.3 Mint

A conformant minter (`ce-iam grant`) runs the checks of 5.1 step 3.4 on the new link against its parent before signing
and refuses to sign a link that would not verify. This is a courtesy to the holder; safety rests on the verifier alone.
How many children a holder mints cannot be bounded offline and does not need to be: `Uses` bounds what all of them
together can do at each node.

### 5.4 Revocation

```
REVOKE3_DOMAIN = "ce-cap-revoke-v3"
RevocationV3   = struct { issuer: Key, nonce: u64, not_after: u64 }
revoke_bytes   = len(16) || "ce-cap-revoke-v3" || RevocationV3
wire           = RevocationV3 || Sig                -- signed by issuer, rules of section 2
```

Semantics as v1: revoking `(issuer, nonce)` kills that link and everything below it. V1 revocations keep working for V1
links, including V1 links at the head of a v3 token.

## 6. Programs

A program is the exact description of what may happen. It has no loops, no branches and no variables: a list of typed
steps, each naming its node and every resource it touches. Two programs that differ in one byte have different ids.

### 6.1 Types

```
PROGRAM_DOMAIN = "ce-program-v1"

Program = struct {
  v     : u8                 -- always 1
  steps : seq<Step>          -- 1..=32
}

program_id(p) = SHA-256(len(13) || "ce-program-v1" || Program(p))

Step = enum {
  0 Install     { on: bytes32, path: string, sha256: bytes32, size: u64, mode: u32 }
  1 InstallCell { on: bytes32, verb: string, api: string, build: bytes32 }
  2 Run         { on: ResourceV3, exe: Exe, argv: seq<string>, env: seq<EnvVar>, cwd: string,
                  mode: RunMode, box: Box }
  3 Call        { on: bytes32, api: string, op: string, req_sha256: bytes32 }
  4 Sub         { program: bytes32 }
}

Exe     = enum { 0 Path { path: string, sha256: bytes32 }, 1 Output(u32) }   -- Output(i): the file step i installed
EnvVar  = struct { name: string, value: string }
RunMode = enum { 0 Once, 1 Keep }            -- Keep: supervised, restarted until the chain expires
Box     = struct {
  cpu      : u32            -- cores
  mem_mb   : u32
  wall_s   : u64            -- 0 only with RunMode::Keep
  read     : seq<string>    -- absolute paths visible read-only, besides the executable
  write    : seq<string>    -- absolute paths writable
  egress   : seq<EgressRule>          -- empty = no network
  bytes_out: u64
  bytes_in : u64
}
```

`path` and `cwd` are absolute, normalized (no `.`, `..`, `//`, trailing `/`). `mode` is the low 12 permission bits.
`InstallCell.build` is the cell build id the node's cell.install checks against a signed build statement.

### 6.2 Typing: what each step needs

A program is **well-typed under a leaf** when every step passes its row. The check is pure: it reads the program and
the verified chain, never the machine.

| Step | Ability the leaf must cover | Also required |
|---|---|---|
| `Install` | `cell.install:install-file` | `on` within the leaf's resource; `path` within `caveats.path_prefix` (v1 `within`), and a `path_prefix` MUST be set on the chain |
| `InstallCell` | `cell.install:<verb>` and `cell.install:<verb>:<api>@<short-hostname of on>` | `on` within the leaf's resource |
| `Run` | `proc.spawn:run` | `on` a subset of the leaf's resource; `exe` is `Output(i)` with `i` an earlier `Install` on the same single node, or `Path` with a hash; `box.cpu <= max_cpu`, `box.mem_mb <= max_mem_mb` when set; `box.egress` covered by the chain's `Egress` (which MUST be present if `box.egress` is non-empty); `box.bytes_*`, `box.wall_s` within the `net.egress.*` and `proc.spawn.wall_s` limits when set; every `box.read` / `box.write` path within `caveats.path_prefix` when set |
| `Call` | `<api>:<right of op>` | `on` within the leaf's resource |
| `Sub` | none itself | the body is in `TokenV3.programs`; it is well-typed under the same leaf; nesting at most 4 deep, 64 steps in total after expansion |

No ambient authority, by construction:

- a `Run` process starts with exactly `env`, `argv`, `cwd`, the files in `read`/`write`, and the network in
  `box.egress`. It inherits no environment, no open file, no credential, no wallet, no socket of its parent;
- the executable is named by hash; the runner refuses if the bytes on disk differ at start;
- a step that needs something the table does not list for it cannot be written, so it cannot be granted.

`ability_for(step)` strings above are new except the `cell.install:<verb>…` family, which is the form cell.install
checks today.

### 6.3 Binding a program into a chain

`Caveat::Programs([id, …])` on a link means: this link and everything below it may be used only to execute one of these
programs. Narrowing keeps the list shrinking, so whoever adds the caveat fixes the ceiling for the whole subtree. Leif
can bind the program himself (he approves exactly these bytes), or grant a right without it and let the grantee bind
one when it delegates ("you choose the script; the next agent runs only that").

### 6.4 Execution

`Execute { program_id, run, step }` at a node, with a token (`run` is a `u32` the caller picks to tell one execution of
the program from the next; a step runs at most once per `(leaf id, program_id, run)`):

1. `authorize_v3` for the step's ability, without charging counters yet;
2. the leaf's effective caveats carry `Programs` containing `program_id` -> else `"program is not the one granted"`;
   a token whose chain carries no `Programs` caveat can also execute a program, typed the same way;
3. the body is in `TokenV3.programs` and hashes to `program_id`; the whole program is well-typed under the leaf;
4. the step names this node; all earlier steps on this node have a completed record in the node's run log for this
   `(leaf id, program_id, run)`, and earlier steps on **other** nodes that this step depends on (`Exe::Output`) are on this
   node by rule 6.2;
5. charge counters (section 7). `Uses` with `per: Link` is charged **once per `(program, run)` at this node**, when
   the node runs its first step of that run. `Uses` with `per: Action` is charged per step, the action being the
   step's most specific ability from 6.2 (`InstallCell`: `cell.install:<verb>:<api>@<host>`). Cumulative limits are
   charged as they are consumed;
6. run the step; write the receipt.

```
Receipt = struct { program: bytes32, step: u32, node: bytes32, leaf: bytes32, ok: bool, out_sha256: bytes32, at: u64 }
          signed by the node key over len(18) || "ce-program-rcpt-v1" || Receipt
```

A failed step stops the program on that node; nothing is rolled back, and the use stays burned. Steps on different
nodes are independent unless the caller orders them by waiting for a receipt.

### 6.5 Composition

`concat(P, Q)` (the steps of `P` then `Q`, `Output` indexes of `Q` shifted) is well-typed under a leaf iff `P` and `Q`
are. `Sub` includes a program by hash without copying it. A pipeline is therefore built from audited pieces, and the
type check of the whole is the conjunction of the checks of the parts: there is no step whose authority comes from
where it sits.

## 7. Counted use

`Uses { max, per }` on a link `L` lets the subtree of `L` be exercised `max` times **at each executing node**.

```
counter_key = SHA-256( len(13) || "ce-cap-use-v1" || cap_id(L) || self_id || string(scope) )
scope       = ""                  when per == Link
            = the charged action  when per == Action
```

The charged action is the most specific right the cell checks for the call (cell.install:
`cell.install:install:talk.messages@leif-desk`); for a program step it is that step's most specific ability (6.4).

Rules:

- A link carrying `Uses` or a cumulative limit MUST have `caveats.not_after != 0` and a finite resource
  (`Node` or `Nodes`) -> else not canonical. The global bound is then `max x nodes` (x actions for `per: Action`), and
  each node enforces its share alone, offline, with no coordinator. To get "once, anywhere", name one node.
- With `per: Action`, the abilities reachable under `L` (its `abilities` and `delegate.abilities`) MUST contain no
  wildcard, so the set of actions, and with it the total, is finite.
- On use, the node takes its burn lock, reads the counter of **every** link in the chain that carries `Uses`, refuses
  if any is at its `max`, increments all of them, appends the burn records, `fsync`s, and only then acts. A crash
  between the burn and the act loses the use; it never grants a second one.
- The burn log is local to the node, append-only, readable and writable only by the enforcing service's uid:

  ```
  BurnRecord = { counter_key, count_after: u32, link: bytes32, leaf: bytes32, action: string, at: u64, not_after: u64 }
  ```

  A record may be pruned once `now > not_after + 86400`. The log also keeps the highest `at` it has seen; a node whose
  clock reads more than 300 s below that refuses every counted use (`"clock went backwards"`), so setting the clock
  back cannot revive a pruned, expired link.
- Cumulative limits (`net.egress.bytes_*`, `net.egress.conns`) use the same key with `scope = limit name` and a `u64`
  total, flushed at least every 5 s and at process exit; on restart the enforcer adds one flush interval's worth of the
  maximum rate, so a crash can only cost budget.

Replay: a token presented twice finds its counter spent. A token copied to another node is charged there only if that
node is in the link's finite resource. The transport's own Hello-nonce replay window is unchanged and separate.

## 8. Sandbox enforcement of `Run` and `Egress`

The node that runs a `Run` step (`code.box` / `agent.box` on the node, or the ce-replica agent, section 10):

1. `proc.spawn:Prepare { program_id, step }` with the spawner's token: verifies as 6.4, creates a fresh Ed25519
   **process key** held by the sandbox supervisor, and returns it. Nothing has started.
2. The spawner mints a leaf to the process key: abilities `["net.egress:connect"]` (plus any cell rights the process
   may call), `ext` no looser than its own, `delegate` None unless the process may itself delegate.
3. `proc.spawn:Start { process_key, token }`: the supervisor accepts only a leaf addressed to a process key it issued
   for that `(program_id, step)`, and starts the process in its own network, mount, pid and user namespaces.
4. Network: default drop. Outbound connections exist only through the supervisor, which allows a connection iff the
   process leaf's `Egress` (and `box.egress`, and every ancestor's, by narrowing the same or looser) has a rule for
   it. `Name`/`Suffix` rules are matched on the name the process asked the supervisor's resolver for; the connection
   goes to the address that resolver returned, never to an address the process supplies. `Cidr` rules match the
   address. DNS itself is answered only for names a rule could match. Bytes and connections are counted per section 7.
5. The process may ask the supervisor (over an inherited socket) to sign with its key, so it can call cells with its
   own leaf or, if its leaf has a `delegate`, mint a link to a child process: the chain continues as far as depth
   allows.

The process leaf is the "resources the process may use": it is one more link, verified by the same rules.

## 9. Owner roots

Every node accepts the owner's device keys as roots for v3 chains, for every api, including the own-key-only and
must-pin sets of ce-gate. File, root-owned, mode 0644, never writable by a lane or a cell uid:

```
/etc/ce-wire/owner-roots.json
{ "v": 1, "seq": 3,
  "keys": [ { "key": "p256:<66 hex>", "name": "person:leif", "device": "iphone",
              "rp_id": "<webauthn rp id or null>", "not_before": 0, "not_after": 0 } ],
  "prev": "<sha256 hex of the previous file's canonical bytes, or null>",
  "sigs": [ "<Sig hex>" ] }
```

- **Bootstrap, once per node**: local root writes `seq 1` (on nodes with host.root: a new time-locked approvable
  action `SetOwnerRoots`, signed by a key already in `/etc/host-root/approvers.json`, the same path `SetRoots` takes
  today). The keys SHOULD be the ones already in `approvers.json`. At least two device keys from the start.
- **Rotation, no per-node work**: a `RootUpdate` is the next file (`seq + 1`, `prev` = hash of the current one), signed
  by a key valid in the **current** file over `len(20) || "ce-owner-roots-v1" || canonical JSON without "sigs"`. A
  node applies an update it is shown (pushed by any peer, or carried in a call) when `seq` is exactly one higher, the
  signature verifies, and the update is at least 24 h old by its own `not_before` stamp (the same delay host.root gives
  key changes). Applying is the one privileged step and is done by the root-owned helper.
- **Lost or stolen key**: any other valid owner key signs an update removing it. If every key is lost, local root on
  each node is the only way back; that is deliberate.
- An owner key is a root only for V3 links; it cannot head a v1 chain (v1 has no P-256).
- Roots that exist today (`~/.config/ce-wire/roots`, `own-key`, mesh peers, `/etc/ce-wire/roots`) keep exactly their
  current reach for v1 and for v3 chains headed by them.

`roots` in section 5 is therefore: the owner keys, plus whatever ce-gate already accepts for the api being called.

## 10. ce-replica

A row in state.store `ce-place/desired` is today a command any writer can make every matching node run. Under this
spec a row carries `auth`: a v3 token. The node agent, before `Command::new`:

1. builds `Program { steps: [ Run { on, exe: Path{path, sha256}, argv, env, cwd, mode: Keep|Once, box } ] }` from the
   row's own fields (deterministically; the row has no field the program lacks);
2. runs 6.4 with ability `proc.spawn:run`: the chain roots at an owner key or at this node's key, the program id is in
   the chain's `Programs`, `on` matches this node, counters charged once per run (`Keep` restarts of one run are not new runs);
3. starts the command through the sandbox of section 8 with exactly `box`.

A row with no `auth`, or one that fails, is not run and is written to incident.log. Roll-out without stopping anything
that runs now: (a) report-only: the agent logs what it would refuse; (b) the rows that exist are listed once and Leif
signs one link binding exactly their program ids; (c) enforce. `host.exec` stays disabled; it gets no program path.

## 11. Audit

- **Mint**: `ce-iam grant` appends `cap.mint { link id, parent id, issuer, audience, abilities, delegate, ext,
  not_after }` to the minter's audit.log. Advisory (the minter could skip it); it is the minter's own record.
- **Use** (authoritative, written by the enforcing node with the burn, before acting): audit.log row
  `cap.use { root key, every link id, leaf audience, action, program id, step, counters after, outcome }`.
- **Refusal** of a v3 chain for a wrong root, a spent counter, a program mismatch or an egress attempt outside the
  rules: incident.log, with the same fields and the rule that refused.
- An owner key's signature (an approval) appears on first use as `cap.approved`, so Leif sees each of his approvals
  land.

## 12. Worked examples

Keys are written by name; `<…>` marks a value known only when the link is minted. `T` is the signing time.

### 12.1 The Raspberry Pi

Leif lets planner let one other agent install one Python script on `pi-01`, and nothing else.

```
P_pi = Program { v: 1, steps: [
  Install { on: pi-01, path: "/opt/x/run.py", sha256: <sha256 of run.py>, size: <bytes>, mode: 0o755 } ] }
id_pi = program_id(P_pi)

L0  issuer: P256(leif-iphone)       audience: Ed25519(planner)
    abilities: []                   resource: Node(pi-01)
    caveats: { not_after: T+7d, path_prefix: "/opt/x" }
    ext: [ Uses{max: 1, per: Link}, Programs([id_pi]) ]
    delegate: { abilities: ["cell.install:install-file"], audience: Any, depth: 1 }
    parent: None                    sig: WebAuthn (Approvals card) or P256

L1  issuer: Ed25519(planner)   audience: Ed25519(agent B)
    abilities: ["cell.install:install-file"]    resource: Node(pi-01)
    caveats: { not_after: T+1d, path_prefix: "/opt/x" }
    ext: [ Uses{max: 1, per: Link}, Programs([id_pi]) ]
    delegate: None                  parent: cap_id(L0)      sig: Ed25519

token = hex( "CEC3" || [V3(L0), V3(L1)] || [P_pi] )
```

Agent B calls `cell.install Execute { program_id: id_pi, run: 1, step: 0 }` on pi-01 with the token and the file bytes. pi-01
checks: L0's issuer is in its owner roots; L1 fits inside L0's grant; `id_pi` is in `Programs`; the path is under
`/opt/x`; the counter of L0 and of L1 is 0; burns both; checks the bytes hash to `sha256`; writes the file 0755.
What is refused: planner using the right itself without minting to itself (L0 has no `abilities`); B passing it on
(L1 has no `delegate`); another path, another hash, another node, a second install, running the script (no
`proc.spawn:run` anywhere in the chain).

### 12.2 The long chain: Leif -> a friend -> the friend's agent -> a Python process -> the internet

On Leif's node `box-1` (a code.box node), for one day.

```
P_job = Program { v: 1, steps: [
  Install { on: box-1, path: "/srv/jobs/f/job.py", sha256: <h>, size: <n>, mode: 0o755 },
  Run { on: Node(box-1), exe: Output(0), argv: ["job.py"], env: [], cwd: "/srv/jobs/f", mode: Once,
        box: { cpu: 1, mem_mb: 512, wall_s: 600, read: [], write: ["/srv/jobs/f/out"],
               egress: [ { host: Name("api.example.org"), ports: [443], proto: Tcp } ],
               bytes_out: 10_000_000, bytes_in: 100_000_000 } } ] }

L0  Leif -> friend
    issuer: P256(leif-iphone)       audience: Ed25519(friend)       abilities: []
    resource: Node(box-1)
    caveats: { not_after: T+1d, max_cpu: 2, max_mem_mb: 1024, path_prefix: "/srv/jobs/f" }
    ext: [ Uses{max: 5, per: Link},
           Limits([net.egress.bytes_in: 500_000_000, net.egress.bytes_out: 50_000_000, proc.spawn.wall_s: 3600]),
           Egress([ { Suffix(".example.org"), [443], Tcp } ]) ]
    delegate: { abilities: ["cell.install:install-file", "net.egress:connect", "proc.spawn:run"],
                audience: Any, depth: 2 }

L1  friend -> friend's agent
    issuer: Ed25519(friend)         audience: Ed25519(friend-agent)
    abilities: ["cell.install:install-file", "proc.spawn:run"]
    resource: Node(box-1)
    caveats: { not_after: T+12h, max_cpu: 1, max_mem_mb: 512, path_prefix: "/srv/jobs/f" }
    ext: [ Uses{max: 2, per: Link},
           Limits([net.egress.bytes_in: 100_000_000, net.egress.bytes_out: 10_000_000, proc.spawn.wall_s: 600]),
           Egress([ { Name("api.example.org"), [443], Tcp } ]) ]
    delegate: { abilities: ["net.egress:connect"], audience: Any, depth: 1 }
    parent: cap_id(L0)

    -- the agent presents [L0, L1] + P_job: Execute run 1 step 0 (install), then Prepare for step 1 -> process key K

L2  friend's agent -> the process
    issuer: Ed25519(friend-agent)   audience: Ed25519(K)            abilities: ["net.egress:connect"]
    resource: Node(box-1)
    caveats: as L1                  ext: as L1, plus Programs([program_id(P_job)])
    delegate: None                  parent: cap_id(L1)

    -- Start { process_key: K, token: [L0, L1, L2] + P_job }
```

Each link narrows: 5 runs become 2, any `*.example.org` host becomes one, 500 MB becomes 100 MB, two more links become
one and then none. The friend's agent can run its script twice; the script can open TLS to `api.example.org` and
nothing else, for 10 minutes and 100 MB; the supervisor on box-1 enforces that from L2, and box-1 never needed to know
the friend, the agent or the script beforehand. The friend signs with his own key on his own machine; Leif signs once.

### 12.3 First real use

Leif approves: "planner may grant cell.install manage and install on leif-desk and the MacBook for the cells
talk.messages, feed.view and feed.att, once each."

```
L0  issuer: P256(leif-iphone)       audience: Ed25519(planner)       abilities: []
    resource: Nodes([leif-desk, macbook])
    caveats: { not_after: T+7d }
    ext: [ Uses{max: 1, per: Action} ]
    delegate: { audience: Any, depth: 1, abilities: [
      "cell.install:install", "cell.install:manage",
      "cell.install:install:feed.att@<desk>",      "cell.install:install:feed.att@<mac>",
      "cell.install:install:feed.view@<desk>",     "cell.install:install:feed.view@<mac>",
      "cell.install:install:talk.messages@<desk>", "cell.install:install:talk.messages@<mac>",
      "cell.install:manage:feed.att@<desk>",       "cell.install:manage:feed.att@<mac>",
      "cell.install:manage:feed.view@<desk>",      "cell.install:manage:feed.view@<mac>",
      "cell.install:manage:talk.messages@<desk>",  "cell.install:manage:talk.messages@<mac>" ] }
```

`<desk>` and `<mac>` are the two short hostnames. "Once each" is read as: each of the twelve specific rights once
(the charged action is the specific right; the two bare `cell.install:<verb>` entries are what ce-gate checks first and
are not the charged action). planner then mints, per install, a leaf to the lane that does it, for example:

```
L1  issuer: Ed25519(planner)   audience: Ed25519(installer lane)
    abilities: ["cell.install:install", "cell.install:install:talk.messages@<desk>"]
    resource: Node(leif-desk)       caveats: { not_after: T+1h }
    ext: [ Uses{max: 1, per: Action}, Programs([ program_id(Program{ steps: [
             InstallCell { on: leif-desk, verb: "install", api: "talk.messages", build: <build id> } ] }) ]) ]
    delegate: None                  parent: cap_id(L0)
```

Needed on leif-desk and the MacBook before this works: owner roots bootstrapped (section 9), a ce-gate and
cell.install that verify v3 and accept an owner-rooted chain for the own-key-only `cell.install`, and a signed build
statement for each build.

## 13. Compatibility and versioning

- v1 tokens, v1 revocations and the v1 golden vectors: unchanged bytes, unchanged results. A v3-capable verifier runs
  the v1 algorithm on any token without the magic.
- v2 hash-id caps of ce-gate (`cap_hash.rs`): unchanged; they are a different format with their own domain.
- A verifier that does not know v3 refuses v3 tokens (decode error). No v3 token is ever silently weakened into a v1
  reading.
- Adding a `Caveat`, `Step`, `Key` or `Sig` variant appends a variant index; old v3 verifiers refuse tokens that use
  it. Changing the layout of an existing type needs a new domain tag (`ce-cap-v4`, `ce-program-v2`).
- Vectors to ship with the implementation: one per refusal message in section 5, the three chains of section 12 with
  fixed test keys, a v1-headed mixed chain, a P-256 and a WebAuthn root, counter exhaustion, and program typing
  failures for each row of 6.2.
