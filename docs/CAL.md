# CAL, the cell auth language

Status: **implemented in this crate (`src/cal`), CLI `ce-cal`, SDKs for Rust, TypeScript and Python** (2026-11-15).
CAL is the readable text form of the v3 capability links and programs of
[CAPABILITY-PROGRAMS.md](CAPABILITY-PROGRAMS.md). It compiles to them, decompiles from them, explains them in plain
English and checks a request against them. It adds no authority of its own: a CAL file means exactly the links it
compiles to, and the verifier of CAPABILITY-PROGRAMS.md section 5 is the only judge.

Leif, 2026-11-15: "this is like a programming language or scripting language or sdk for all languages? the cell auth
language - the 'cal' maybe. make it simple and intuitive to use and verify." And: "cal needs to use ce-ref properly with
crypto hashes. 'run.py' is ambiguous across the mesh, we need the ref system".

The command is `ce-cal` (the Unix `cal` prints a calendar); files end in `.cal`.

## 1. A first look

```
# Leif lets a friend let any agent run one exact script on pi-01, once, before December,
# reaching one host, only after reading a chat thread, through the printer's guard,
# co-signed by the auth guard.
person:leif grants person:friend {
  may grant cell.install:install-file, proc.spawn:run to anyone depth 2
  on node:pi-01
  until 2026-12-01
  files under /opt/huey
  once
  only {
    install repo:huey-scripts/run.py@3f2a1c sha256:9b1e… to /opt/huey/run.py on node:pi-01 mode 755
    spawn repo:huey-scripts/run.py@3f2a1c sha256:9b1e… on node:pi-01 once { egress api.example.org:443; out 10MB; time 1h }
  }
  egress api.example.org:443
  limit net.egress.bytes_out 10MB
  limit proc.spawn.wall_s 1h
  require read wechat:thread/123 by cell:wechat.read@1 within 10m
  via agent:printer-guard
  cosign agent:auth-guard
}
```

(`sha256:9b1e…` is shortened for the page. CAL itself refuses a shortened hash and answers with the whole one.)

Every name is a ce-ref (section 3): `run.py` alone would be a different file on every machine of the mesh, so CAL names
it by repository, commit and content hash, and the compiled link stores only the hash. Complete, tested files are in
[`examples/`](../examples): [the Raspberry Pi](../examples/raspberry-pi.cal), [the long chain](../examples/long-chain.cal),
[the WeChat-read rule](../examples/wechat-read.cal), [the 3d printer broker rule](../examples/printer-broker.cal),
[the guard that co-signs and brokers](../examples/door-guard.cal) and [the feed-cell install](../examples/feed-cell-install.cal),
each with its `ce-cal explain` output beside it (`*.explain.txt`, checked by `tests/cal_examples.rs`).

## 2. Grammar

### 2.1 Lexical

A file is UTF-8. Whitespace separates tokens; a newline or `;` ends a clause or a step; `#` at the start of a token
begins a comment to the end of the line. `{` `}` `,` are tokens of their own; `"..."` is a string with the escapes
`\"` `\\` `\n` `\t`. A list may continue on the next line after a comma. Every other run of characters is a word.
Numbers may contain `_`. Amounts take a unit: sizes `B KB MB GB TB` (decimal) and `KiB MiB GiB TiB` (binary);
durations `s m h d w`; memory is always written in `MB`. Times are UTC: `2026-12-01` (midnight), `2026-12-01T12:30Z`,
`2026-12-01T12:30:05Z`, or `@<unix seconds>`.

### 2.2 Syntax (EBNF)

```
file       = { sep } [ "cal" "1" sep ] { ( program | link ) { sep } } ;
sep        = NEWLINE | ";" ;

program    = "program" NAME steps ;
steps      = "{" { sep } step { sep step } { sep } "}" ;
link       = principal "grants" principal "{" { sep } { clause { sep } } "}" ;

clause     = "can" ability { "," ability }
           | "may" "grant" ability { "," ability } "to" ( "anyone" | principal { "," principal } ) [ "depth" INT ]
           | "on" resource
           | "until" TIME | "for" DURATION | "not" "before" TIME
           | "once" | "uses" INT [ "per" ( "link" | "action" ) ]
           | "limit" LIMIT_NAME AMOUNT
           | "egress" ( "none" | rule { "," rule } )
           | "cpu" INT | "memory" MEMORY | "credits" INT | "ports" ( "none" | INT { "," INT } )
           | "files" "under" ABS_PATH
           | "only" progref { "," progref }
           | "require" "read" thread "by" party [ "within" DURATION ]
           | "require" "fact" FACT_NAME "=" ( STRING | "hex:" HEX ) "by" party [ "within" DURATION ]
           | "cosign" principal
           | "via" party
           | "nonce" INT
           | "inherit" "nothing" ;

step       = "install" file "to" ABS_PATH "on" node [ "mode" OCTAL ]
           | ( "install" | "upgrade" ) cell "build" SHA256 "on" node
           | "spawn" ( file [ "at" ABS_PATH ] | "step" INT ) "on" resource [ "once" | "keep" ] { opt } [ optblock ]
           | "call" cell OP "on" node "body" SHA256
           | "include" progref ;
optblock   = "{" { sep } { opt { opt } sep } "}" ;
opt        = "args" STRING { STRING } | "env" NAME STRING | "cwd" ABS_PATH | "cpu" INT | "memory" MEMORY
           | "time" DURATION | "read" ABS_PATH { "," ABS_PATH } | "write" ABS_PATH { "," ABS_PATH }
           | "egress" rule { "," rule } | "out" SIZE | "in" SIZE ;

resource   = "any" "node" | node { "," node } | "nodes" node { "," node }
           | "nodes" "tagged" ( TAG | "all" "of" TAG { "," TAG } ) ;
progref    = NAME | "program:" HEX64 | steps ;
rule       = HOST ":" PORT { "+" PORT } [ "/udp" | "/tcp" ] ;      (* api.example.org:443, *.example.org:443,
                                                                    10.0.0.0/8:22, [2001:db8::]/32:443+80 *)
ability    = API ":" RIGHT | "*" ;

(* refs, section 3 *)
principal  = ( "person:" ID | "agent:" LANE | "node:" NAME ) [ KEY ] | KEY ;
KEY        = "ed25519:" HEX64 | "p256:" HEX66 ;
node       = "node:" HEX64 | "node:" NAME [ "ed25519:" HEX64 ] ;
file       = ( "repo:" REPO "/" PATH "@" COMMIT | "ce-ref://repo/" HEX64 "/" PATH ) [ SHA256 ] [ "size" INT ]
           | "ce-blob:" SHA256 [ "size" INT ] ;
SHA256     = "sha256:" HEX64 ;
cell       = "cell:" API [ "@" MAJOR ] ;
party      = principal | cell ;
thread     = SOURCE ":thread/" ID [ "@" MESSAGE ] | "doc:" REPO "/" PATH [ "@" COMMIT ] | "ce-ref://repo/" HEX64 "/" PATH ;
```

`NAME` (a program) starts with a letter and holds letters, digits, `_`, `-`. `COMMIT` is 4 to 40 lowercase hex digits.
`ABS_PATH` is absolute and normalized (no `.`, `..`, `//`, trailing `/`): it is a path **on the executing node**, inside
the sandbox the link sets, not a name of a thing (a thing is a ref).

### 2.3 Links and inheritance

`<issuer> grants <audience> { ... }` is one link; the links of a file are one chain, root first. The issuer of every
link below the root must be the audience of the link above it (the verifier requires it, and CAL says so at compile).

| Clause | Link field (CAPABILITY-PROGRAMS.md) |
|---|---|
| `can a, b` | `abilities`: what the audience may itself do (absent = nothing: "may grant, may not use") |
| `may grant a, b to anyone \| <principals> depth n` | `delegate` (absent = final: nothing may be granted below); `depth` defaults to 1 |
| `on ...` | `resource`: `node:a` is `Node`, two or more nodes or `nodes ...` is `Nodes`, `nodes tagged t` is `Tag`, `nodes tagged all of ...` is `AllOf`, `any node` is `Any` |
| `until`, `for`, `not before` | `caveats.not_after` (`for d` = compile time + d), `caveats.not_before` |
| `files under`, `cpu`, `memory`, `credits`, `ports` | `caveats.path_prefix`, `max_cpu`, `max_mem_mb`, `max_credits`, `allowed_ports` |
| `once` / `uses n [per link\|per action]` | `Uses { max, per }` (`once` = `uses 1 per link`) |
| `limit name amount` | one entry of `Limits` |
| `egress ...` / `egress none` | `Egress` (none = an empty list: no network at all) |
| `only p, q` | `Programs` |
| `require read ... / require fact ...` | one entry of `Requires` |
| `cosign <principal>` | one entry of `CoSign` (`per: Use`) |
| `via <party>` | one entry of `Via` |
| `nonce n` | `nonce` (absent: a random one; `decompile` always writes it) |

**Inheritance.** The root starts from nothing and must say where it applies (`on`). A link below it starts from its
parent's resource and every caveat of its parent, because a child must carry them anyway; a clause then replaces that
value (it may only narrow, which compile checks), `limit` replaces or adds one name, and `require`, `cosign` and `via`
add to the inherited conditions (a `require` with the same witness and claim replaces the inherited one, with a fresher
bound). Abilities, `may grant` and `nonce` are never inherited. `inherit nothing` starts a link from nothing; it exists
so that `decompile` can write a link that drops something of its parent's (which every verifier refuses), and `check`
can show why.

### 2.4 Programs and steps

`program <name> { ... }` defines a program; `only <name>` binds it, `only { ... }` defines and binds one in place,
`include <name>` makes it a `Sub` step of another. A program that is defined and never used is an error.

- `install <file> to <path> on <node> [mode 755]`: `Install { on, path, sha256, size, mode }`; mode defaults to 644.
- `install|upgrade cell:<api> build sha256:<id> on <node>`: `InstallCell`; the build id pins the exact build.
- `spawn <file> on <nodes> [once|keep] { ... }`: `Run` of the file the program installed earlier on that node
  (`Exe::Output` of the latest such install); `spawn <file> at <path>` runs a file already at `<path>` (`Exe::Path`, the
  runner checks its hash); `spawn step i` names the install step. Defaults: `args` = the file's name, no environment, a
  private working directory, 1 CPU, 512MB, `time 10m` (no limit with `keep`), no network, `out 0`, `in 0`.
- `call cell:<api> <Op> on <node> body sha256:<hash>`: `Call`: exactly one request, by the hash of its bytes.

## 3. References

Every thing a CAL file names is a ce-ref, never a bare name or path, and every ref is compiled to a **pinned** form. The
compiled link stores only the pinned forms (hashes, full ids, keys), so its meaning never depends on where it is read.

| Written | Pinned | Rule |
|---|---|---|
| `repo:<repo>/<path>@<commit> sha256:<hash>` | the content hash and size | the commit and the whole hash are required; the resolver must confirm the hash. The file's identity is the portable ref `ce-ref://repo/<sha256 of the normalized git origin>/<path>` (ce-ref `docs/GLOBAL-FILES.md`, the same ids as ce-ref's `portable.py`) |
| `ce-ref://repo/<id>/<path> sha256:<hash>` | the same | the portable ref written directly: never ambiguous |
| `ce-blob:sha256:<hash> [size n]` | the hash | content that is in no repository; the hash is its identity |
| `node:<name>` | the full node id | must resolve to exactly one node |
| `node:<64 hex>` | itself | |
| `person:<id>`, `agent:<lane>`, `node:<name>` as a principal | the public key | must resolve to exactly one key |
| `ed25519:<64 hex>`, `p256:<66 hex>` | itself | a key is its own pin; it may follow a ref: `person:leif p256:02…` |
| `cell:<api>@<major>` | the string `<api>@<major>` | the major version is required for a party (`via`, `require ... by`); the node resolves that exact string to the keys it trusts |
| `wechat:thread/<id>[@<msg>]` | `ReadThrough { "wechat", <id>, <msg> }` | any `<source>:thread/<id>` the same way |
| `doc:<repo>/<path>[@<commit>]` | `ReadThrough { "doc", "ce-ref://repo/<id>/<path>.md", <commit> }` | the document by its portable ref |

`program:<64 hex>` names a program by id. Abilities (`cell.install:install-file`) and limit names are rights and units
of the verifier, not things, and are written as they are.

### 3.1 Refusals

`ce-cal compile` refuses, with the line, the reason and a suggestion:

- a bare name or path: `'friend' is a bare name; write person:friend or agent:friend`, `'run.py' is a bare path: it names a different file on every machine`;
- an unpinned ref: a file without a content hash (the suggestion is the hash the resolver sees, to approve), a repo
  file without a commit, a principal or node the resolver does not know (the suggestion is the pinned form to write),
  a cell party without its major;
- a shortened hash (`sha256:9b1e…`): the suggestion is the whole hash, when the resolver knows the file;
- an ambiguous ref: a node name with two ids, a principal with two keys, a repository name two origins share, a
  `repo:a/b/c` that splits into two known repositories: the suggestion lists each candidate in its pinned form;
- a pin the resolver contradicts: `content hash mismatch`, `size mismatch`, `pin mismatch`;
- a link the verifier would refuse (canonical form, CAPABILITY-PROGRAMS.md 3.4 and 7; narrowing, 5.1), with the
  verifier's message and, in plain English, what exactly is broader than the parent.

### 3.2 Resolvers

A `Resolver` answers each lookup with a list: empty is unknown, one is the pin, more than one is ambiguous. The offline
one is the **ref book**; `ce-cal --ce-ref` puts the live ce.ref resolver over it for repository files (`ce cell call
ref.index Repositories` / `Resolve`, the ce.ref cell; its verdicts `PASS`, `FAIL` and `CANNOT DETERMINE` are kept, so
an index that cannot answer is a refusal, never an empty answer). Reverse lookups give `explain` and `decompile` the
readable names.

### 3.3 The ref book

A JSON file (`--refs`, default `./cal.refs.json`); every value is a list, so the book can record an ambiguity:

```json
{
  "principals": { "person:leif": ["p256:<66 hex>"], "agent:printer-guard": ["ed25519:<64 hex>"] },
  "nodes":      { "pi-01": ["<64 hex node id>"] },
  "repos":      { "huey-scripts": ["https://github.com/<owner>/huey-scripts"] },
  "files":      { "ce-ref://repo/<id>/run.py": [ { "sha256": "<64 hex>", "size": 26, "commit": "<40 hex>" } ] },
  "blobs":      { "<sha256 hex>": 26 },
  "cells":      { "printer3d.gate@1": ["ed25519:<64 hex>"] },
  "roots":      ["person:leif"]
}
```

`cells` and `roots` are what `check` acts as the node with: the keys it trusts per cell party and its root keys.
[`examples/cal.refs.json`](../examples/cal.refs.json) is the book of the examples, with the fixed test keys of
CAPABILITY-PROGRAMS.md 12.5.

## 4. Compile

`ce-cal compile file.cal` pins every ref (section 3), builds each program and link (2.3, 2.4), sorts every list the
format keeps sorted, and checks each link as the minter does (CAPABILITY-PROGRAMS.md 5.3): canonical form, and below
the root every narrowing check of 5.1 step 3.4, with the same functions the verifier runs. The output is a **draft**:

```json
{ "cal_draft": 1,
  "links": [ { "id": "<cap_id hex>", "issuer": "p256:…", "cap": "<CapabilityV3 hex>", "sig": null } ],
  "programs": [ "<Program hex>" ] }
```

Each issuer signs its own link, on its own machine (`ce-cal sign draft.json --key <file>`, or `--key` on compile);
when the last link is signed the command prints the token (lowercase hex, CAPABILITY-PROGRAMS.md 3.2). The link ids do
not depend on the signatures, so every party can check the id of the link it signs.

The examples prove the compiler against the conformance vectors: [raspberry-pi.cal](../examples/raspberry-pi.cal),
[long-chain.cal](../examples/long-chain.cal) and [feed-cell-install.cal](../examples/feed-cell-install.cal) compile to
exactly the links of vectors `pi-install-once`, `long-process-key` and `first-use-six-installs`, and signed with the
same test keys give the same token bytes (`tests/cal_examples.rs`).

## 5. Explain

`ce-cal explain <file.cal | token | draft>` prints what the chain allows and requires, link by link: each link's id,
issuer and audience (readable ref = pinned key), what the audience may do itself and may grant (to whom, how deep),
where, when, every limit, every condition and the programs it is bound to; then each program step by step, with every
file as its readable ref, its portable ref and its content hash, and the hash check the executor makes before acting;
whether the programs type under the leaf; and in short what the holder may do and what every use must prove. It is
generated from the compiled links, never from the source, so it says what a verifier will read.

## 6. Decompile

`ce-cal decompile <token | draft>` writes a token as CAL: every value in its pinned form, with the readable ref beside
it when the ref book knows one (`person:leif p256:…`, `node:pi-01 ed25519:…`). Below the root a link is written as
what differs from its parent (2.3); a link that drops something of its parent's is written in full after `inherit
nothing`. Without a ref book the output names only keys, ids and `ce-blob:` hashes and compiles back on any machine
with no resolver at all; `tests/cal_examples.rs` checks both round trips for every example.

## 7. Check

`ce-cal check <token> --node <node> --as <principal> (--do <ability> | --program <id> [--step i] [--run n])`
runs `authorize_v3` (or, with `--request` and `--proofs`, `authorize_use_v3`) of CAPABILITY-PROGRAMS.md 5.2 as that
node would, with the ref book's `roots` and `cells`, and prints `ALLOWED` or `REFUSED: <the verifier's reason>`
followed by why, in plain English: which link refuses and what in it is broader than its parent, who holds the chain
and who asked, which condition was not met and what proof it needs. With `--content <file>` it also does what the
executor does before acting: the bytes must hash to the pinned sha256 (and have its size), else
`content hash mismatch`. It is a dry run on a node with no earlier uses: no counter is charged and no request id
recorded. Exit 0 allowed, 1 refused.

## 8. SDKs

Every SDK is a thin wrapper over one JSON entry point, `ce_net_proto::cal::api::call(op, request) -> response`, so all
give the Rust crate's answers:

| op | request | response |
|---|---|---|
| `parse` | `{source}` | `{formatted}` |
| `compile` | `{source, refs?, now?, nonces?}` | `{draft, ids, programs}` |
| `sign` | `{draft, key}` | `{draft, signed, token}` |
| `explain` | `{source \| token \| draft, refs?, now?}` | `{text}` |
| `decompile` | `{token \| draft, refs?}` | `{source}` |
| `verify` | `{token, node, as, do \| program+step+run, now?, request?, proofs?, body?, content?, refs?}` | `{allowed, reason, why, text}` |

A refusal is `{"ok": false, "error": {"line", "message", "suggestion"}}`.

- **Rust**: this crate, module `cal` ([`examples/explain.rs`](../examples/explain.rs), `cargo run --example explain`).
- **TypeScript / JavaScript**: [`sdk/ts`](../sdk/ts), the wasm-bindgen build of the crate with typed calls
  (`ce-cal.ts`, [`example.ts`](../sdk/ts/example.ts)).
- **Python and any C FFI**: [`sdk/python`](../sdk/python), the C ABI `ce_cal_call` / `ce_cal_free`
  ([`ce_cal.h`](../sdk/python/ce_cal.h)); Python calls it through `ctypes` (the ctypes package itself is not in this
  repository yet).

The wrappers draw link nonces from the platform's CSPRNG; the crate draws no randomness.

## 9. CLI

```
ce-cal fmt <file.cal>                       the file in canonical layout
ce-cal compile <file.cal> [--key <file>]... a draft, or the token once every link is signed
ce-cal sign <draft.json> --key <file>       sign the links whose issuer is that key
ce-cal explain <file.cal | token | draft>
ce-cal decompile <token | draft>
ce-cal check <token> --node <node> --as <principal> (--do <ability> | --program <id> [--step i] [--run n])
             [--request <hex>] [--proofs <hex>] [--body <file>] [--content <file>]
common: --refs <book.json>  --ce-ref  --now <unix secs | date>  -o <file>
```

A key file holds `ed25519:<64 hex seed>` or `p256:<64 hex scalar>`. Exit status 0 ok or allowed, 1 refused or invalid,
2 usage.
