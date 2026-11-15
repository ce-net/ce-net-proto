//! The syntax tree of a CAL file (`docs/CAL.md` section 2). It holds what was written, refs
//! unresolved; [`super::compile`] pins them. The printer ([`super::print`]) writes it back in the
//! one canonical layout, so `parse(print(f)) == f`.

use crate::program::Hash;
use crate::v3::{Key, UsePer};

/// One `.cal` file: named programs, then the links of one chain, root first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct File {
    pub programs: Vec<ProgramDef>,
    pub links: Vec<LinkDef>,
}

/// `program <name> { <step>... }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramDef {
    pub name: String,
    pub steps: Vec<StepDef>,
    pub line: usize,
}

/// A principal as written: a ref (`person:leif`, `agent:printer-guard`, `node:pi-01`) with an
/// optional key pin, or a bare key (`ed25519:<hex>`), which is its own pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalRef {
    /// The ref text; empty for a bare key.
    pub name: String,
    pub pin: Option<Key>,
}

/// A node as written: `node:<name>` (optionally pinned) or `node:<64 hex>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRef {
    /// The name after `node:`; empty when written as a full id.
    pub name: String,
    pub pin: Option<[u8; 32]>,
}

/// A content hash as written after `sha256:`; the full 64 digits, or a prefix (refused at
/// compile, with the full hash as the suggestion when it can be found).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashPin {
    Full(Hash),
    Prefix(String),
}

/// Where a file comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSource {
    /// `repo:<repo>/<path>@<commit>`: `spec` is `<repo>/<path>`, split by the resolver.
    Repo { spec: String, commit: Option<String> },
    /// `ce-ref://repo/<id>/<path>`.
    Portable(String),
    /// `ce-blob:sha256:<hash>`: the hash is the identity.
    Blob,
}

/// A file: its source, its content hash and, when written, its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRef {
    pub source: FileSource,
    pub sha: Option<HashPin>,
    pub size: Option<u64>,
}

/// `cell:<api>[@<major>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellRef {
    pub api: String,
    pub major: Option<u32>,
}

/// Who vouches in a condition: a principal, or a cell (resolved by the executing node).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartyRef {
    Principal(PrincipalRef),
    Cell(CellRef),
}

/// A thread or document that must have been read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadRef {
    /// `<source>:thread/<id>[@<msg>]`, e.g. `wechat:thread/123`.
    Thread { source: String, thread: String, upto: Option<String> },
    /// `doc:<repo>/<path>[@<commit>]` or `ce-ref://repo/<id>/<path>[@<commit>]`.
    Doc { spec: String, upto: Option<String> },
}

/// One `require` clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequireDef {
    Read { what: ThreadRef, by: PartyRef, within: Option<u64> },
    Fact { name: String, value: Vec<u8>, by: PartyRef, within: Option<u64> },
}

/// One egress rule: `host:port[+port...][/udp]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDef {
    /// `api.example.org`, `*.example.org`, `10.0.0.0/8`, `[2001:db8::]/32`.
    pub host: String,
    pub ports: Vec<u16>,
    pub udp: bool,
}

/// Where a link or a `spawn` applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceDef {
    /// `on any node`.
    Any,
    /// `on node:a`.
    Node(NodeRef),
    /// `on nodes node:a, node:b` (or `on node:a, node:b`).
    Nodes(Vec<NodeRef>),
    /// `on nodes tagged t`.
    Tag(String),
    /// `on nodes tagged all of t1, t2`.
    AllOf(Vec<String>),
}

/// A program named in `only` or `include`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgRef {
    /// A `program` defined in this file.
    Name(String),
    /// `program:<64 hex>`: an id whose body is not in this file.
    Id(Hash),
    /// `only { <steps> }`: an anonymous program written in place.
    Inline(Vec<StepDef>),
}

/// The sandbox and arguments of a `spawn` (`docs/CAL.md` section 2.4); `None` = the default.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpawnOpts {
    pub args: Option<Vec<String>>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    pub cpu: Option<u32>,
    pub memory_mb: Option<u32>,
    pub time_s: Option<u64>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub egress: Vec<EgressDef>,
    pub bytes_out: Option<u64>,
    pub bytes_in: Option<u64>,
}

/// One program step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepDef {
    /// `install <file> to <path> on <node> [mode 755]`.
    Install { file: FileRef, to: String, on: NodeRef, mode: u32, line: usize },
    /// `install|upgrade cell:<api> build sha256:<hash> on <node>`.
    InstallCell { verb: String, cell: CellRef, build: HashPin, on: NodeRef, line: usize },
    /// `spawn <file> [at <path>] on <nodes> [once|keep] [options]`, or `spawn step <i> ...`.
    Spawn { exe: SpawnExe, on: ResourceDef, keep: bool, opts: SpawnOpts, line: usize },
    /// `call cell:<api> <op> on <node> body sha256:<hash>`.
    Call { cell: CellRef, op: String, on: NodeRef, body: HashPin, line: usize },
    /// `include <program>`.
    Include { program: ProgRef, line: usize },
}

/// What a `spawn` runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnExe {
    /// A file: installed earlier in the program on that node (no `at`), or already at `at`.
    File { file: FileRef, at: Option<String> },
    /// `spawn step <i>`: the file step `i` installed.
    Step(u32),
}

/// One link: `<issuer> grants <audience> { <clause>... }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkDef {
    pub issuer: PrincipalRef,
    pub audience: PrincipalRef,
    pub clauses: Vec<Clause>,
    pub line: usize,
}

/// Who a link may grant to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudienceDef {
    Anyone,
    Some(Vec<PrincipalRef>),
}

/// One clause of a link (`docs/CAL.md` section 2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Clause {
    /// `can a, b`: what the audience may itself do.
    Can(Vec<String>, usize),
    /// `may grant a, b to <audience> [depth n]`.
    MayGrant { abilities: Vec<String>, to: AudienceDef, depth: u8, line: usize },
    On(ResourceDef, usize),
    /// `until <time>` / `for <duration>`.
    Until(TimeDef, usize),
    /// `not before <time>`.
    NotBefore(TimeDef, usize),
    /// `once` (= `uses 1 per link`), `uses n [per link|per action]`.
    Uses { max: u32, per: UsePer, line: usize },
    /// `limit <api.name> <amount>`.
    Limit { name: String, max: u64, line: usize },
    /// `egress <rule>, ...` or `egress none`.
    Egress(Vec<EgressDef>, usize),
    Cpu(u32, usize),
    MemoryMb(u32, usize),
    Credits(u64, usize),
    /// `ports 22, 443`: the v1 tunnel port list.
    Ports(Vec<u16>, usize),
    /// `files under /path`.
    FilesUnder(String, usize),
    /// `only <program>, ...`.
    Only(Vec<ProgRef>, usize),
    Require(RequireDef, usize),
    CoSign(PrincipalRef, usize),
    Via(PartyRef, usize),
    Nonce(u64, usize),
    /// `inherit nothing`: this link starts from no caveats instead of its parent's.
    InheritNothing(usize),
}

/// A time as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeDef {
    /// Unix seconds.
    At(u64),
    /// `for <duration>`: that long after the compile time.
    For(u64),
}

impl Clause {
    pub fn line(&self) -> usize {
        match self {
            Clause::Can(_, l)
            | Clause::On(_, l)
            | Clause::Until(_, l)
            | Clause::NotBefore(_, l)
            | Clause::Egress(_, l)
            | Clause::Cpu(_, l)
            | Clause::MemoryMb(_, l)
            | Clause::Credits(_, l)
            | Clause::Ports(_, l)
            | Clause::FilesUnder(_, l)
            | Clause::Only(_, l)
            | Clause::Require(_, l)
            | Clause::CoSign(_, l)
            | Clause::Via(_, l)
            | Clause::Nonce(_, l)
            | Clause::InheritNothing(l) => *l,
            Clause::MayGrant { line, .. } | Clause::Uses { line, .. } | Clause::Limit { line, .. } => *line,
        }
    }
}

impl StepDef {
    pub fn line(&self) -> usize {
        match self {
            StepDef::Install { line, .. }
            | StepDef::InstallCell { line, .. }
            | StepDef::Spawn { line, .. }
            | StepDef::Call { line, .. }
            | StepDef::Include { line, .. } => *line,
        }
    }
}
