//! Capability programs: the exact, typed description of what a chain may be used for
//! (`docs/CAPABILITY-PROGRAMS.md` sections 4 and 6).
//!
//! A [`Program`] is a list of typed [`Step`]s with no loops, branches or variables. Its id is
//! `SHA-256(len(13) || "ce-program-v1" || Program)` ([`program_id`]); a v3 capability link binds
//! programs by id (`Caveat::Programs`). This module is pure: it holds the types, the canonical
//! encoding, the hash, the well-formedness rules, the typing of a program under a verified leaf
//! ([`type_check`]) and the check that a requested action is exactly a step of the program
//! ([`check_request`]). It reads no file and no clock.
//!
//! The same file is the `ce-program` crate in the `ce` repo (only this header differs); the
//! bytes and results are identical, which `ce-net-proto/tests/compat_v3.rs` proves.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A node key (Ed25519 public key, the v1 `NodeId`).
pub type NodeKey = [u8; 32];
/// A SHA-256 digest.
pub type Hash = [u8; 32];

/// Domain tag of [`program_id`].
pub const PROGRAM_DOMAIN: &[u8] = b"ce-program-v1";
/// Steps per program body.
pub const MAX_STEPS: usize = 32;
/// Steps after `Sub` expansion.
pub const MAX_EXPANDED: usize = 64;
/// `Sub` nesting.
pub const MAX_SUB_DEPTH: usize = 4;

/// Which nodes a link (or a `Run` step) applies to. Variants 0..=3 are v1 `Resource`, variant for
/// variant; `Nodes` is new in v3: a finite list of node keys, sorted ascending, unique, non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceV3 {
    Any,
    Node(NodeKey),
    Tag(String),
    AllOf(Vec<String>),
    Nodes(Vec<NodeKey>),
}

impl ResourceV3 {
    /// Does node (`id`, `tags`) fall within this set?
    pub fn matches(&self, id: &NodeKey, tags: &[String]) -> bool {
        match self {
            ResourceV3::Any => true,
            ResourceV3::Node(n) => n == id,
            ResourceV3::Tag(t) => tags.iter().any(|x| x == t),
            ResourceV3::AllOf(ts) => ts.iter().all(|t| tags.iter().any(|x| x == t)),
            ResourceV3::Nodes(ns) => ns.contains(id),
        }
    }

    /// Is `self` no broader than `parent` (section 5.1)? Conservative: a pair it cannot decide is false.
    pub fn is_subset_of(&self, parent: &ResourceV3) -> bool {
        use ResourceV3::*;
        match (self, parent) {
            (_, Any) => true,
            (Node(s), Node(p)) => s == p,
            (Nodes(s), Node(p)) => s.len() == 1 && &s[0] == p,
            (Node(s), Nodes(t)) => t.contains(s),
            (Nodes(s), Nodes(t)) => s.iter().all(|n| t.contains(n)),
            (Tag(s), Tag(t)) => s == t,
            (AllOf(s), Tag(t)) => s.contains(t),
            (AllOf(s), AllOf(ps)) => ps.iter().all(|p| s.contains(p)),
            (Tag(s), AllOf(ps)) => ps.iter().all(|p| p == s),
            _ => false,
        }
    }

    /// A finite set of nodes (`Node` or `Nodes`): required on a counted link (section 7).
    pub fn is_finite(&self) -> bool {
        matches!(self, ResourceV3::Node(_) | ResourceV3::Nodes(_))
    }

    /// The one node this names, if it names exactly one.
    pub fn single(&self) -> Option<&NodeKey> {
        match self {
            ResourceV3::Node(n) => Some(n),
            ResourceV3::Nodes(ns) if ns.len() == 1 => Some(&ns[0]),
            _ => None,
        }
    }

    pub(crate) fn canonical(&self) -> bool {
        match self {
            ResourceV3::Nodes(ns) => !ns.is_empty() && sorted_unique(ns),
            ResourceV3::AllOf(ts) => !ts.is_empty(),
            _ => true,
        }
    }
}

/// Transport protocol of an egress rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

/// A host pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostPat {
    /// One exact DNS name, lowercase, no trailing dot.
    Name(String),
    /// ".example.org": any name ending in it, not "example.org" itself.
    Suffix(String),
    /// An address block; `addr` is 4 or 16 bytes with the host bits zero.
    Cidr { addr: Vec<u8>, prefix: u8 },
}

/// One allowed outbound destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRule {
    pub host: HostPat,
    /// Sorted, unique, non-empty.
    pub ports: Vec<u16>,
    pub proto: Proto,
}

/// A named ceiling (`"<api>.<name>"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limit {
    pub name: String,
    pub max: u64,
}

/// Limit names that are counted across uses (section 4), and so make a link "counted".
pub const CUMULATIVE_LIMITS: &[&str] = &["net.egress.bytes_out", "net.egress.bytes_in", "net.egress.conns"];

fn dns_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.ends_with('.')
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && !s.contains("..")
}

impl HostPat {
    fn canonical(&self) -> bool {
        match self {
            HostPat::Name(n) => dns_ok(n) && !n.starts_with('.'),
            HostPat::Suffix(s) => s.starts_with('.') && dns_ok(&s[1..]),
            HostPat::Cidr { addr, prefix } => {
                let bits = addr.len() * 8;
                (addr.len() == 4 || addr.len() == 16) && (*prefix as usize) <= bits && host_bits_zero(addr, *prefix)
            }
        }
    }

    /// Is every destination `self` admits also admitted by `parent` (section 4 table)?
    pub fn is_covered_by(&self, parent: &HostPat) -> bool {
        match (self, parent) {
            (HostPat::Name(c), HostPat::Name(p)) => c == p,
            (HostPat::Name(c), HostPat::Suffix(p)) => c.ends_with(p.as_str()),
            (HostPat::Suffix(c), HostPat::Suffix(p)) => c.ends_with(p.as_str()),
            (HostPat::Cidr { addr: ca, prefix: cp }, HostPat::Cidr { addr: pa, prefix: pp }) => {
                ca.len() == pa.len() && cp >= pp && prefix_eq(ca, pa, *pp)
            }
            _ => false,
        }
    }
}

fn host_bits_zero(addr: &[u8], prefix: u8) -> bool {
    (prefix as usize..addr.len() * 8).all(|i| addr[i / 8] & (0x80 >> (i % 8)) == 0)
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    (0..prefix as usize).all(|i| (a[i / 8] ^ b[i / 8]) & (0x80 >> (i % 8)) == 0)
}

impl EgressRule {
    /// Covered by one rule of `parent`: same proto, ports a subset, host covered.
    pub fn is_covered_by(&self, parent: &[EgressRule]) -> bool {
        parent.iter().any(|p| p.proto == self.proto && self.ports.iter().all(|x| p.ports.contains(x)) && self.host.is_covered_by(&p.host))
    }

    fn canonical(&self) -> bool {
        self.host.canonical() && !self.ports.is_empty() && sorted_unique(&self.ports)
    }
}

/// Every rule of `child` is covered by `parent`.
pub fn egress_narrower(child: &[EgressRule], parent: &[EgressRule]) -> bool {
    child.iter().all(|c| c.is_covered_by(parent))
}

/// A canonical egress list: each rule canonical, sorted by encoding, unique.
pub fn egress_canonical(rules: &[EgressRule]) -> bool {
    rules.iter().all(EgressRule::canonical) && sorted_unique_by_encoding(rules)
}

/// Strictly ascending by value.
pub fn sorted_unique<T: Ord>(v: &[T]) -> bool {
    v.windows(2).all(|w| w[0] < w[1])
}

/// Strictly ascending by bincode encoding.
pub fn sorted_unique_by_encoding<T: Serialize>(v: &[T]) -> bool {
    let enc: Vec<Vec<u8>> = v.iter().map(|x| bincode::serialize(x).unwrap_or_default()).collect();
    enc.windows(2).all(|w| w[0] < w[1])
}

/// The executable of a `Run` step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Exe {
    /// A file already on the node, named by path and content hash (checked at start).
    Path { path: String, sha256: Hash },
    /// The file step `i` (an earlier `Install` on the same single node) installed.
    Output(u32),
}

/// One environment variable a `Run` process starts with (it inherits no other).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// `Once`: run to completion. `Keep`: supervised, restarted until the chain expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunMode {
    Once,
    Keep,
}

/// The sandbox of a `Run` step (spec name `Box`): everything the process gets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunBox {
    pub cpu: u32,
    pub mem_mb: u32,
    /// 0 only with `RunMode::Keep`.
    pub wall_s: u64,
    /// Absolute paths visible read-only, besides the executable.
    pub read: Vec<String>,
    /// Absolute paths writable.
    pub write: Vec<String>,
    /// Empty = no network.
    pub egress: Vec<EgressRule>,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// One typed step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
    /// Write one file with exactly these bytes (by hash and size) and permission bits.
    Install { on: NodeKey, path: String, sha256: Hash, size: u64, mode: u32 },
    /// cell.install's install/upgrade of a cell build (checked against a signed build statement).
    InstallCell { on: NodeKey, verb: String, api: String, build: Hash },
    /// Start a process with exactly `argv`, `env`, `cwd` and the box.
    ///
    /// `cwd` is an absolute path, or `""` = a private directory the runner chooses for this run
    /// (ce-replica: the cell's data dir).
    Run { on: ResourceV3, exe: Exe, argv: Vec<String>, env: Vec<EnvVar>, cwd: String, mode: RunMode, sandbox: RunBox },
    /// One call of `api`'s `op` with a request whose bytes hash to `req_sha256`.
    Call { on: NodeKey, api: String, op: String, req_sha256: Hash },
    /// Include another program by id (its body travels in the token).
    Sub { program: Hash },
}

/// A program: version 1, 1..=32 steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    pub v: u8,
    pub steps: Vec<Step>,
}

impl Program {
    pub fn new(steps: Vec<Step>) -> Program {
        Program { v: 1, steps }
    }

    /// Canonical bytes (bincode 1, default configuration).
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Decode, refusing trailing bytes and anything that does not re-encode to the same bytes.
    pub fn decode(b: &[u8]) -> Result<Program, String> {
        use bincode::Options;
        let p: Program = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(1 << 20)
            .deserialize(b)
            .map_err(|e| format!("malformed program: {e}"))?;
        if p.encode() != b {
            return Err("program is not canonical".into());
        }
        Ok(p)
    }

    /// [`program_id`] of this program.
    pub fn id(&self) -> Hash {
        program_id(self)
    }

    /// `concat(P, Q)` (section 6.5): the steps of `self` then `q`, `Output` indexes of `q` shifted.
    pub fn concat(&self, q: &Program) -> Program {
        let off = self.steps.len() as u32;
        let mut steps = self.steps.clone();
        steps.extend(q.steps.iter().cloned().map(|s| shift(s, off)));
        Program::new(steps)
    }
}

/// `SHA-256(len(13) || "ce-program-v1" || Program)`.
pub fn program_id(p: &Program) -> Hash {
    let b = bincode::serialize(&(PROGRAM_DOMAIN, p)).unwrap_or_default();
    Sha256::digest(&b).into()
}

fn shift(s: Step, off: u32) -> Step {
    match s {
        Step::Run { on, exe: Exe::Output(i), argv, env, cwd, mode, sandbox } => {
            Step::Run { on, exe: Exe::Output(i + off), argv, env, cwd, mode, sandbox }
        }
        s => s,
    }
}

/// Absolute and normalized: starts with `/`, no `.` or `..` component, no `//`, no trailing `/` (except "/").
pub fn path_ok(p: &str) -> bool {
    if p == "/" {
        return true;
    }
    p.starts_with('/') && !p.ends_with('/') && p[1..].split('/').all(|c| !c.is_empty() && c != "." && c != "..") && !p.contains('\0')
}

/// `child` within `parent` on a `/` boundary (the v1 `path_within`).
pub fn path_within(child: &str, parent: &str) -> bool {
    let child = child.trim_end_matches('/');
    let parent = parent.trim_end_matches('/');
    parent.is_empty() || child == parent || child.starts_with(&format!("{parent}/"))
}

/// The ability-matching rule of TOKEN-FORMAT.md section 6 (identical to `ce_cap::ability_covers`).
pub fn covers(granted: &str, needed: &str) -> bool {
    if granted == needed || granted == "*" {
        return true;
    }
    if let Some(prefix) = granted.strip_suffix('*') {
        if prefix.ends_with(':') {
            return needed.len() > prefix.len() && needed.starts_with(prefix);
        }
    }
    false
}

fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// Well-formedness of one body (section 6.1), independent of any chain: version, step count, paths,
/// modes, egress lists, and every `Output(i)` naming an earlier `Install` of the same body on the
/// `Run`'s single node.
pub fn well_formed(p: &Program) -> Result<(), String> {
    if p.v != 1 {
        return Err("program: version must be 1".into());
    }
    if p.steps.is_empty() || p.steps.len() > MAX_STEPS {
        return Err(format!("program: 1..={MAX_STEPS} steps"));
    }
    for (i, s) in p.steps.iter().enumerate() {
        let bad = |m: &str| Err(format!("program step {i}: {m}"));
        match s {
            Step::Install { path, mode, .. } => {
                if !path_ok(path) || path == "/" {
                    return bad("path must be absolute and normalized");
                }
                if *mode > 0o7777 {
                    return bad("mode has more than the low 12 bits");
                }
            }
            Step::InstallCell { verb, api, .. } => {
                if !matches!(verb.as_str(), "install" | "upgrade") || !name_ok(api) {
                    return bad("InstallCell needs verb install|upgrade and an api name");
                }
            }
            Step::Run { on, exe, argv, env, cwd, mode, sandbox } => {
                if !on.canonical() {
                    return bad("on is not canonical");
                }
                if !(cwd.is_empty() || path_ok(cwd)) {
                    return bad("cwd must be empty or absolute and normalized");
                }
                if argv.is_empty() {
                    return bad("argv must name argv[0]");
                }
                if env.iter().any(|e| !name_ok(&e.name)) || !sorted_unique(&env.iter().map(|e| e.name.as_str()).collect::<Vec<_>>()) {
                    return bad("env names must be sorted, unique, [A-Za-z0-9._-]");
                }
                if sandbox.read.iter().chain(&sandbox.write).any(|p| !path_ok(p)) {
                    return bad("read/write paths must be absolute and normalized");
                }
                if !egress_canonical(&sandbox.egress) {
                    return bad("egress rules are not canonical");
                }
                if sandbox.wall_s == 0 && *mode != RunMode::Keep {
                    return bad("wall_s 0 only with RunMode::Keep");
                }
                match exe {
                    Exe::Path { path, .. } => {
                        if !path_ok(path) {
                            return bad("exe path must be absolute and normalized");
                        }
                    }
                    Exe::Output(j) => {
                        let j = *j as usize;
                        let Some(Step::Install { on: inst_on, .. }) = p.steps.get(j).filter(|_| j < i) else {
                            return bad("Output(i) must name an earlier Install step");
                        };
                        if on.single() != Some(inst_on) {
                            return bad("a Run of an installed file must be on that one node");
                        }
                    }
                }
            }
            Step::Call { api, op, .. } => {
                if !name_ok(api) || !name_ok(op) {
                    return bad("Call needs an api and an op name");
                }
            }
            Step::Sub { .. } => {}
        }
    }
    Ok(())
}

/// The program `id` from `bodies`, checked to hash to `id` and well-formed.
pub fn find<'a>(id: &Hash, bodies: &'a [Program]) -> Result<&'a Program, String> {
    let p = bodies.iter().find(|p| &p.id() == id).ok_or_else(|| format!("program {} is not in the token", hex::encode(&id[..8])))?;
    well_formed(p)?;
    Ok(p)
}

/// Inline every `Sub` (at most [`MAX_SUB_DEPTH`] deep, [`MAX_EXPANDED`] steps in total), shifting
/// `Output` indexes. Bodies come from `bodies` and must hash to the named id.
pub fn expand(p: &Program, bodies: &[Program]) -> Result<Vec<Step>, String> {
    fn go(p: &Program, bodies: &[Program], depth: usize, out: &mut Vec<Step>) -> Result<(), String> {
        well_formed(p)?;
        let base = out.len() as u32;
        // index map: a body's own step j lands at out[map[j]]; Output(j) must name a non-Sub step
        let mut map: Vec<Option<u32>> = Vec::with_capacity(p.steps.len());
        for s in &p.steps {
            match s {
                Step::Sub { program } => {
                    if depth >= MAX_SUB_DEPTH {
                        return Err(format!("program: Sub nested more than {MAX_SUB_DEPTH} deep"));
                    }
                    let body = find(program, bodies)?;
                    map.push(None);
                    go(body, bodies, depth + 1, out)?;
                }
                Step::Run { on, exe: Exe::Output(j), argv, env, cwd, mode, sandbox } => {
                    let at = map.get(*j as usize).copied().flatten().ok_or("program: Output(i) names a Sub step")?;
                    let _ = base;
                    map.push(Some(out.len() as u32));
                    out.push(Step::Run { on: on.clone(), exe: Exe::Output(at), argv: argv.clone(), env: env.clone(), cwd: cwd.clone(), mode: *mode, sandbox: sandbox.clone() });
                }
                s => {
                    map.push(Some(out.len() as u32));
                    out.push(s.clone());
                }
            }
            if out.len() > MAX_EXPANDED {
                return Err(format!("program: more than {MAX_EXPANDED} steps after expansion"));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    go(p, bodies, 0, &mut out)?;
    Ok(out)
}

/// What a verified leaf allows, as the typing rules read it (section 6.2). Built by the v3
/// verifier from the leaf link: its `abilities`, `resource`, v1 caveats and `ext` caveats.
#[derive(Debug, Clone, Copy)]
pub struct Scope<'a> {
    pub abilities: &'a [String],
    pub resource: &'a ResourceV3,
    pub path_prefix: Option<&'a str>,
    pub max_cpu: Option<u32>,
    pub max_mem_mb: Option<u32>,
    /// `Caveat::Egress` of the leaf; `None` = the chain carries no egress caveat.
    pub egress: Option<&'a [EgressRule]>,
    pub limits: &'a [Limit],
}

impl Scope<'_> {
    fn has(&self, ability: &str) -> bool {
        self.abilities.iter().any(|a| covers(a, ability))
    }

    fn limit(&self, name: &str) -> Option<u64> {
        self.limits.iter().find(|l| l.name == name).map(|l| l.max)
    }

    fn node_in(&self, n: &NodeKey) -> bool {
        ResourceV3::Node(*n).is_subset_of(self.resource)
    }

    fn path_in(&self, p: &str) -> bool {
        self.path_prefix.is_none_or(|pp| path_within(p, pp))
    }
}

/// The abilities a step needs, most specific last; `host` is the short hostname of the step's node
/// when the caller knows it (only `InstallCell` uses it).
pub fn abilities_for(step: &Step, host: Option<&str>) -> Vec<String> {
    match step {
        Step::Install { .. } => vec!["cell.install:install-file".into()],
        Step::InstallCell { verb, api, .. } => {
            let mut v = vec![format!("cell.install:{verb}")];
            if let Some(h) = host {
                v.push(format!("cell.install:{verb}:{api}@{h}"));
            }
            v
        }
        Step::Run { .. } => vec!["proc.spawn:run".into()],
        Step::Call { api, op, .. } => vec![format!("{api}:{op}")],
        Step::Sub { .. } => vec![],
    }
}

/// The action a `Uses { per: Action }` counter is charged under for this step (section 6.4 rule 5).
pub fn charged_action(step: &Step, host: Option<&str>) -> String {
    abilities_for(step, host).pop().unwrap_or_default()
}

/// The node(s) a step runs on.
pub fn step_on(step: &Step) -> ResourceV3 {
    match step {
        Step::Install { on, .. } | Step::InstallCell { on, .. } | Step::Call { on, .. } => ResourceV3::Node(*on),
        Step::Run { on, .. } => on.clone(),
        Step::Sub { .. } => ResourceV3::Any,
    }
}

/// Type an expanded program under a leaf (section 6.2). `host_of` gives a node's short hostname when
/// known (the executing node knows its own); an `InstallCell` on a node whose name is unknown here is
/// typed against `cell.install:<verb>` and some leaf ability naming `cell.install:<verb>:<api>@...`,
/// and the node that runs it checks the exact one.
pub fn type_check(steps: &[Step], scope: &Scope, host_of: &dyn Fn(&NodeKey) -> Option<String>) -> Result<(), String> {
    for (i, s) in steps.iter().enumerate() {
        let bad = |m: String| Err(format!("program step {i}: {m}"));
        for a in abilities_for(s, None) {
            if !scope.has(&a) {
                return bad(format!("the capability does not grant '{a}'"));
            }
        }
        match s {
            Step::Install { on, path, .. } => {
                if !scope.node_in(on) {
                    return bad("node is outside the capability's resource".into());
                }
                let Some(pp) = scope.path_prefix else { return bad("an Install needs a path_prefix on the chain".into()) };
                if !path_within(path, pp) {
                    return bad(format!("path {path} is outside {pp}"));
                }
            }
            Step::InstallCell { on, verb, api, .. } => {
                if !scope.node_in(on) {
                    return bad("node is outside the capability's resource".into());
                }
                match host_of(on) {
                    Some(h) => {
                        let need = format!("cell.install:{verb}:{api}@{h}");
                        if !scope.has(&need) {
                            return bad(format!("the capability does not grant '{need}'"));
                        }
                    }
                    None => {
                        let pre = format!("cell.install:{verb}:{api}@");
                        if !scope.abilities.iter().any(|a| a.starts_with(&pre) || covers(a, &format!("{pre}x"))) {
                            return bad(format!("the capability grants no '{pre}<node>'"));
                        }
                    }
                }
            }
            Step::Run { on, exe, sandbox, cwd, .. } => {
                if !on.is_subset_of(scope.resource) {
                    return bad("nodes are outside the capability's resource".into());
                }
                if let Exe::Output(j) = exe {
                    let ok = matches!(steps.get(*j as usize), Some(Step::Install { on: n, .. }) if (*j as usize) < i && on.single() == Some(n));
                    if !ok {
                        return bad("Output(i) must name an earlier Install on the same node".into());
                    }
                }
                if scope.max_cpu.is_some_and(|m| sandbox.cpu > m) {
                    return bad("cpu exceeds max_cpu".into());
                }
                if scope.max_mem_mb.is_some_and(|m| sandbox.mem_mb > m) {
                    return bad("mem_mb exceeds max_mem_mb".into());
                }
                if !sandbox.egress.is_empty() {
                    let Some(allowed) = scope.egress else { return bad("network needs an Egress caveat on the chain".into()) };
                    if !egress_narrower(&sandbox.egress, allowed) {
                        return bad("egress is wider than the capability's Egress".into());
                    }
                }
                for (name, used) in [("net.egress.bytes_out", sandbox.bytes_out), ("net.egress.bytes_in", sandbox.bytes_in)] {
                    if scope.limit(name).is_some_and(|m| used > m) {
                        return bad(format!("{name} exceeds the capability's limit"));
                    }
                }
                if let Some(m) = scope.limit("proc.spawn.wall_s") {
                    if sandbox.wall_s == 0 || sandbox.wall_s > m {
                        return bad("wall_s exceeds proc.spawn.wall_s".into());
                    }
                }
                if sandbox.read.iter().chain(&sandbox.write).chain(std::iter::once(cwd).filter(|c| !c.is_empty())).any(|p| !scope.path_in(p)) {
                    return bad("a path is outside the capability's path_prefix".into());
                }
            }
            Step::Call { on, .. } => {
                if !scope.node_in(on) {
                    return bad("node is outside the capability's resource".into());
                }
            }
            Step::Sub { .. } => return bad("Sub left after expansion".into()),
        }
    }
    Ok(())
}

/// Resolve a step for comparison: `Run { exe: Output(i) }` becomes `Path { path, sha256 }` of step `i`.
fn resolved(steps: &[Step], s: &Step) -> Step {
    match s {
        Step::Run { on, exe: Exe::Output(j), argv, env, cwd, mode, sandbox } => match steps.get(*j as usize) {
            Some(Step::Install { path, sha256, .. }) => Step::Run {
                on: on.clone(),
                exe: Exe::Path { path: path.clone(), sha256: *sha256 },
                argv: argv.clone(),
                env: env.clone(),
                cwd: cwd.clone(),
                mode: *mode,
                sandbox: sandbox.clone(),
            },
            _ => s.clone(),
        },
        s => s.clone(),
    }
}

/// Does the requested action `req` (as a concrete step) exactly equal step `index` of the expanded
/// program, and does that step run on `node`? A `Run` of `Output(i)` matches a request naming the
/// installed path and hash. Answers the step as written in the program.
pub fn check_request<'a>(steps: &'a [Step], index: u32, node: &NodeKey, req: &Step) -> Result<&'a Step, String> {
    let s = steps.get(index as usize).ok_or_else(|| format!("program has no step {index}"))?;
    if !step_on(s).matches(node, &[]) {
        return Err(format!("program step {index} is not for this node"));
    }
    if resolved(steps, s) != resolved(steps, req) {
        return Err(format!("the request is not program step {index}"));
    }
    Ok(s)
}
