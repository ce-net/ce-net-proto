//! `ce-cal decompile` (`docs/CAL.md` section 6): a v3 token back to CAL. Every value is written
//! in its pinned form (keys, full node ids, content hashes), with the readable ref beside it when
//! the labels know one, so the output compiles back to the same links on any machine.
//!
//! A link below the root is written as the clauses that differ from its parent (CAL's
//! inheritance, `docs/CAL.md` 2.3); a link that cannot be written that way (it drops something
//! its parent sets, which no verifier accepts) is written in full after `inherit nothing`, so a
//! refused chain decompiles too and `check` can say why it is refused.

use super::Labels;
use super::ast::*;
use super::compile::spawn_defaults;
use crate::cap::Caveats;
use crate::program::{EgressRule, Exe, Hash, HostPat, NodeKey, Program, Proto, ResourceV3, RunMode, Step};
use crate::v3::{AudienceSet, CapabilityV3, Caveat, Claim, Key, Link, Party, Requirement, TokenV3, UsePer};

/// The CAL source of a token.
pub fn decompile(t: &TokenV3, l: &Labels) -> Result<String, String> {
    let mut links = Vec::new();
    for (i, link) in t.links.iter().enumerate() {
        match link {
            Link::V3 { cap, .. } => links.push(cap.clone()),
            Link::V1(_) => return Err(format!("link {i} is a v1 link: CAL describes v3 links (see TOKEN-FORMAT.md and ce-cap-verify for v1)")),
        }
    }
    Ok(super::print::print(&file(&links, &t.programs, l)))
}

/// The syntax tree of a chain and its programs.
pub fn file(links: &[CapabilityV3], programs: &[Program], l: &Labels) -> File {
    let mut names = l.programs.clone();
    for p in programs {
        let id = p.id();
        names.entry(id).or_insert_with(|| format!("prog_{}", hex::encode(&id[..4])));
    }
    let mut f = File::default();
    for p in programs {
        let id = p.id();
        let steps = p.steps.iter().enumerate().map(|(i, s)| step(i, s, &p.steps, l, &names)).collect();
        f.programs.push(ProgramDef { name: names[&id].clone(), steps, line: 0 });
    }
    for (i, c) in links.iter().enumerate() {
        let parent = if i > 0 { Some(&links[i - 1]) } else { None };
        f.links.push(LinkDef { issuer: principal(&c.issuer, l), audience: principal(&c.audience, l), clauses: clauses(c, parent, l, &names, programs), line: 0 });
    }
    f
}

fn principal(k: &Key, l: &Labels) -> PrincipalRef {
    PrincipalRef { name: l.key(k).unwrap_or_default().to_string(), pin: Some(*k) }
}

fn node(n: &NodeKey, l: &Labels) -> NodeRef {
    NodeRef { name: l.nodes.get(n).cloned().unwrap_or_default(), pin: Some(*n) }
}

fn file_ref(sha: &Hash, size: Option<u64>, l: &Labels) -> FileRef {
    match l.files.get(sha) {
        Some(name) if name.starts_with("repo:") => {
            let rest = &name[5..];
            let (spec, commit) = match rest.rsplit_once('@') {
                Some((s, c)) => (s.to_string(), Some(c.to_string())),
                None => (rest.to_string(), None),
            };
            FileRef { source: FileSource::Repo { spec, commit }, sha: Some(HashPin::Full(*sha)), size: None }
        }
        Some(name) if name.starts_with("ce-ref://") => FileRef { source: FileSource::Portable(name.clone()), sha: Some(HashPin::Full(*sha)), size: None },
        _ => FileRef { source: FileSource::Blob, sha: Some(HashPin::Full(*sha)), size },
    }
}

fn resource(r: &ResourceV3, l: &Labels) -> ResourceDef {
    match r {
        ResourceV3::Any => ResourceDef::Any,
        ResourceV3::Node(n) => ResourceDef::Node(node(n, l)),
        ResourceV3::Nodes(ns) => ResourceDef::Nodes(ns.iter().map(|n| node(n, l)).collect()),
        ResourceV3::Tag(t) => ResourceDef::Tag(t.clone()),
        ResourceV3::AllOf(ts) => ResourceDef::AllOf(ts.clone()),
    }
}

pub fn egress_def(r: &EgressRule) -> EgressDef {
    let host = match &r.host {
        HostPat::Name(n) => n.clone(),
        HostPat::Suffix(s) => format!("*{s}"),
        HostPat::Cidr { addr, prefix } => match addr.len() {
            4 => format!("{}/{prefix}", std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
            _ => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&addr[..16.min(addr.len())]);
                format!("[{}]/{prefix}", std::net::Ipv6Addr::from(b))
            }
        },
    };
    EgressDef { host, ports: r.ports.clone(), udp: r.proto == Proto::Udp }
}

fn party(p: &Party, l: &Labels) -> PartyRef {
    match p {
        Party::Key(k) => PartyRef::Principal(principal(k, l)),
        Party::Cell(s) => match s.rsplit_once('@').and_then(|(a, m)| m.parse::<u32>().ok().map(|m| (a, m))) {
            Some((api, m)) => PartyRef::Cell(CellRef { api: api.to_string(), major: Some(m) }),
            None => PartyRef::Cell(CellRef { api: s.clone(), major: None }),
        },
    }
}

fn require(r: &Requirement, l: &Labels) -> RequireDef {
    let by = party(&r.witness, l);
    match &r.claim {
        Claim::ReadThrough { source, thread, upto_msg } if source == "doc" && thread.starts_with("ce-ref://") => {
            RequireDef::Read { what: ThreadRef::Doc { spec: thread.clone(), upto: upto_msg.clone() }, by, within: r.fresh_within_s }
        }
        Claim::ReadThrough { source, thread, upto_msg } => {
            RequireDef::Read { what: ThreadRef::Thread { source: source.clone(), thread: thread.clone(), upto: upto_msg.clone() }, by, within: r.fresh_within_s }
        }
        Claim::Fact { name, value } => RequireDef::Fact { name: name.clone(), value: value.clone(), by, within: r.fresh_within_s },
    }
}

fn prog(id: &Hash, names: &std::collections::BTreeMap<Hash, String>, programs: &[Program]) -> ProgRef {
    if programs.iter().any(|p| &p.id() == id) { ProgRef::Name(names[id].clone()) } else { ProgRef::Id(*id) }
}

fn step(i: usize, s: &Step, steps: &[Step], l: &Labels, names: &std::collections::BTreeMap<Hash, String>) -> StepDef {
    match s {
        Step::Install { on, path, sha256, size, mode } => StepDef::Install { file: file_ref(sha256, Some(*size), l), to: path.clone(), on: node(on, l), mode: *mode, line: 0 },
        Step::InstallCell { on, verb, api, build } => {
            StepDef::InstallCell { verb: verb.clone(), cell: CellRef { api: api.clone(), major: None }, build: HashPin::Full(*build), on: node(on, l), line: 0 }
        }
        Step::Call { on, api, op, req_sha256 } => {
            StepDef::Call { cell: CellRef { api: api.clone(), major: None }, op: op.clone(), on: node(on, l), body: HashPin::Full(*req_sha256), line: 0 }
        }
        Step::Sub { program } => StepDef::Include { program: if names.contains_key(program) { ProgRef::Name(names[program].clone()) } else { ProgRef::Id(*program) }, line: 0 },
        Step::Run { on, exe, argv, env, cwd, mode, sandbox } => {
            let keep = *mode == RunMode::Keep;
            let (exe, at) = match exe {
                Exe::Output(j) => {
                    let j = *j as usize;
                    match steps.get(j) {
                        Some(Step::Install { sha256, on: n, path, .. }) => {
                            // `spawn <file>` means the latest earlier install of that file on that node.
                            let latest = steps[..i].iter().enumerate().rev().find(|(_, s)| matches!(s, Step::Install { sha256: h, on: m, .. } if h == sha256 && Some(m) == on.single())).map(|x| x.0);
                            let e = if latest == Some(j) && Some(n) == on.single() { SpawnExe::File { file: file_ref(sha256, None, l), at: None } } else { SpawnExe::Step(j as u32) };
                            (e, path.clone())
                        }
                        _ => (SpawnExe::Step(j as u32), String::new()),
                    }
                }
                Exe::Path { path, sha256 } => (SpawnExe::File { file: file_ref(sha256, None, l), at: Some(path.clone()) }, path.clone()),
            };
            let base = at.rsplit('/').next().unwrap_or(&at).to_string();
            let d = spawn_defaults(keep);
            let opts = SpawnOpts {
                args: if argv.len() == 1 && argv[0] == base { None } else { Some(argv.clone()) },
                env: env.iter().map(|e| (e.name.clone(), e.value.clone())).collect(),
                cwd: if cwd.is_empty() { None } else { Some(cwd.clone()) },
                cpu: (sandbox.cpu != d.cpu).then_some(sandbox.cpu),
                memory_mb: (sandbox.mem_mb != d.mem_mb).then_some(sandbox.mem_mb),
                time_s: (sandbox.wall_s != d.wall_s).then_some(sandbox.wall_s),
                read: sandbox.read.clone(),
                write: sandbox.write.clone(),
                egress: sandbox.egress.iter().map(egress_def).collect(),
                bytes_out: (sandbox.bytes_out != 0).then_some(sandbox.bytes_out),
                bytes_in: (sandbox.bytes_in != 0).then_some(sandbox.bytes_in),
            };
            StepDef::Spawn { exe, on: resource(on, l), keep, opts, line: 0 }
        }
    }
}

/// Can `c` be written as its parent `p` plus clauses? Only if it keeps every caveat `p` sets.
fn inherits(c: &CapabilityV3, p: &CapabilityV3) -> bool {
    let (a, b) = (&c.caveats, &p.caveats);
    let keeps = (b.not_before == 0 || a.not_before != 0)
        && (b.not_after == 0 || a.not_after != 0)
        && (b.max_cpu.is_none() || a.max_cpu.is_some())
        && (b.max_mem_mb.is_none() || a.max_mem_mb.is_some())
        && (b.max_credits.is_none() || a.max_credits.is_some())
        && (b.allowed_ports.is_none() || a.allowed_ports.is_some())
        && (b.path_prefix.is_none() || a.path_prefix.is_some());
    keeps
        && p.ext.iter().all(|pe| {
            let Some(ce) = c.ext.iter().find(|x| x.index() == pe.index()) else { return false };
            match (ce, pe) {
                (Caveat::Limits(cl), Caveat::Limits(pl)) => pl.iter().all(|x| cl.iter().any(|y| y.name == x.name)),
                (Caveat::Requires(cr), Caveat::Requires(pr)) => pr.iter().all(|x| cr.iter().any(|y| y.witness == x.witness && y.claim == x.claim)),
                (Caveat::CoSign(cs), Caveat::CoSign(ps)) => ps.iter().all(|x| cs.contains(x)),
                (Caveat::Via(cv), Caveat::Via(pv)) => pv.iter().all(|x| cv.contains(x)),
                _ => true,
            }
        })
}

fn clauses(c: &CapabilityV3, parent: Option<&CapabilityV3>, l: &Labels, names: &std::collections::BTreeMap<Hash, String>, programs: &[Program]) -> Vec<Clause> {
    let mut out = Vec::new();
    let base = parent.filter(|p| inherits(c, p));
    if parent.is_some() && base.is_none() {
        out.push(Clause::InheritNothing(0));
    }
    if !c.abilities.is_empty() {
        out.push(Clause::Can(c.abilities.clone(), 0));
    }
    if let Some(d) = &c.delegate {
        let to = match &d.audience {
            AudienceSet::Any => AudienceDef::Anyone,
            AudienceSet::Keys(ks) => AudienceDef::Some(ks.iter().map(|k| principal(k, l)).collect()),
        };
        out.push(Clause::MayGrant { abilities: d.abilities.clone(), to, depth: d.depth, line: 0 });
    }
    let empty = Caveats::default();
    let pc = base.map(|p| &p.caveats).unwrap_or(&empty);
    if base.is_none_or(|p| p.resource != c.resource) {
        out.push(Clause::On(resource(&c.resource, l), 0));
    }
    let cv = &c.caveats;
    if cv.not_before != pc.not_before {
        out.push(Clause::NotBefore(TimeDef::At(cv.not_before), 0));
    }
    if cv.not_after != pc.not_after {
        out.push(Clause::Until(TimeDef::At(cv.not_after), 0));
    }
    if cv.path_prefix != pc.path_prefix {
        if let Some(p) = &cv.path_prefix {
            out.push(Clause::FilesUnder(p.clone(), 0));
        }
    }
    if cv.max_cpu != pc.max_cpu {
        if let Some(n) = cv.max_cpu {
            out.push(Clause::Cpu(n, 0));
        }
    }
    if cv.max_mem_mb != pc.max_mem_mb {
        if let Some(n) = cv.max_mem_mb {
            out.push(Clause::MemoryMb(n, 0));
        }
    }
    if cv.max_credits != pc.max_credits {
        if let Some(n) = cv.max_credits {
            out.push(Clause::Credits(n, 0));
        }
    }
    if cv.allowed_ports != pc.allowed_ports {
        if let Some(ps) = &cv.allowed_ports {
            out.push(Clause::Ports(ps.clone(), 0));
        }
    }
    let pext: &[Caveat] = base.map(|p| p.ext.as_slice()).unwrap_or(&[]);
    let pget = |i: u32| pext.iter().find(|x| x.index() == i);
    for e in &c.ext {
        let pe = pget(e.index());
        if pe == Some(e) {
            continue;
        }
        match e {
            Caveat::Uses { max, per } => out.push(Clause::Uses { max: *max, per: *per, line: 0 }),
            Caveat::Limits(ls) => {
                let pl = match pe {
                    Some(Caveat::Limits(pl)) => pl.as_slice(),
                    _ => &[],
                };
                for x in ls.iter().filter(|x| !pl.contains(x)) {
                    out.push(Clause::Limit { name: x.name.clone(), max: x.max, line: 0 });
                }
                if ls.is_empty() && pe.is_none() {
                    // An empty Limits caveat cannot be written as clauses; it constrains nothing.
                }
            }
            Caveat::Egress(rs) => out.push(Clause::Egress(rs.iter().map(egress_def).collect(), 0)),
            Caveat::Programs(ids) => out.push(Clause::Only(ids.iter().map(|i| prog(i, names, programs)).collect(), 0)),
            Caveat::Requires(rs) => {
                let pr = match pe {
                    Some(Caveat::Requires(pr)) => pr.as_slice(),
                    _ => &[],
                };
                for r in rs.iter().filter(|r| !pr.contains(r)) {
                    out.push(Clause::Require(require(r, l), 0));
                }
            }
            Caveat::CoSign(cs) => {
                let ps = match pe {
                    Some(Caveat::CoSign(ps)) => ps.as_slice(),
                    _ => &[],
                };
                for x in cs.iter().filter(|x| !ps.contains(x)) {
                    out.push(Clause::CoSign(principal(&x.by, l), 0));
                }
            }
            Caveat::Via(vs) => {
                let pv = match pe {
                    Some(Caveat::Via(pv)) => pv.as_slice(),
                    _ => &[],
                };
                for x in vs.iter().filter(|x| !pv.contains(x)) {
                    out.push(Clause::Via(party(x, l), 0));
                }
            }
        }
    }
    let _ = UsePer::Link;
    out.push(Clause::Nonce(c.nonce, 0));
    out
}
