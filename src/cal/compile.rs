//! Compiling CAL (`docs/CAL.md` section 4): pin every ref, build each program and link, and
//! refuse what the verifier would refuse.
//!
//! - Every ref goes through the [`Resolver`]: a principal to exactly one key, a node name to
//!   exactly one full id, a repository file to the content hash the file pins (which the resolver
//!   must confirm) and its size. A name that resolves to nothing, or to more than one thing, is
//!   refused with the candidates; a pin the resolver contradicts is refused.
//! - A link below the root starts from its parent's resource and caveats (`docs/CAL.md` 2.3):
//!   a clause narrows or adds; conditions (`require`, `cosign`, `via`) add to the parent's.
//!   `inherit nothing` starts from nothing.
//! - Each link is held to the canonical form ([`canon::check_cap`]) and, below the root, to the
//!   narrowing checks the minter and verifier run ([`check_child`]), so a draft that compiles
//!   verifies once signed.

use std::collections::BTreeMap;

use super::ast::*;
use super::refs::{self, FileInfo, Resolver, fmt_key};
use super::{CalError, Draft, Labels};
use crate::cap::Caveats;
use crate::program::{self, EgressRule, EnvVar, Exe, Hash, HostPat, Limit, NodeKey, Program, Proto, ResourceV3, RunBox, RunMode, Step};
use crate::v3::narrow::{Parent, check_child};
use crate::v3::{AudienceSet, CapabilityV3, Caveat, Claim, CoSignPer, CoSigner, Delegate, Key, Link, Party, Requirement, Sig, UsePer, canon, cap_id};

/// Compile options.
pub struct Options<'a> {
    /// Unix seconds that `for <duration>` counts from.
    pub now: u64,
    /// A fresh random nonce for a link that does not write one (`nonce` names a link for
    /// revocation and must be unique per issuer).
    pub nonce: &'a mut dyn FnMut() -> u64,
    /// Skip the narrowing checks (canonical form is still checked): only to build a refused
    /// chain on purpose, to see `check` refuse it.
    pub lenient: bool,
}

/// What a CAL file compiles to: the unsigned links, the program bodies and the readable names.
#[derive(Debug, Clone)]
pub struct Compiled {
    pub links: Vec<CapabilityV3>,
    pub programs: Vec<Program>,
    pub labels: Labels,
}

impl Compiled {
    /// The links waiting for their issuers' signatures.
    pub fn draft(&self) -> Draft {
        Draft { links: self.links.iter().map(|c| (c.clone(), None)).collect(), programs: self.programs.clone() }
    }
}

type R<T> = Result<T, CalError>;

struct Cx<'a> {
    r: &'a dyn Resolver,
    labels: Labels,
    defs: BTreeMap<String, &'a ProgramDef>,
    /// Compiled programs, in the order the token carries them.
    done: Vec<(Option<String>, Program)>,
    /// Names being compiled (to refuse `include` cycles).
    stack: Vec<String>,
}

/// Compile a parsed file.
pub fn compile(f: &File, r: &dyn Resolver, o: &mut Options) -> R<Compiled> {
    let mut cx = Cx { r, labels: Labels::default(), defs: BTreeMap::new(), done: Vec::new(), stack: Vec::new() };
    for p in &f.programs {
        cx.defs.insert(p.name.clone(), p);
    }
    let mut links: Vec<CapabilityV3> = Vec::new();
    let mut audience_names: Vec<String> = Vec::new();
    for (i, l) in f.links.iter().enumerate() {
        let issuer = cx.principal(&l.issuer, l.line)?;
        let audience = cx.principal(&l.audience, l.line)?;
        if let Some(prev) = links.last() {
            if prev.audience != issuer {
                return Err(CalError::at(
                    l.line,
                    format!("link {i}: the issuer {} is not link {}'s audience {}", show(&l.issuer), i - 1, audience_names[i - 1]),
                )
                .hint(format!("a link is granted by whoever holds the link above it: start this one with {} grants ...", audience_names[i - 1])));
            }
        }
        audience_names.push(show(&l.audience));
        let cap = cx.link(i, l, issuer, audience, links.last(), o)?;
        if links.iter().any(|p| p.issuer == cap.issuer && p.nonce == cap.nonce) {
            return Err(CalError::at(l.line, format!("link {i} reuses nonce {} of the same issuer: one revocation would name two links", cap.nonce)));
        }
        canon::check_cap(&cap).map_err(|why| CalError::at(l.line, format!("link {i} is not canonical: {why}")).hint(canon_hint(&why)))?;
        if let (Some(parent), false) = (links.last(), o.lenient) {
            let as_link = Link::V3 { cap: parent.clone(), sig: Sig::Ed25519([0; 64]) };
            if let Err(why) = check_child(&cap, &Parent::of(&as_link)) {
                let detail = super::explain::why_child(&cap, parent, &cx.labels);
                return Err(CalError::at(l.line, format!("link {i} is refused by every verifier: {why}")).hint(detail));
            }
        }
        if cap.caveats.not_after != 0 && cap.caveats.not_before > cap.caveats.not_after {
            return Err(CalError::at(l.line, format!("link {i} is never valid: 'not before' is after 'until'")));
        }
        links.push(cap);
    }
    for p in &f.programs {
        if !cx.done.iter().any(|(n, _)| n.as_deref() == Some(p.name.as_str())) {
            return Err(CalError::at(p.line, format!("program '{}' is never used", p.name)).hint(format!("bind it to a link with 'only {}', or remove it", p.name)));
        }
    }
    if cx.done.len() > crate::v3::MAX_PROGRAMS {
        return Err(CalError::at(0, format!("a token carries at most {} programs; this file has {}", crate::v3::MAX_PROGRAMS, cx.done.len())));
    }
    let programs: Vec<Program> = cx.done.iter().map(|(_, p)| p.clone()).collect();
    Ok(Compiled { links, programs, labels: cx.labels })
}

/// The ref as written, for messages.
fn show(p: &PrincipalRef) -> String {
    super::print::principal(p)
}

fn canon_hint(why: &str) -> String {
    if why.contains("counted link must set caveats.not_after") {
        "a counted link (once, uses, or an egress byte limit) must expire: add 'until <date>' or 'for <duration>'".into()
    } else if why.contains("finite resource") {
        "a counted link must name its nodes: 'on node:<name>' or 'on nodes node:a, node:b' (each node counts on its own)".into()
    } else if why.contains("without wildcards") {
        "'uses n per action' needs abilities without '*', so the number of actions is finite".into()
    } else {
        "see docs/CAPABILITY-PROGRAMS.md section 3.4".into()
    }
}

fn many<T>(items: &[T], f: impl Fn(&T) -> String) -> String {
    items.iter().map(f).collect::<Vec<_>>().join(", ")
}

impl<'a> Cx<'a> {
    fn principal(&mut self, p: &PrincipalRef, line: usize) -> R<Key> {
        if p.name.is_empty() {
            let k = p.pin.expect("a bare key is its own pin");
            return Ok(k);
        }
        let found = if let Some(n) = p.name.strip_prefix("node:") {
            self.r.node(n).map(|ids| ids.into_iter().map(Key::Ed25519).collect::<Vec<_>>())
        } else {
            self.r.principal(&p.name)
        };
        let k = match (found, p.pin) {
            (Err(why), Some(pin)) => {
                let _ = why;
                pin
            }
            (Err(why), None) => {
                return Err(CalError::at(line, format!("cannot determine {}: {why}", p.name))
                    .hint(format!("pin it with its key: {} ed25519:<64 hex>", p.name)));
            }
            (Ok(ks), Some(pin)) if ks.is_empty() || ks.contains(&pin) => pin,
            (Ok(ks), Some(pin)) if ks.len() == 1 => {
                return Err(CalError::at(line, format!("pin mismatch: {} is {} in the ref book, but the file pins {}", p.name, fmt_key(&ks[0]), fmt_key(&pin)))
                    .hint(format!("if the key changed, write {} {}", p.name, fmt_key(&ks[0]))));
            }
            (Ok(ks), Some(pin)) => {
                return Err(CalError::at(line, format!("pin mismatch: {} pins {}, which is none of its {} keys", p.name, fmt_key(&pin), ks.len()))
                    .hint(format!("pin one of: {}", many(&ks, |k| format!("{} {}", p.name, fmt_key(k))))));
            }
            (Ok(ks), None) if ks.is_empty() => {
                return Err(CalError::at(line, format!("unpinned: {} is not in the ref book, so CAL cannot know which key it means", p.name))
                    .hint(format!("write its key after it ({} ed25519:<64 hex>), or add it to the ref book", p.name)));
            }
            (Ok(ks), None) if ks.len() == 1 => ks[0],
            (Ok(ks), None) => {
                return Err(CalError::at(line, format!("ambiguous: {} has {} keys", p.name, ks.len()))
                    .hint(format!("pin the one you mean: {}", many(&ks, |k| format!("{} {}", p.name, fmt_key(k))))));
            }
        };
        self.labels.keys.entry(fmt_key(&k)).or_insert_with(|| p.name.clone());
        Ok(k)
    }

    fn node(&mut self, n: &NodeRef, line: usize) -> R<NodeKey> {
        if n.name.is_empty() {
            return Ok(n.pin.expect("a full node id is its own pin"));
        }
        let id = match (self.r.node(&n.name), n.pin) {
            (Err(_), Some(pin)) => pin,
            (Err(why), None) => {
                return Err(CalError::at(line, format!("cannot determine node:{}: {why}", n.name)).hint("write the full node id: node:<64 hex>"));
            }
            (Ok(ids), Some(pin)) if ids.is_empty() || ids.contains(&pin) => pin,
            (Ok(ids), Some(pin)) => {
                return Err(CalError::at(line, format!("pin mismatch: node:{} is {} here, but the file pins {}", n.name, many(&ids, |i| hex::encode(i)), hex::encode(pin)))
                    .hint(format!("write node:{} ed25519:{} if that is the machine you mean", n.name, hex::encode(ids[0]))));
            }
            (Ok(ids), None) if ids.is_empty() => {
                return Err(CalError::at(line, format!("unpinned: no node named '{}' is known", n.name))
                    .hint(format!("write the full node id (node:<64 hex>), or node:{} ed25519:<64 hex>", n.name)));
            }
            (Ok(ids), None) if ids.len() == 1 => ids[0],
            (Ok(ids), None) => {
                return Err(CalError::at(line, format!("ambiguous: {} nodes are named '{}'", ids.len(), n.name))
                    .hint(format!("name the one you mean by its full id: {}", many(&ids, |i| format!("node:{}", hex::encode(i))))));
            }
        };
        self.labels.nodes.entry(id).or_insert_with(|| n.name.clone());
        Ok(id)
    }

    /// `(content hash, size)` of a file ref. `need_size`: an `install` needs the size; a `spawn ... at`
    /// names a file already on the node and needs only the hash.
    fn file(&mut self, f: &FileRef, need_size: bool, line: usize) -> R<(Hash, u64)> {
        let written = super::print::file(&FileRef { size: None, ..f.clone() });
        let (portable, label) = match &f.source {
            FileSource::Blob => {
                let sha = match &f.sha {
                    Some(HashPin::Full(h)) => *h,
                    _ => return Err(CalError::at(line, format!("'{written}' is not a full hash")).hint("a blob is named by its whole hash: ce-blob:sha256:<64 hex>")),
                };
                let size = match (f.size, self.r.blob(&sha)) {
                    (Some(s), _) => s,
                    (None, Ok(v)) if v.len() == 1 => v[0],
                    (None, _) if !need_size => 0,
                    (None, _) => {
                        return Err(CalError::at(line, format!("cannot determine the size of {written}"))
                            .hint(format!("write its size: {written} size <bytes>")));
                    }
                };
                self.labels.files.entry(sha).or_insert_with(|| written.clone());
                return Ok((sha, size));
            }
            FileSource::Portable(p) => {
                refs::parse_portable(p).map_err(|e| CalError::at(line, format!("'{p}': {e}")))?;
                (p.clone(), p.clone())
            }
            FileSource::Repo { spec, commit } => {
                let Some(c) = commit else {
                    return Err(CalError::at(line, format!("unpinned: repo:{spec} names no commit"))
                        .hint(format!("write repo:{spec}@<commit> sha256:<hash of the bytes you approve>")));
                };
                (self.repo_file(spec, line)?, format!("repo:{spec}@{c}"))
            }
        };
        let variants = self.r.file(&portable).map_err(|why| {
            CalError::at(line, format!("cannot check {label}: {why}"))
                .hint("CAL pins only what it can check: make the file known to ce.ref (or the ref book), or name the content itself as ce-blob:sha256:<hash> size <bytes>")
        })?;
        let pin = match &f.sha {
            Some(HashPin::Full(h)) => *h,
            Some(HashPin::Prefix(pre)) => {
                let full: Vec<&FileInfo> = variants.iter().filter(|v| v.sha256.starts_with(pre.as_str())).collect();
                let hint = match full.as_slice() {
                    [v] => format!("the file's hash is sha256:{}: write {label} sha256:{}", v.sha256, v.sha256),
                    _ => format!("write all 64 hex digits of the hash: {label} sha256:<64 hex>"),
                };
                return Err(CalError::at(line, format!("'sha256:{pre}…' is only the start of a hash: a pin must be the whole hash")).hint(hint));
            }
            None => {
                let hint = match variants.as_slice() {
                    [v] => format!("ce.ref sees sha256:{} for it{}: write {label} sha256:{} if those are the bytes you approve", v.sha256, at_commit(v), v.sha256),
                    _ => format!("write {label} sha256:<hash of the bytes you approve>"),
                };
                return Err(CalError::at(line, format!("unpinned: {label} has no content hash, so its bytes could change after you approve it")).hint(hint));
            }
        };
        if variants.is_empty() {
            return Err(CalError::at(line, format!("{label} is not known to the resolver ({portable})"))
                .hint("check the repository and path, or name the content itself as ce-blob:sha256:<hash> size <bytes>"));
        }
        let want = hex::encode(pin);
        let Some(v) = variants.iter().find(|v| v.sha256 == want) else {
            return Err(CalError::at(
                line,
                format!("content hash mismatch: {label} pins sha256:{want}, but the file is {}", many(&variants, |v| format!("sha256:{}{}", v.sha256, at_commit(v)))),
            )
            .hint("pin the hash of the bytes you mean, or check the commit"));
        };
        if let Some(s) = f.size {
            if s != v.size {
                return Err(CalError::at(line, format!("size mismatch: {label} is {} bytes, the file says size {s}", v.size)));
            }
        }
        self.labels.files.entry(pin).or_insert(label);
        self.labels.portable.entry(pin).or_insert(portable);
        Ok((pin, v.size))
    }

    /// `<repo>/<path>` to its portable ref, refusing an unknown or ambiguous repository.
    fn repo_file(&self, spec: &str, line: usize) -> R<String> {
        let mut found: Vec<(String, String, String)> = Vec::new(); // (id, canonical origin, path)
        for (k, _) in spec.match_indices('/') {
            let (name, path) = (&spec[..k], &spec[k + 1..]);
            let origins = self.r.repo(name).map_err(|why| CalError::at(line, format!("cannot determine repository '{name}': {why}")))?;
            for o in origins {
                let (id, canonical) = refs::origin_id(&o).map_err(|e| CalError::at(line, format!("repository '{name}' has origin '{o}': {e}")))?;
                if !found.iter().any(|f| f.0 == id && f.2 == path) {
                    found.push((id, canonical, path.to_string()));
                }
            }
        }
        match found.as_slice() {
            [] => Err(CalError::at(line, format!("unknown repository in repo:{spec}: no repository named '{}' is known", spec.split('/').next().unwrap_or(spec)))
                .hint("name the file by its portable ref: ce-ref://repo/<sha256 of the git origin>/<path> sha256:<hash>")),
            [(id, _, path)] => refs::portable(id, path).map_err(|e| CalError::at(line, e)),
            _ => Err(CalError::at(line, format!("ambiguous: repo:{spec} names {} different files: {}", found.len(), many(&found, |(_, c, p)| format!("{p} in {c}")))).hint(format!(
                "write the one you mean as a portable ref: {}",
                many(&found, |(id, _, p)| refs::portable(id, p).unwrap_or_default())
            ))),
        }
    }

    fn party(&mut self, p: &PartyRef, line: usize) -> R<Party> {
        match p {
            PartyRef::Principal(x) => Ok(Party::Key(self.principal(x, line)?)),
            PartyRef::Cell(c) => match c.major {
                Some(m) => Ok(Party::Cell(format!("{}@{m}", c.api))),
                None => Err(CalError::at(line, format!("unpinned: cell:{} names no major version", c.api))
                    .hint(format!("write cell:{}@<major>, e.g. cell:{}@1: a node trusts keys for one major version of a cell", c.api, c.api))),
            },
        }
    }

    fn claim(&mut self, t: &ThreadRef, line: usize) -> R<Claim> {
        Ok(match t {
            ThreadRef::Thread { source, thread, upto } => Claim::ReadThrough { source: source.clone(), thread: thread.clone(), upto_msg: upto.clone() },
            ThreadRef::Doc { spec, upto } => {
                let portable = if spec.starts_with("ce-ref://") {
                    refs::parse_portable(spec).map_err(|e| CalError::at(line, format!("'{spec}': {e}")))?;
                    spec.clone()
                } else {
                    let with_md = if spec.ends_with(".md") { spec.clone() } else { format!("{spec}.md") };
                    self.repo_file(&with_md, line)?
                };
                Claim::ReadThrough { source: "doc".into(), thread: portable, upto_msg: upto.clone() }
            }
        })
    }

    fn resource(&mut self, r: &ResourceDef, line: usize) -> R<ResourceV3> {
        Ok(match r {
            ResourceDef::Any => ResourceV3::Any,
            ResourceDef::Node(n) => ResourceV3::Node(self.node(n, line)?),
            ResourceDef::Nodes(ns) => {
                let mut ids = Vec::new();
                for n in ns {
                    let id = self.node(n, line)?;
                    if ids.contains(&id) {
                        return Err(CalError::at(line, format!("{} is named twice", super::print::node(n))));
                    }
                    ids.push(id);
                }
                ids.sort();
                ResourceV3::Nodes(ids)
            }
            ResourceDef::Tag(t) => ResourceV3::Tag(t.clone()),
            ResourceDef::AllOf(ts) => ResourceV3::AllOf(ts.clone()),
        })
    }

    fn egress(&self, rules: &[EgressDef], line: usize) -> R<Vec<EgressRule>> {
        let mut out: Vec<EgressRule> = Vec::new();
        for e in rules {
            let r = egress_rule(e).map_err(|m| CalError::at(line, m))?;
            if out.contains(&r) {
                return Err(CalError::at(line, format!("egress {} is written twice", super::print::egress(e))));
            }
            out.push(r);
        }
        out.sort_by_key(|r| bincode::serialize(r).unwrap_or_default());
        Ok(out)
    }

    fn program_ref(&mut self, p: &ProgRef, line: usize) -> R<Hash> {
        match p {
            ProgRef::Id(h) => Ok(*h),
            ProgRef::Inline(steps) => {
                let prog = self.program_body(steps, line)?;
                let id = prog.id();
                if !self.done.iter().any(|(_, q)| q.id() == id) {
                    self.done.push((None, prog));
                }
                Ok(id)
            }
            ProgRef::Name(n) => {
                if let Some((_, q)) = self.done.iter().find(|(name, _)| name.as_deref() == Some(n.as_str())) {
                    return Ok(q.id());
                }
                let Some(def) = self.defs.get(n).copied() else {
                    return Err(CalError::at(line, format!("no program named '{n}' in this file")).hint(format!("define it: program {n} {{ ... }}, or name it by id: program:<64 hex>")));
                };
                if self.stack.contains(n) {
                    return Err(CalError::at(def.line, format!("program '{n}' includes itself")));
                }
                self.stack.push(n.clone());
                let prog = self.program_body(&def.steps, def.line)?;
                self.stack.pop();
                let id = prog.id();
                self.labels.programs.entry(id).or_insert_with(|| n.clone());
                self.done.push((Some(n.clone()), prog));
                Ok(id)
            }
        }
    }

    fn program_body(&mut self, steps: &[StepDef], line: usize) -> R<Program> {
        let mut out: Vec<Step> = Vec::new();
        for s in steps {
            let l = s.line();
            let step = match s {
                StepDef::Install { file, to, on, mode, .. } => {
                    let (sha256, size) = self.file(file, true, l)?;
                    Step::Install { on: self.node(on, l)?, path: to.clone(), sha256, size, mode: *mode }
                }
                StepDef::InstallCell { verb, cell, build, on, .. } => {
                    let HashPin::Full(build) = build else {
                        return Err(CalError::at(l, "a build id must be the whole hash (sha256:<64 hex>)"));
                    };
                    Step::InstallCell { on: self.node(on, l)?, verb: verb.clone(), api: cell.api.clone(), build: *build }
                }
                StepDef::Call { cell, op, on, body, .. } => {
                    let HashPin::Full(body) = body else {
                        return Err(CalError::at(l, "a request body hash must be the whole hash (sha256:<64 hex>)"));
                    };
                    Step::Call { on: self.node(on, l)?, api: cell.api.clone(), op: op.clone(), req_sha256: *body }
                }
                StepDef::Include { program, .. } => Step::Sub { program: self.program_ref(program, l)? },
                StepDef::Spawn { exe, on, keep, opts, .. } => {
                    let on = self.resource(on, l)?;
                    let (exe, at) = match exe {
                        SpawnExe::Step(i) => match out.get(*i as usize) {
                            Some(Step::Install { path, .. }) => (Exe::Output(*i), path.clone()),
                            _ => return Err(CalError::at(l, format!("spawn step {i}: step {i} of this program is not an install"))),
                        },
                        SpawnExe::File { file, at: Some(p) } => {
                            let (sha256, _) = self.file(file, false, l)?;
                            (Exe::Path { path: p.clone(), sha256 }, p.clone())
                        }
                        SpawnExe::File { file, at: None } => {
                            let (sha256, _) = self.file(file, false, l)?;
                            let one = on.single().copied();
                            let found = out.iter().enumerate().rev().find(|(_, s)| matches!(s, Step::Install { sha256: h, on: n, .. } if *h == sha256 && Some(*n) == one));
                            match found {
                                Some((j, Step::Install { path, .. })) => (Exe::Output(j as u32), path.clone()),
                                _ => {
                                    let w = super::print::file(file);
                                    return Err(CalError::at(l, format!("spawn {w}: the file is not installed earlier in this program on that node"))
                                        .hint(format!("install it first (install {w} to <path> on <node>), or say where it already is: spawn {w} at <path>")));
                                }
                            }
                        }
                    };
                    let mut env: Vec<EnvVar> = opts.env.iter().map(|(n, v)| EnvVar { name: n.clone(), value: v.clone() }).collect();
                    env.sort_by(|a, b| a.name.cmp(&b.name));
                    if env.windows(2).any(|w| w[0].name == w[1].name) {
                        return Err(CalError::at(l, "an environment variable is set twice"));
                    }
                    let base = at.rsplit('/').next().unwrap_or(&at).to_string();
                    let d = spawn_defaults(*keep);
                    Step::Run {
                        on,
                        exe,
                        argv: opts.args.clone().unwrap_or_else(|| vec![base]),
                        env,
                        cwd: opts.cwd.clone().unwrap_or_default(),
                        mode: if *keep { RunMode::Keep } else { RunMode::Once },
                        sandbox: RunBox {
                            cpu: opts.cpu.unwrap_or(d.cpu),
                            mem_mb: opts.memory_mb.unwrap_or(d.mem_mb),
                            wall_s: opts.time_s.unwrap_or(d.wall_s),
                            read: opts.read.clone(),
                            write: opts.write.clone(),
                            egress: self.egress(&opts.egress, l)?,
                            bytes_out: opts.bytes_out.unwrap_or(0),
                            bytes_in: opts.bytes_in.unwrap_or(0),
                        },
                    }
                }
            };
            out.push(step);
        }
        let p = Program::new(out);
        program::well_formed(&p).map_err(|e| CalError::at(line, e))?;
        Ok(p)
    }

    #[allow(clippy::too_many_lines)]
    fn link(&mut self, i: usize, l: &LinkDef, issuer: Key, audience: Key, parent: Option<&CapabilityV3>, o: &mut Options) -> R<CapabilityV3> {
        let fresh = l.clauses.iter().any(|c| matches!(c, Clause::InheritNothing(_)));
        let base = parent.filter(|_| !fresh);
        let mut e = Ext::of(base.map(|p| p.ext.as_slice()).unwrap_or(&[]));
        let mut caveats = base.map(|p| p.caveats.clone()).unwrap_or_default();
        let mut resource = base.map(|p| p.resource.clone());
        let mut abilities: Option<Vec<String>> = None;
        let mut delegate: Option<Delegate> = None;
        let mut nonce: Option<u64> = None;
        let mut seen: Vec<&'static str> = Vec::new();
        let mut once = |what: &'static str, line: usize| -> R<()> {
            if seen.contains(&what) {
                return Err(CalError::at(line, format!("'{what}' is given twice in this link")));
            }
            seen.push(what);
            Ok(())
        };
        let time = |t: &TimeDef| match t {
            TimeDef::At(x) => *x,
            TimeDef::For(d) => o.now.saturating_add(*d),
        };
        for c in &l.clauses {
            let line = c.line();
            match c {
                Clause::InheritNothing(_) => once("inherit nothing", line)?,
                Clause::Can(a, _) => {
                    once("can", line)?;
                    abilities = Some(a.clone());
                }
                Clause::MayGrant { abilities: a, to, depth, .. } => {
                    once("may grant", line)?;
                    let audience = match to {
                        AudienceDef::Anyone => AudienceSet::Any,
                        AudienceDef::Some(ps) => {
                            let mut ks = Vec::new();
                            for p in ps {
                                let k = self.principal(p, line)?;
                                if !ks.contains(&k) {
                                    ks.push(k);
                                }
                            }
                            ks.sort_by_key(|k| bincode::serialize(k).unwrap_or_default());
                            AudienceSet::Keys(ks)
                        }
                    };
                    delegate = Some(Delegate { abilities: a.clone(), audience, depth: *depth });
                }
                Clause::On(r, _) => {
                    once("on", line)?;
                    resource = Some(self.resource(r, line)?);
                }
                Clause::Until(t, _) => {
                    once("until", line)?;
                    caveats.not_after = time(t);
                }
                Clause::NotBefore(t, _) => {
                    once("not before", line)?;
                    caveats.not_before = time(t);
                }
                Clause::Uses { max, per, .. } => {
                    once("uses", line)?;
                    e.uses = Some((*max, *per));
                }
                Clause::Limit { name, max, .. } => {
                    if l.clauses.iter().filter(|c| matches!(c, Clause::Limit { name: n, .. } if n == name)).count() > 1 {
                        return Err(CalError::at(line, format!("limit {name} is given twice in this link")));
                    }
                    e.limits.insert(name.clone(), *max);
                }
                Clause::Egress(rules, _) => {
                    once("egress", line)?;
                    e.egress = Some(self.egress(rules, line)?);
                }
                Clause::Cpu(n, _) => {
                    once("cpu", line)?;
                    caveats.max_cpu = Some(*n);
                }
                Clause::MemoryMb(n, _) => {
                    once("memory", line)?;
                    caveats.max_mem_mb = Some(*n);
                }
                Clause::Credits(n, _) => {
                    once("credits", line)?;
                    caveats.max_credits = Some(*n);
                }
                Clause::Ports(ps, _) => {
                    once("ports", line)?;
                    let mut ps = ps.clone();
                    ps.sort();
                    ps.dedup();
                    caveats.allowed_ports = Some(ps);
                }
                Clause::FilesUnder(p, _) => {
                    once("files under", line)?;
                    caveats.path_prefix = Some(p.clone());
                }
                Clause::Only(ps, _) => {
                    once("only", line)?;
                    let mut ids = Vec::new();
                    for p in ps {
                        let id = self.program_ref(p, line)?;
                        if !ids.contains(&id) {
                            ids.push(id);
                        }
                    }
                    ids.sort();
                    e.programs = Some(ids);
                }
                Clause::Require(rq, _) => {
                    let (witness, claim, within) = match rq {
                        RequireDef::Read { what, by, within } => (self.party(by, line)?, self.claim(what, line)?, *within),
                        RequireDef::Fact { name, value, by, within } => {
                            (self.party(by, line)?, Claim::Fact { name: name.clone(), value: value.clone() }, *within)
                        }
                    };
                    if within == Some(0) {
                        return Err(CalError::at(line, "'within 0s' can never be met: give at least 1s"));
                    }
                    let entry = Requirement { witness, claim, fresh_within_s: within };
                    // one entry per (witness, claim): a later one replaces (narrows) an inherited one
                    e.requires.retain(|r| !(r.witness == entry.witness && r.claim == entry.claim));
                    e.requires.push(entry);
                }
                Clause::CoSign(p, _) => {
                    let by = self.principal(p, line)?;
                    let c = CoSigner { by, per: CoSignPer::Use };
                    if !e.cosign.contains(&c) {
                        e.cosign.push(c);
                    }
                }
                Clause::Via(p, _) => {
                    let b = self.party(p, line)?;
                    if !e.via.contains(&b) {
                        e.via.push(b);
                    }
                }
                Clause::Nonce(n, _) => {
                    once("nonce", line)?;
                    nonce = Some(*n);
                }
            }
        }
        let Some(resource) = resource else {
            return Err(CalError::at(l.line, format!("link {i} does not say where it applies"))
                .hint("add 'on node:<name>', 'on nodes node:a, node:b', 'on nodes tagged <tag>' or, deliberately, 'on any node'"));
        };
        let nonce = match nonce {
            Some(n) => n,
            None => (o.nonce)(),
        };
        Ok(CapabilityV3 {
            v: 3,
            issuer,
            audience,
            abilities: abilities.unwrap_or_default(),
            resource,
            caveats,
            ext: e.build(),
            delegate,
            nonce,
            parent: parent.map(cap_id),
        })
    }
}

fn at_commit(v: &FileInfo) -> String {
    if v.commit.is_empty() { String::new() } else { format!(" at commit {}", refs::short(&v.commit)) }
}

/// The defaults of a `spawn` sandbox (`docs/CAL.md` section 2.4).
pub struct SpawnDefaults {
    pub cpu: u32,
    pub mem_mb: u32,
    pub wall_s: u64,
}

pub fn spawn_defaults(keep: bool) -> SpawnDefaults {
    SpawnDefaults { cpu: 1, mem_mb: 512, wall_s: if keep { 0 } else { 600 } }
}

/// One `host:port` rule as written, to an `EgressRule`.
pub fn egress_rule(e: &EgressDef) -> Result<EgressRule, String> {
    let host = if let Some(s) = e.host.strip_prefix('*') {
        if !s.starts_with('.') {
            return Err(format!("'{}': a wildcard host is *.<domain>", e.host));
        }
        HostPat::Suffix(s.to_string())
    } else if let Some((addr, prefix)) = e.host.split_once('/') {
        let addr = addr.trim_start_matches('[').trim_end_matches(']');
        let prefix: u8 = prefix.parse().map_err(|_| format!("'{}': the prefix length is not a number", e.host))?;
        let bytes = match addr.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(a)) => a.octets().to_vec(),
            Ok(std::net::IpAddr::V6(a)) => a.octets().to_vec(),
            Err(_) => return Err(format!("'{addr}' is not an IP address")),
        };
        HostPat::Cidr { addr: bytes, prefix }
    } else if let Ok(ip) = e.host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>() {
        let (bytes, prefix) = match ip {
            std::net::IpAddr::V4(a) => (a.octets().to_vec(), 32),
            std::net::IpAddr::V6(a) => (a.octets().to_vec(), 128),
        };
        HostPat::Cidr { addr: bytes, prefix }
    } else {
        HostPat::Name(e.host.clone())
    };
    let mut ports = e.ports.clone();
    ports.sort();
    if ports.windows(2).any(|w| w[0] == w[1]) {
        return Err(format!("'{}': a port is written twice", super::print::egress(e)));
    }
    let r = EgressRule { host, ports, proto: if e.udp { Proto::Udp } else { Proto::Tcp } };
    if !program::egress_canonical(std::slice::from_ref(&r)) {
        return Err(format!(
            "'{}' is not a valid egress rule (a lowercase DNS name with no trailing dot, *.<domain>, or an address block with its host bits zero)",
            super::print::egress(e)
        ));
    }
    Ok(r)
}

/// The `ext` caveats while a link is being built, by variant.
#[derive(Default)]
struct Ext {
    uses: Option<(u32, UsePer)>,
    limits: BTreeMap<String, u64>,
    has_limits: bool,
    egress: Option<Vec<EgressRule>>,
    programs: Option<Vec<Hash>>,
    requires: Vec<Requirement>,
    cosign: Vec<CoSigner>,
    via: Vec<Party>,
}

impl Ext {
    fn of(ext: &[Caveat]) -> Ext {
        let mut e = Ext::default();
        for c in ext {
            match c {
                Caveat::Uses { max, per } => e.uses = Some((*max, *per)),
                Caveat::Limits(ls) => {
                    e.has_limits = true;
                    for l in ls {
                        e.limits.insert(l.name.clone(), l.max);
                    }
                }
                Caveat::Egress(r) => e.egress = Some(r.clone()),
                Caveat::Programs(p) => e.programs = Some(p.clone()),
                Caveat::Requires(r) => e.requires = r.clone(),
                Caveat::CoSign(c) => e.cosign = c.clone(),
                Caveat::Via(v) => e.via = v.clone(),
            }
        }
        e
    }

    fn build(mut self) -> Vec<Caveat> {
        let mut out = Vec::new();
        if let Some((max, per)) = self.uses {
            out.push(Caveat::Uses { max, per });
        }
        if self.has_limits || !self.limits.is_empty() {
            out.push(Caveat::Limits(self.limits.into_iter().map(|(name, max)| Limit { name, max }).collect()));
        }
        if let Some(r) = self.egress {
            out.push(Caveat::Egress(r));
        }
        if let Some(p) = self.programs {
            out.push(Caveat::Programs(p));
        }
        let enc = |x: &dyn erased::Enc| x.enc();
        if !self.requires.is_empty() {
            self.requires.sort_by_key(|r| enc(r));
            out.push(Caveat::Requires(self.requires));
        }
        if !self.cosign.is_empty() {
            self.cosign.sort_by_key(|c| enc(c));
            out.push(Caveat::CoSign(self.cosign));
        }
        if !self.via.is_empty() {
            self.via.sort_by_key(|v| enc(v));
            out.push(Caveat::Via(self.via));
        }
        out
    }
}

mod erased {
    pub trait Enc {
        fn enc(&self) -> Vec<u8>;
    }
    impl<T: serde::Serialize> Enc for T {
        fn enc(&self) -> Vec<u8> {
            bincode::serialize(self).unwrap_or_default()
        }
    }
}

#[allow(unused_imports)]
use Caveats as _;

fn standalone(r: &dyn Resolver) -> Cx<'_> {
    Cx { r, labels: Labels::default(), defs: BTreeMap::new(), done: Vec::new(), stack: Vec::new() }
}

/// Resolve one principal ref outside a file (for `check`), with the same rules as in a file.
pub fn resolve_principal(p: &PrincipalRef, r: &dyn Resolver) -> R<Key> {
    standalone(r).principal(p, 0)
}

/// Resolve one node ref outside a file (for `check`).
pub fn resolve_node(n: &NodeRef, r: &dyn Resolver) -> R<NodeKey> {
    standalone(r).node(n, 0)
}
