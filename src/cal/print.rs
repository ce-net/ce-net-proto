//! The canonical layout of a CAL file: two-space indents, one clause per line, programs before
//! links. `print(parse(s))` is the formatted `s`, and printing is idempotent.

use super::ast::*;
use super::refs::fmt_key;
use super::units::{fmt_bytes, fmt_duration, fmt_time};
use crate::v3::UsePer;

/// The whole file, starting with `cal 1`.
pub fn print(f: &File) -> String {
    let mut out = String::from("cal 1\n");
    for p in &f.programs {
        out.push('\n');
        out.push_str(&format!("program {} {{\n", p.name));
        for s in &p.steps {
            step(&mut out, s, 1);
        }
        out.push_str("}\n");
    }
    for l in &f.links {
        out.push('\n');
        out.push_str(&format!("{} grants {} {{\n", principal(&l.issuer), principal(&l.audience)));
        for c in &l.clauses {
            clause(&mut out, c, 1);
        }
        out.push_str("}\n");
    }
    out
}

fn ind(n: usize) -> String {
    "  ".repeat(n)
}

pub fn principal(p: &PrincipalRef) -> String {
    match (&p.pin, p.name.is_empty()) {
        (Some(k), true) => fmt_key(k),
        (Some(k), false) => format!("{} {}", p.name, fmt_key(k)),
        (None, _) => p.name.clone(),
    }
}

pub fn node(n: &NodeRef) -> String {
    match (&n.pin, n.name.is_empty()) {
        (Some(id), true) => format!("node:{}", hex::encode(id)),
        (Some(id), false) => format!("node:{} ed25519:{}", n.name, hex::encode(id)),
        (None, _) => format!("node:{}", n.name),
    }
}

pub fn hash_pin(h: &HashPin) -> String {
    match h {
        HashPin::Full(b) => format!("sha256:{}", hex::encode(b)),
        HashPin::Prefix(p) => format!("sha256:{p}…"),
    }
}

pub fn file(f: &FileRef) -> String {
    let mut s = match &f.source {
        FileSource::Repo { spec, commit: Some(c) } => format!("repo:{spec}@{c}"),
        FileSource::Repo { spec, commit: None } => format!("repo:{spec}"),
        FileSource::Portable(p) => p.clone(),
        FileSource::Blob => format!("ce-blob:{}", f.sha.as_ref().map(hash_pin).unwrap_or_default()),
    };
    if !matches!(f.source, FileSource::Blob) {
        if let Some(h) = &f.sha {
            s.push(' ');
            s.push_str(&hash_pin(h));
        }
    }
    if let Some(n) = f.size {
        s.push_str(&format!(" size {n}"));
    }
    s
}

pub fn cell(c: &CellRef) -> String {
    match c.major {
        Some(m) => format!("cell:{}@{m}", c.api),
        None => format!("cell:{}", c.api),
    }
}

pub fn party(p: &PartyRef) -> String {
    match p {
        PartyRef::Principal(x) => principal(x),
        PartyRef::Cell(c) => cell(c),
    }
}

fn thread(t: &ThreadRef) -> String {
    let (base, upto) = match t {
        ThreadRef::Thread { source, thread, upto } => (format!("{source}:thread/{thread}"), upto),
        ThreadRef::Doc { spec, upto } if spec.starts_with("ce-ref://") => (spec.clone(), upto),
        ThreadRef::Doc { spec, upto } => (format!("doc:{spec}"), upto),
    };
    match upto {
        Some(u) => format!("{base}@{u}"),
        None => base,
    }
}

pub fn egress(e: &EgressDef) -> String {
    let ports: Vec<String> = e.ports.iter().map(u16::to_string).collect();
    format!("{}:{}{}", e.host, ports.join("+"), if e.udp { "/udp" } else { "" })
}

fn resource(r: &ResourceDef) -> String {
    match r {
        ResourceDef::Any => "any node".into(),
        ResourceDef::Node(n) => node(n),
        ResourceDef::Nodes(ns) if ns.len() >= 2 => ns.iter().map(node).collect::<Vec<_>>().join(", "),
        ResourceDef::Nodes(ns) => format!("nodes {}", ns.iter().map(node).collect::<Vec<_>>().join(", ")),
        ResourceDef::Tag(t) => format!("nodes tagged {t}"),
        ResourceDef::AllOf(ts) => format!("nodes tagged all of {}", ts.join(", ")),
    }
}

fn quoted(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn prog_ref(out: &mut String, p: &ProgRef, depth: usize) -> String {
    match p {
        ProgRef::Name(n) => n.clone(),
        ProgRef::Id(h) => format!("program:{}", hex::encode(h)),
        ProgRef::Inline(steps) => {
            let mut s = String::from("{\n");
            for st in steps {
                step(&mut s, st, depth + 1);
            }
            s.push_str(&ind(depth));
            s.push('}');
            let _ = out;
            s
        }
    }
}

fn amount_for(name: &str, v: u64) -> String {
    if name.ends_with("_s") {
        fmt_duration(v)
    } else if name.contains("bytes") {
        fmt_bytes(v)
    } else {
        v.to_string()
    }
}

fn clause(out: &mut String, c: &Clause, d: usize) {
    let line = match c {
        Clause::Can(a, _) => format!("can {}", a.join(", ")),
        Clause::MayGrant { abilities, to, depth, .. } => {
            let to = match to {
                AudienceDef::Anyone => "anyone".to_string(),
                AudienceDef::Some(ps) => ps.iter().map(principal).collect::<Vec<_>>().join(", "),
            };
            format!("may grant {} to {to} depth {depth}", abilities.join(", "))
        }
        Clause::On(r, _) => format!("on {}", resource(r)),
        Clause::Until(TimeDef::At(t), _) => format!("until {}", fmt_time(*t)),
        Clause::Until(TimeDef::For(s), _) => format!("for {}", fmt_duration(*s)),
        Clause::NotBefore(TimeDef::At(t), _) => format!("not before {}", fmt_time(*t)),
        Clause::NotBefore(TimeDef::For(s), _) => format!("not before @{s}"),
        Clause::Uses { max: 1, per: UsePer::Link, .. } => "once".into(),
        Clause::Uses { max, per: UsePer::Link, .. } => format!("uses {max} per link"),
        Clause::Uses { max, per: UsePer::Action, .. } => format!("uses {max} per action"),
        Clause::Limit { name, max, .. } => format!("limit {name} {}", amount_for(name, *max)),
        Clause::Egress(rules, _) if rules.is_empty() => "egress none".into(),
        Clause::Egress(rules, _) => format!("egress {}", rules.iter().map(egress).collect::<Vec<_>>().join(", ")),
        Clause::Cpu(n, _) => format!("cpu {n}"),
        Clause::MemoryMb(n, _) => format!("memory {n}MB"),
        Clause::Credits(n, _) => format!("credits {n}"),
        Clause::Ports(ps, _) if ps.is_empty() => "ports none".into(),
        Clause::Ports(ps, _) => format!("ports {}", ps.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")),
        Clause::FilesUnder(p, _) => format!("files under {p}"),
        Clause::Only(ps, _) => {
            let mut parts = Vec::new();
            for p in ps {
                parts.push(prog_ref(out, p, d));
            }
            format!("only {}", parts.join(", "))
        }
        Clause::Require(RequireDef::Read { what, by, within }, _) => {
            let w = within.map(|s| format!(" within {}", fmt_duration(s))).unwrap_or_default();
            format!("require read {} by {}{w}", thread(what), party(by))
        }
        Clause::Require(RequireDef::Fact { name, value, by, within }, _) => {
            let v = match std::str::from_utf8(value) {
                Ok(s) if !s.is_empty() && s.chars().all(|c| !c.is_control()) => quoted(s),
                _ => format!("hex:{}", hex::encode(value)),
            };
            let w = within.map(|s| format!(" within {}", fmt_duration(s))).unwrap_or_default();
            format!("require fact {name} = {v} by {}{w}", party(by))
        }
        Clause::CoSign(p, _) => format!("cosign {}", principal(p)),
        Clause::Via(p, _) => format!("via {}", party(p)),
        Clause::Nonce(n, _) => format!("nonce {n}"),
        Clause::InheritNothing(_) => "inherit nothing".into(),
    };
    out.push_str(&ind(d));
    out.push_str(&line);
    out.push('\n');
}

fn step(out: &mut String, s: &StepDef, d: usize) {
    out.push_str(&ind(d));
    match s {
        StepDef::Install { file: f, to, on, mode, .. } => {
            out.push_str(&format!("install {} to {to} on {}", file(f), node(on)));
            if *mode != 0o644 {
                out.push_str(&format!(" mode {mode:o}"));
            }
        }
        StepDef::InstallCell { verb, cell: c, build, on, .. } => {
            out.push_str(&format!("{verb} {} build {} on {}", cell(c), hash_pin(build), node(on)));
        }
        StepDef::Call { cell: c, op, on, body, .. } => {
            out.push_str(&format!("call {} {op} on {} body {}", cell(c), node(on), hash_pin(body)));
        }
        StepDef::Include { program, .. } => {
            let r = prog_ref(&mut String::new(), program, d);
            out.push_str(&format!("include {r}"));
        }
        StepDef::Spawn { exe, on, keep, opts, .. } => {
            let exe = match exe {
                SpawnExe::File { file: f, at: Some(p) } => format!("{} at {p}", file(f)),
                SpawnExe::File { file: f, at: None } => file(f),
                SpawnExe::Step(i) => format!("step {i}"),
            };
            out.push_str(&format!("spawn {exe} on {} {}", resource(on), if *keep { "keep" } else { "once" }));
            let o = spawn_opts(opts);
            if !o.is_empty() {
                out.push_str(" {\n");
                for l in o {
                    out.push_str(&ind(d + 1));
                    out.push_str(&l);
                    out.push('\n');
                }
                out.push_str(&ind(d));
                out.push('}');
            }
        }
    }
    out.push('\n');
}

fn spawn_opts(o: &SpawnOpts) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(a) = &o.args {
        v.push(format!("args {}", a.iter().map(|x| quoted(x)).collect::<Vec<_>>().join(" ")));
    }
    for (k, val) in &o.env {
        v.push(format!("env {k} {}", quoted(val)));
    }
    if let Some(c) = &o.cwd {
        v.push(format!("cwd {c}"));
    }
    if let Some(n) = o.cpu {
        v.push(format!("cpu {n}"));
    }
    if let Some(n) = o.memory_mb {
        v.push(format!("memory {n}MB"));
    }
    if let Some(n) = o.time_s {
        v.push(format!("time {}", fmt_duration(n)));
    }
    if !o.read.is_empty() {
        v.push(format!("read {}", o.read.join(", ")));
    }
    if !o.write.is_empty() {
        v.push(format!("write {}", o.write.join(", ")));
    }
    if !o.egress.is_empty() {
        v.push(format!("egress {}", o.egress.iter().map(egress).collect::<Vec<_>>().join(", ")));
    }
    if let Some(n) = o.bytes_out {
        v.push(format!("out {}", fmt_bytes(n)));
    }
    if let Some(n) = o.bytes_in {
        v.push(format!("in {}", fmt_bytes(n)));
    }
    v
}
