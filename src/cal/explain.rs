//! `ce-cal explain` (`docs/CAL.md` section 5): what a chain allows and requires, in plain
//! English, link by link, every readable ref beside the pinned value it stands for.
//!
//! The text is generated from the compiled links and programs (what a verifier reads), never
//! from the source, so it says exactly what the token means; the source contributes only names.

use super::Labels;
use super::refs::fmt_key;
use super::units::{say_bytes, say_duration, say_time};
use crate::program::{self, EgressRule, Exe, Hash, HostPat, NodeKey, Program, Proto, ResourceV3, RunMode, Step};
use crate::v3::narrow::{audience_in, fresh_no_looser};
use crate::v3::{AudienceSet, CapabilityV3, Caveat, Claim, Delegate, Key, Party, Requirement, UsePer, cap_id};

/// `name = ed25519:<hex>`, or the key alone when no name is known.
pub fn key(k: &Key, l: &Labels) -> String {
    match l.key(k) {
        Some(n) => format!("{n} = {}", fmt_key(k)),
        None => fmt_key(k),
    }
}

fn short_key(k: &Key, l: &Labels) -> String {
    l.key(k).map(str::to_string).unwrap_or_else(|| fmt_key(k))
}

pub fn node(n: &NodeKey, l: &Labels) -> String {
    match l.nodes.get(n) {
        Some(name) if !name.is_empty() => format!("node:{name} = {}", hex::encode(n)),
        _ => format!("node:{}", hex::encode(n)),
    }
}

pub fn resource(r: &ResourceV3, l: &Labels) -> String {
    match r {
        ResourceV3::Any => "on any node".into(),
        ResourceV3::Node(n) => format!("only on {}", node(n, l)),
        ResourceV3::Nodes(ns) => format!("only on these {} nodes: {}", ns.len(), ns.iter().map(|n| node(n, l)).collect::<Vec<_>>().join("; ")),
        ResourceV3::Tag(t) => format!("only on nodes tagged '{t}'"),
        ResourceV3::AllOf(ts) => format!("only on nodes tagged all of: {}", ts.join(", ")),
    }
}

pub fn program_name(id: &Hash, l: &Labels) -> String {
    match l.programs.get(id) {
        Some(n) => format!("{n} (program id {})", hex::encode(id)),
        None => format!("program {}", hex::encode(id)),
    }
}

fn file(sha: &Hash, l: &Labels) -> String {
    let mut s = String::new();
    if let Some(n) = l.files.get(sha).filter(|n| !n.starts_with("ce-blob:")) {
        s.push_str(n);
        if let Some(p) = l.portable.get(sha).filter(|p| *p != n) {
            s.push_str(&format!(" ({p})"));
        }
        s.push_str(", ");
    }
    s.push_str(&format!("content sha256:{}", hex::encode(sha)));
    s
}

pub fn egress_rule(r: &EgressRule) -> String {
    let host = match &r.host {
        HostPat::Name(n) => n.clone(),
        HostPat::Suffix(s) => format!("any name ending in {s}"),
        HostPat::Cidr { addr, prefix } => {
            let a = match addr.len() {
                4 => std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string(),
                16 => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(addr);
                    std::net::Ipv6Addr::from(b).to_string()
                }
                _ => hex::encode(addr),
            };
            format!("addresses in {a}/{prefix}")
        }
    };
    let ports: Vec<String> = r.ports.iter().map(u16::to_string).collect();
    let proto = match r.proto {
        Proto::Tcp => "TCP",
        Proto::Udp => "UDP",
    };
    format!("{host}, {proto} port{} {}", if ports.len() == 1 { "" } else { "s" }, ports.join(", "))
}

pub fn party(p: &Party, l: &Labels) -> String {
    match p {
        Party::Key(k) => key(k, l),
        Party::Cell(api) => format!("cell:{api} (whichever key the executing node trusts for it)"),
    }
}

fn claim(c: &Claim) -> String {
    match c {
        Claim::ReadThrough { source, thread, upto_msg } => {
            let what = if source == "doc" { format!("document {thread}") } else { format!("{source} thread {thread}") };
            match upto_msg {
                Some(m) => format!("has read {what} through message {m}"),
                None => format!("has read {what} through its newest message at the time"),
            }
        }
        Claim::Fact { name, value } => match std::str::from_utf8(value) {
            Ok(s) => format!("satisfies {name} = \"{s}\""),
            Err(_) => format!("satisfies {name} = hex:{}", hex::encode(value)),
        },
    }
}

pub fn requirement(r: &Requirement, l: &Labels) -> String {
    let fresh = match r.fresh_within_s {
        Some(s) => format!(", attested at most {} before the use", say_duration(s)),
        None => ", attested at any time before the use".into(),
    };
    format!("{} must attest that the requester {}{fresh}", party(&r.witness, l), claim(&r.claim))
}

fn ability_list(a: &[String]) -> String {
    a.iter().map(|x| format!("'{x}'")).collect::<Vec<_>>().join(", ")
}

/// Plain-English lines for the caveats of one link (the v1 fields and `ext`).
fn caveat_lines(c: &CapabilityV3, l: &Labels, out: &mut Vec<String>) {
    let cv = &c.caveats;
    match (cv.not_before, cv.not_after) {
        (0, 0) => out.push("When: no time limit (never expires).".into()),
        (0, t) => out.push(format!("When: until {} (unix {t}).", say_time(t))),
        (f, 0) => out.push(format!("When: from {} (unix {f}), no end.", say_time(f))),
        (f, t) => out.push(format!("When: from {} until {} (unix {f} to {t}).", say_time(f), say_time(t))),
    }
    if let Some(p) = &cv.path_prefix {
        out.push(format!("Files: only paths under {p}."));
    }
    if let Some(n) = cv.max_cpu {
        out.push(format!("CPU: at most {n} core{} per process.", if n == 1 { "" } else { "s" }));
    }
    if let Some(n) = cv.max_mem_mb {
        out.push(format!("Memory: at most {n} MB per process."));
    }
    if let Some(n) = cv.max_credits {
        out.push(format!("Credits: at most {n}."));
    }
    if let Some(ps) = &cv.allowed_ports {
        if ps.is_empty() {
            out.push("Tunnels: no port may be reached.".into());
        } else {
            out.push(format!("Tunnels: only ports {}.", ps.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")));
        }
    }
    for e in &c.ext {
        match e {
            Caveat::Uses { max, per: UsePer::Link } => out.push(format!(
                "Counted: at most {max} use{} at each node; a plain call is one use, and so is a program run (leaf, program, run), charged at its first step on that node.",
                if *max == 1 { "" } else { "s" }
            )),
            Caveat::Uses { max, per: UsePer::Action } => out.push(format!(
                "Counted: at most {max} use{} of each action at each node (each specific right is counted on its own).",
                if *max == 1 { "" } else { "s" }
            )),
            Caveat::Limits(ls) => {
                for lim in ls {
                    let v = if lim.name.contains("bytes") {
                        say_bytes(lim.max)
                    } else if lim.name.ends_with("_s") {
                        say_duration(lim.max)
                    } else {
                        lim.max.to_string()
                    };
                    let kind = match lim.name.as_str() {
                        "net.egress.bytes_out" => "bytes sent, in total",
                        "net.egress.bytes_in" => "bytes received, in total",
                        "net.egress.conns" => "connections opened, in total",
                        "proc.spawn.wall_s" => "wall-clock time per spawned process",
                        "proc.spawn.procs" => "processes alive at once",
                        _ => "a ceiling set by that cell",
                    };
                    out.push(format!("Limit: {} at most {v} ({kind}).", lim.name));
                }
            }
            Caveat::Egress(rs) if rs.is_empty() => out.push("Network: none at all.".into()),
            Caveat::Egress(rs) => {
                out.push(format!("Network: only to {}.", rs.iter().map(egress_rule).collect::<Vec<_>>().join("; ")));
            }
            Caveat::Programs(ids) => out.push(format!(
                "Programs: may be used only to execute {}.",
                ids.iter().map(|i| program_name(i, l)).collect::<Vec<_>>().join(", or ")
            )),
            c => out.extend(conditions(c, l).into_iter().map(|(k, t)| format!("Condition ({k}): {t}"))),
        }
    }
}

/// The sentences of one condition caveat, each with its kind (`require`, `cosign`, `via`).
pub fn conditions(c: &Caveat, l: &Labels) -> Vec<(&'static str, String)> {
    match c {
        Caveat::Requires(rs) => rs.iter().map(|r| ("require", format!("before every use, {}.", requirement(r, l)))).collect(),
        Caveat::CoSign(cs) => cs.iter().map(|c| ("cosign", format!("every use must be co-signed by {}, over that exact request.", key(&c.by, l)))).collect(),
        Caveat::Via(ps) => ps
            .iter()
            .map(|p| ("via", format!("every use must come through {}, which signs its approval of that exact request.", party(p, l))))
            .collect(),
        _ => Vec::new(),
    }
}

fn delegate_lines(c: &CapabilityV3, l: &Labels, out: &mut Vec<String>) {
    let who = short_key(&c.audience, l);
    match &c.delegate {
        None => out.push("Delegation: nothing may be granted below this link (it is final).".into()),
        Some(Delegate { abilities, audience, depth }) => {
            let to = match audience {
                AudienceSet::Any => "to anyone".to_string(),
                AudienceSet::Keys(ks) => format!("only to {}", ks.iter().map(|k| key(k, l)).collect::<Vec<_>>().join("; ")),
            };
            let deep = if *depth == 1 {
                "one link deep: the link it grants may grant nothing further".to_string()
            } else {
                format!("up to {depth} links deep")
            };
            out.push(format!("Delegation: {who} may grant {} {to}, {deep}.", ability_list(abilities)));
        }
    }
}

fn step_line(i: usize, s: &Step, steps: &[Step], l: &Labels) -> Vec<String> {
    let mut v = Vec::new();
    match s {
        Step::Install { on, path, sha256, size, mode } => {
            v.push(format!("step {i}: install {} ({size} bytes) as {path}, mode {mode:04o}, on {}.", file(sha256, l), node(on, l)));
            v.push(format!("        The node checks that the bytes hash to sha256:{} before it writes them.", hex::encode(sha256)));
        }
        Step::InstallCell { on, verb, api, build } => {
            v.push(format!("step {i}: {verb} cell {api}, build sha256:{} (checked against its signed build statement), on {}.", hex::encode(build), node(on, l)));
        }
        Step::Call { on, api, op, req_sha256 } => {
            v.push(format!("step {i}: call {api} {op} on {}, with exactly the request whose bytes hash to sha256:{}.", node(on, l), hex::encode(req_sha256)));
        }
        Step::Sub { program } => v.push(format!("step {i}: run all of {}.", program_name(program, l))),
        Step::Run { on, exe, argv, env, cwd, mode, sandbox } => {
            let exe = match exe {
                Exe::Output(j) => match steps.get(*j as usize) {
                    Some(Step::Install { path, sha256, .. }) => format!("the file step {j} installed ({path}, sha256:{})", hex::encode(sha256)),
                    _ => format!("the file step {j} installed"),
                },
                Exe::Path { path, sha256 } => format!("{path}, which must be {}", file(sha256, l)),
            };
            let how = match mode {
                RunMode::Once => "once, to completion",
                RunMode::Keep => "and keep it running (restarted until the chain expires)",
            };
            v.push(format!("step {i}: spawn {exe} {how}, {}.", resource(on, l)));
            v.push(format!("        argv {:?}; environment {}; working directory {}.", argv,
                if env.is_empty() { "empty".to_string() } else { env.iter().map(|e| format!("{}={:?}", e.name, e.value)).collect::<Vec<_>>().join(" ") },
                if cwd.is_empty() { "a private one the runner chooses".to_string() } else { cwd.clone() }));
            let wall = if sandbox.wall_s == 0 { "no time limit".to_string() } else { format!("at most {}", say_duration(sandbox.wall_s)) };
            v.push(format!("        Sandbox: {} CPU core{}, {} MB memory, {wall}; reads {}; writes {}.", sandbox.cpu, if sandbox.cpu == 1 { "" } else { "s" }, sandbox.mem_mb,
                if sandbox.read.is_empty() { "only its executable".to_string() } else { sandbox.read.join(", ") },
                if sandbox.write.is_empty() { "nothing".to_string() } else { sandbox.write.join(", ") }));
            if sandbox.egress.is_empty() {
                v.push("        Network: none.".into());
            } else {
                v.push(format!("        Network: only {}; at most {} out and {} in.", sandbox.egress.iter().map(egress_rule).collect::<Vec<_>>().join("; "), say_bytes(sandbox.bytes_out), say_bytes(sandbox.bytes_in)));
            }
            v.push("        The runner checks the executable's bytes against its hash before it starts it.".into());
        }
    }
    v
}

fn scope_of(c: &CapabilityV3) -> program::Scope<'_> {
    let egress = c.ext.iter().find_map(|x| if let Caveat::Egress(r) = x { Some(r.as_slice()) } else { None });
    let limits = c.ext.iter().find_map(|x| if let Caveat::Limits(r) = x { Some(r.as_slice()) } else { None }).unwrap_or(&[]);
    program::Scope {
        abilities: &c.abilities,
        resource: &c.resource,
        path_prefix: c.caveats.path_prefix.as_deref(),
        max_cpu: c.caveats.max_cpu,
        max_mem_mb: c.caveats.max_mem_mb,
        egress,
        limits,
    }
}

/// Explain a chain (root first) and the program bodies it carries.
pub fn explain(links: &[CapabilityV3], programs: &[Program], l: &Labels) -> String {
    let mut o = String::new();
    let n = links.len();
    o.push_str(&format!(
        "A chain of {n} link{}{}. Each link is signed by its issuer and can only narrow the link above it; every use must satisfy every link.\n",
        if n == 1 { "" } else { "s" },
        match programs.len() {
            0 => String::new(),
            1 => ", carrying 1 program".into(),
            k => format!(", carrying {k} programs"),
        }
    ));
    for (i, c) in links.iter().enumerate() {
        o.push_str(&format!("\nLink {i}: {} grants {}\n", short_key(&c.issuer, l), short_key(&c.audience, l)));
        let mut lines = vec![
            format!("link id   {}", hex::encode(cap_id(c))),
            format!("issuer    {}", key(&c.issuer, l)),
            format!("audience  {}", key(&c.audience, l)),
        ];
        if i == 0 {
            lines.push("This is the root: a node accepts the chain only if it trusts the issuer's key as a root.".into());
        }
        let who = short_key(&c.audience, l);
        if c.abilities.is_empty() {
            lines.push(format!("Own use: {who} may not use this link itself; it can only grant."));
        } else {
            lines.push(format!("Own use: {who} may {}.", ability_list(&c.abilities)));
        }
        delegate_lines(c, l, &mut lines);
        lines.push(format!("Where: {}.", resource(&c.resource, l)));
        caveat_lines(c, l, &mut lines);
        if !c.ext.iter().any(Caveat::is_condition) {
            lines.push("Conditions: none on this link.".into());
        }
        for x in lines {
            o.push_str(&format!("  {x}\n"));
        }
    }
    for p in programs {
        let id = p.id();
        o.push_str(&format!("\nProgram {}, {} step{}:\n", program_name(&id, l), p.steps.len(), if p.steps.len() == 1 { "" } else { "s" }));
        for (i, s) in p.steps.iter().enumerate() {
            for x in step_line(i, s, &p.steps, l) {
                o.push_str(&format!("  {x}\n"));
            }
        }
        if let Some(leaf) = links.last() {
            let typed = program::expand(p, programs).and_then(|steps| program::type_check(&steps, &scope_of(leaf), &|_| None));
            match typed {
                Ok(()) => o.push_str(&format!("  Typed under the leaf: every step is within what {} may do.\n", short_key(&leaf.audience, l))),
                Err(e) => o.push_str(&format!("  Typed under the leaf: {} could not execute it itself ({e}).\n", short_key(&leaf.audience, l))),
            }
        }
    }
    if let Some(leaf) = links.last() {
        let who = key(&leaf.audience, l);
        o.push_str(&format!("\nIn short: the chain is held by {who}.\n"));
        if leaf.abilities.is_empty() {
            o.push_str("  It may not act with this chain itself.\n");
        } else {
            let mut how = vec![resource(&leaf.resource, l)];
            if leaf.caveats.not_after != 0 {
                how.push(format!("until {}", say_time(leaf.caveats.not_after)));
            }
            if let Some(Caveat::Programs(ids)) = leaf.ext.iter().find(|c| matches!(c, Caveat::Programs(_))) {
                how.push(format!("only to execute {}", ids.iter().map(|i| l.programs.get(i).cloned().unwrap_or_else(|| hex::encode(&i[..8]))).collect::<Vec<_>>().join(" or ")));
            }
            o.push_str(&format!("  It may {}, {}.\n", ability_list(&leaf.abilities), how.join(", ")));
        }
        match &leaf.delegate {
            None => o.push_str("  It may grant nothing further.\n"),
            Some(d) => o.push_str(&format!("  It may grant {} further, {} link{} deep.\n", ability_list(&d.abilities), d.depth, if d.depth == 1 { "" } else { "s" })),
        }
        let conds: Vec<&Caveat> = leaf.ext.iter().filter(|c| c.is_condition()).collect();
        if conds.is_empty() {
            o.push_str("  No condition beyond the chain itself: no proof is needed at use.\n");
        } else {
            o.push_str("  Every use must also meet these conditions:\n");
            for c in conds {
                for (_, t) in conditions(c, l) {
                    o.push_str(&format!("    {t}\n"));
                }
            }
        }
    }
    o
}

fn caveat_name(c: &Caveat) -> &'static str {
    match c {
        Caveat::Uses { .. } => "its use count (once/uses)",
        Caveat::Limits(_) => "its limits",
        Caveat::Egress(_) => "its egress rules",
        Caveat::Programs(_) => "its program binding (only)",
        Caveat::Requires(_) => "a require condition",
        Caveat::CoSign(_) => "a cosign condition",
        Caveat::Via(_) => "a via condition",
    }
}

/// Why `child` is not a valid link below `parent`, in plain English (empty when it is).
pub fn why_child(child: &CapabilityV3, parent: &CapabilityV3, l: &Labels) -> String {
    let mut why: Vec<String> = Vec::new();
    let holder = short_key(&parent.audience, l);
    if child.issuer != parent.audience {
        why.push(format!("it is signed by {}, but only {holder}, the parent's audience, may grant below the parent", short_key(&child.issuer, l)));
    }
    let Some(d) = &parent.delegate else {
        why.push("the parent has no 'may grant': nothing may be granted below it".into());
        return why.join("; ");
    };
    if !audience_in(&child.audience, &d.audience) {
        why.push(format!("it is addressed to {}, but the parent lets {holder} grant only to the keys it lists", short_key(&child.audience, l)));
    }
    let over: Vec<&String> = child.abilities.iter().filter(|a| !d.abilities.iter().any(|g| program::covers(g, a))).collect();
    if !over.is_empty() {
        why.push(format!(
            "it gives {}, which the parent does not let {holder} grant (it may grant {})",
            over.iter().map(|a| format!("'{a}'")).collect::<Vec<_>>().join(", "),
            ability_list(&d.abilities)
        ));
    }
    if let Some(e) = &child.delegate {
        if d.depth < 2 {
            why.push("the parent's grant is one link deep, so this link may not grant further: remove its 'may grant'".into());
        } else if e.depth > d.depth - 1 {
            why.push(format!("the parent allows {} more links, so this link may allow at most depth {} (it says {})", d.depth, d.depth - 1, e.depth));
        }
        let over: Vec<&String> = e.abilities.iter().filter(|a| !d.abilities.iter().any(|g| program::covers(g, a))).collect();
        if !over.is_empty() {
            why.push(format!("it lets its holder grant {}, beyond the parent's grant", over.iter().map(|a| format!("'{a}'")).collect::<Vec<_>>().join(", ")));
        }
        if matches!((&e.audience, &d.audience), (AudienceSet::Any, AudienceSet::Keys(_))) {
            why.push("it lets its holder grant to anyone, but the parent names who may be granted".into());
        }
    }
    if !child.resource.is_subset_of(&parent.resource) {
        why.push(format!("it applies {}, outside the parent's {}", resource(&child.resource, l).trim_start_matches("only "), resource(&parent.resource, l).trim_start_matches("only ")));
    }
    let (c, p) = (&child.caveats, &parent.caveats);
    if p.not_after != 0 && (c.not_after == 0 || c.not_after > p.not_after) {
        why.push(format!("it lasts {}, past the parent's end, {}", if c.not_after == 0 { "forever".to_string() } else { format!("until {}", say_time(c.not_after)) }, say_time(p.not_after)));
    }
    if c.not_before < p.not_before {
        why.push("it starts before the parent does".into());
    }
    let looser = |cv: Option<u64>, pv: Option<u64>| pv.is_some() && cv.is_none_or(|x| x > pv.unwrap_or(0));
    if looser(c.max_cpu.map(u64::from), p.max_cpu.map(u64::from)) {
        why.push("it allows more CPU than the parent".into());
    }
    if looser(c.max_mem_mb.map(u64::from), p.max_mem_mb.map(u64::from)) {
        why.push("it allows more memory than the parent".into());
    }
    if looser(c.max_credits, p.max_credits) {
        why.push("it allows more credits than the parent".into());
    }
    if let Some(pp) = &p.path_prefix {
        if c.path_prefix.as_ref().is_none_or(|cp| !program::path_within(cp, pp)) {
            why.push(format!("its files reach outside the parent's {pp}"));
        }
    }
    if let Some(pp) = &p.allowed_ports {
        if c.allowed_ports.as_ref().is_none_or(|cp| !cp.iter().all(|x| pp.contains(x))) {
            why.push("it allows tunnel ports the parent does not".into());
        }
    }
    for pe in &parent.ext {
        let Some(ce) = child.ext.iter().find(|x| x.index() == pe.index()) else {
            why.push(format!("it drops {} that the parent sets: a child must repeat (or narrow) every caveat above it", caveat_name(pe)));
            continue;
        };
        match (ce, pe) {
            (Caveat::Uses { max: cm, per: cp }, Caveat::Uses { max: pm, per: pp }) => {
                if cp != pp {
                    why.push("it counts uses per a different unit than the parent (per link vs per action)".into());
                } else if cm > pm {
                    why.push(format!("it allows {cm} uses, more than the parent's {pm}"));
                }
            }
            (Caveat::Limits(cl), Caveat::Limits(pl)) => {
                for x in pl {
                    match cl.iter().find(|y| y.name == x.name) {
                        None => why.push(format!("it drops the parent's limit {}", x.name)),
                        Some(y) if y.max > x.max => why.push(format!("its limit {} is {}, above the parent's {}", x.name, y.max, x.max)),
                        _ => {}
                    }
                }
            }
            (Caveat::Egress(cr), Caveat::Egress(pr)) => {
                for r in cr.iter().filter(|r| !r.is_covered_by(pr)) {
                    why.push(format!("its egress to {} is not covered by the parent's ({})", egress_rule(r), pr.iter().map(egress_rule).collect::<Vec<_>>().join("; ")));
                }
            }
            (Caveat::Programs(ci), Caveat::Programs(pi)) => {
                for id in ci.iter().filter(|i| !pi.contains(i)) {
                    why.push(format!("it binds {}, which the parent does not allow", program_name(id, l)));
                }
            }
            (Caveat::Requires(cr), Caveat::Requires(pr)) => {
                for r in pr {
                    match cr.iter().find(|x| x.witness == r.witness && x.claim == r.claim) {
                        None => why.push(format!("it drops the parent's condition: {}", requirement(r, l))),
                        Some(x) if !fresh_no_looser(x.fresh_within_s, r.fresh_within_s) => {
                            why.push(format!("it accepts a staler attestation than the parent does ({})", requirement(r, l)))
                        }
                        _ => {}
                    }
                }
            }
            (Caveat::CoSign(cs), Caveat::CoSign(ps)) => {
                for x in ps.iter().filter(|x| !cs.contains(x)) {
                    why.push(format!("it drops the parent's co-signer {}", key(&x.by, l)));
                }
            }
            (Caveat::Via(cb), Caveat::Via(pb)) => {
                for x in pb.iter().filter(|x| !cb.contains(x)) {
                    why.push(format!("it drops the parent's broker {}", party(x, l)));
                }
            }
            _ => {}
        }
    }
    why.join("; ")
}
