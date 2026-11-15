//! The CAL lexer and parser (`docs/CAL.md` section 2): text to [`File`]. Hand-written recursive
//! descent over the grammar in the doc, one function per rule. Every error names its line.
//!
//! Refs are classified here (a principal must be `person:`, `agent:`, `node:` or a key; a file
//! `repo:`, `ce-ref://repo/` or `ce-blob:`), so a bare name or path is refused before anything
//! is looked up; resolving them is the compiler's job.

use super::CalError;
use super::ast::*;
use super::refs::{hex32, is_lower_hex, parse_key};
use super::units;
use crate::v3::UsePer;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Str(String),
    Open,
    Close,
    Comma,
    /// A newline or `;`.
    Sep,
}

struct Lexed {
    toks: Vec<(Tok, usize)>,
}

fn lex(src: &str) -> Result<Lexed, CalError> {
    let mut toks = Vec::new();
    let mut line = 1;
    let mut it = src.chars().peekable();
    while let Some(&c) = it.peek() {
        match c {
            '\n' => {
                it.next();
                toks.push((Tok::Sep, line));
                line += 1;
            }
            ';' => {
                it.next();
                toks.push((Tok::Sep, line));
            }
            c if c.is_whitespace() => {
                it.next();
            }
            '#' => {
                while it.peek().is_some_and(|c| *c != '\n') {
                    it.next();
                }
            }
            '{' => {
                it.next();
                toks.push((Tok::Open, line));
            }
            '}' => {
                it.next();
                toks.push((Tok::Close, line));
            }
            ',' => {
                it.next();
                toks.push((Tok::Comma, line));
            }
            '"' => {
                it.next();
                let mut s = String::new();
                loop {
                    match it.next() {
                        None | Some('\n') => return Err(CalError::at(line, "unterminated string")),
                        Some('"') => break,
                        Some('\\') => match it.next() {
                            Some('"') => s.push('"'),
                            Some('\\') => s.push('\\'),
                            Some('n') => s.push('\n'),
                            Some('t') => s.push('\t'),
                            _ => return Err(CalError::at(line, "unknown escape in string (use \\\" \\\\ \\n \\t)")),
                        },
                        Some(c) => s.push(c),
                    }
                }
                toks.push((Tok::Str(s), line));
            }
            _ => {
                let mut w = String::new();
                while let Some(&c) = it.peek() {
                    if c.is_whitespace() || "{};,\"".contains(c) {
                        break;
                    }
                    w.push(c);
                    it.next();
                }
                toks.push((Tok::Word(w), line));
            }
        }
    }
    Ok(Lexed { toks })
}

struct P {
    toks: Vec<(Tok, usize)>,
    i: usize,
}

type R<T> = Result<T, CalError>;

impl P {
    fn line(&self) -> usize {
        self.toks.get(self.i).or(self.toks.last()).map_or(1, |t| t.1)
    }
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i).map(|t| &t.0)
    }
    fn peek_word(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Word(w)) => Some(w),
            _ => None,
        }
    }
    fn err<T>(&self, msg: impl Into<String>) -> R<T> {
        Err(CalError::at(self.line(), msg))
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.i).map(|t| t.0.clone());
        self.i += 1;
        t
    }
    fn word(&mut self, what: &str) -> R<String> {
        match self.peek() {
            Some(Tok::Word(w)) => {
                let w = w.clone();
                self.i += 1;
                Ok(w)
            }
            Some(t) => {
                let found = describe(t);
                self.err(format!("expected {what}, found {found}"))
            }
            None => self.err(format!("expected {what}, found the end of the file")),
        }
    }
    fn keyword(&mut self, k: &str) -> R<()> {
        match self.peek_word() {
            Some(w) if w == k => {
                self.i += 1;
                Ok(())
            }
            _ => {
                let found = self.peek().map_or("the end of the file".to_string(), describe);
                self.err(format!("expected '{k}', found {found}"))
            }
        }
    }
    fn eat_word(&mut self, k: &str) -> bool {
        if self.peek_word() == Some(k) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn skip_seps(&mut self) {
        while self.eat(&Tok::Sep) {}
    }
    fn string(&mut self, what: &str) -> R<String> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(s),
            _ => {
                self.i -= 1;
                self.err(format!("expected {what} in double quotes"))
            }
        }
    }
    /// End of a clause: a separator, or the `}` that closes the block (left in place).
    fn end_clause(&mut self) -> R<()> {
        match self.peek() {
            Some(Tok::Sep) => {
                self.skip_seps();
                Ok(())
            }
            Some(Tok::Close) | None => Ok(()),
            Some(t) => {
                let found = describe(t);
                self.err(format!("unexpected {found}: one clause per line (or separate clauses with ';')"))
            }
        }
    }
    fn list<T>(&mut self, mut one: impl FnMut(&mut P) -> R<T>) -> R<Vec<T>> {
        let mut out = vec![one(self)?];
        while self.eat(&Tok::Comma) {
            // a list may continue on the next line after a comma
            while self.eat(&Tok::Sep) {}
            out.push(one(self)?);
        }
        Ok(out)
    }
    fn int<T: std::str::FromStr>(&mut self, what: &str) -> R<T> {
        let w = self.word(what)?;
        let clean: String = w.chars().filter(|c| *c != '_').collect();
        clean.parse().or_else(|_| self.back_err(format!("'{w}' is not {what}")))
    }
    fn back_err<T>(&mut self, msg: String) -> R<T> {
        self.i -= 1;
        self.err(msg)
    }
    fn duration(&mut self) -> R<u64> {
        let w = self.word("a duration (30s, 10m, 1h, 7d)")?;
        units::duration(&w).ok_or(()).or_else(|_| self.back_err(format!("'{w}' is not a duration (30s, 10m, 1h, 7d)")))
    }
    fn bytes(&mut self) -> R<u64> {
        let w = self.word("a size (512, 10MB, 1GiB)")?;
        units::bytes(&w).ok_or(()).or_else(|_| self.back_err(format!("'{w}' is not a size (512, 10MB, 1GiB)")))
    }
    fn memory(&mut self) -> R<u32> {
        let w = self.word("memory in MB (512MB)")?;
        match w.strip_suffix("MB").and_then(|n| n.parse::<u32>().ok()) {
            Some(n) => Ok(n),
            None => self.back_err(format!("'{w}' is not memory in MB: write it as <n>MB, e.g. 512MB")),
        }
    }
    fn abs_path(&mut self) -> R<String> {
        let w = self.word("an absolute path")?;
        if !crate::program::path_ok(&w) {
            return self.back_err(format!("'{w}' is not an absolute, normalized path on the node"));
        }
        Ok(w)
    }
    fn time(&mut self) -> R<u64> {
        let w = self.word("a time (2026-12-01, 2026-12-01T12:00Z or @<unix seconds>)")?;
        units::time(&w).ok_or(()).or_else(|_| self.back_err(format!("'{w}' is not a time: write 2026-12-01, 2026-12-01T12:00Z (UTC) or @<unix seconds>")))
    }
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::Word(w) => format!("'{w}'"),
        Tok::Str(s) => format!("\"{s}\""),
        Tok::Open => "'{'".into(),
        Tok::Close => "'}'".into(),
        Tok::Comma => "','".into(),
        Tok::Sep => "the end of the line".into(),
    }
}

/// Parse a whole CAL file.
pub fn parse(src: &str) -> Result<File, CalError> {
    let toks = lex(src)?.toks;
    let mut p = P { toks, i: 0 };
    let mut f = File::default();
    p.skip_seps();
    if p.eat_word("cal") {
        let v = p.word("the CAL version")?;
        if v != "1" {
            return p.back_err(format!("this is CAL 1; the file says 'cal {v}'"));
        }
        p.end_clause()?;
    }
    while p.peek().is_some() {
        if p.peek_word() == Some("program") {
            let line = p.line();
            p.i += 1;
            let name = p.word("a program name")?;
            if !ident(&name) {
                return p.back_err(format!("'{name}' is not a program name (letters, digits, '_' and '-', starting with a letter)"));
            }
            if f.programs.iter().any(|q| q.name == name) {
                return p.back_err(format!("program '{name}' is defined twice"));
            }
            let steps = steps_block(&mut p)?;
            f.programs.push(ProgramDef { name, steps, line });
        } else {
            f.links.push(link(&mut p)?);
        }
        p.skip_seps();
    }
    if f.links.is_empty() {
        return Err(CalError::at(p.line(), "a CAL file needs at least one link: <issuer> grants <audience> { ... }"));
    }
    Ok(f)
}

fn ident(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn link(p: &mut P) -> R<LinkDef> {
    let line = p.line();
    let issuer = principal(p)?;
    match p.peek_word() {
        Some("grants") => p.i += 1,
        Some("grant") => return p.err("write '<issuer> grants <audience> { ... }' (grants, with an s)"),
        _ => {
            let found = p.peek().map_or("the end of the file".into(), describe);
            return p.err(format!("expected 'grants' after the issuer, found {found}"));
        }
    }
    let audience = principal(p)?;
    if !p.eat(&Tok::Open) {
        return p.err("expected '{' to open the link's clauses");
    }
    p.skip_seps();
    let mut clauses = Vec::new();
    while !p.eat(&Tok::Close) {
        if p.peek().is_none() {
            return Err(CalError::at(line, "this link's '{' is never closed"));
        }
        clauses.push(clause(p)?);
        p.end_clause()?;
    }
    Ok(LinkDef { issuer, audience, clauses, line })
}

const PRINCIPAL_HELP: &str = "a principal is a ce-ref (person:<id>, agent:<lane>, node:<name>) or a key (ed25519:<hex>, p256:<hex>)";

fn principal(p: &mut P) -> R<PrincipalRef> {
    let w = p.word("a principal")?;
    if let Some(k) = parse_key(&w) {
        return Ok(PrincipalRef { name: String::new(), pin: Some(k) });
    }
    if w.starts_with("ed25519:") || w.starts_with("p256:") {
        return p.back_err(format!("'{w}' is not a full key: ed25519: takes 64 lowercase hex digits, p256: 66 (02/03 then X)"));
    }
    let ok = ["person:", "agent:", "node:"].iter().any(|k| w.strip_prefix(k).is_some_and(|r| !r.is_empty() && !r.contains(char::is_whitespace)));
    if !ok {
        let hint = if w.contains(':') { String::new() } else { format!(" — '{w}' is a bare name; write person:{w} or agent:{w}") };
        return p.back_err(format!("'{w}': {PRINCIPAL_HELP}{hint}"));
    }
    let pin = match p.peek_word().and_then(parse_key) {
        Some(k) => {
            p.i += 1;
            Some(k)
        }
        None => None,
    };
    Ok(PrincipalRef { name: w, pin })
}

fn node(p: &mut P) -> R<NodeRef> {
    let w = p.word("a node (node:<name> or node:<64 hex id>)")?;
    let Some(rest) = w.strip_prefix("node:").filter(|r| !r.is_empty()) else {
        let hint = if w.contains(':') { String::new() } else { format!(" — write node:{w}") };
        return p.back_err(format!("'{w}' is not a node ref: write node:<name> or node:<64 hex id>{hint}"));
    };
    if let Some(id) = hex32(rest) {
        return Ok(NodeRef { name: String::new(), pin: Some(id) });
    }
    let pin = match p.peek_word() {
        Some(k) if k.starts_with("ed25519:") => match parse_key(k) {
            Some(crate::v3::Key::Ed25519(id)) => {
                p.i += 1;
                Some(id)
            }
            _ => return p.err(format!("'{k}' is not a full node id: ed25519: takes 64 lowercase hex digits")),
        },
        _ => None,
    };
    Ok(NodeRef { name: rest.to_string(), pin })
}

fn hash_pin(w: &str) -> Option<HashPin> {
    let h = w.strip_prefix("sha256:")?;
    if let Some(full) = hex32(h) {
        return Some(HashPin::Full(full));
    }
    let pre = h.trim_end_matches('…').trim_end_matches("...");
    is_lower_hex(pre).then(|| HashPin::Prefix(pre.to_string()))
}

fn sha(p: &mut P, what: &str) -> R<HashPin> {
    let w = p.word(&format!("{what} (sha256:<64 hex>)"))?;
    hash_pin(&w).ok_or(()).or_else(|_| p.back_err(format!("'{w}' is not a content hash: write sha256:<64 lowercase hex>")))
}

fn file(p: &mut P) -> R<FileRef> {
    let w = p.word("a file (repo:<repo>/<path>@<commit> sha256:<hash>, or ce-blob:sha256:<hash>)")?;
    let (source, mut pin) = if let Some(h) = w.strip_prefix("ce-blob:") {
        let Some(pin) = hash_pin(h) else { return p.back_err(format!("'{w}': a blob is named by its hash, ce-blob:sha256:<64 hex>")) };
        (FileSource::Blob, Some(pin))
    } else if w.starts_with("ce-ref://repo/") {
        (FileSource::Portable(w.clone()), None)
    } else if let Some(rest) = w.strip_prefix("repo:") {
        let (spec, commit) = match rest.rsplit_once('@') {
            Some((s, c)) => {
                if c.len() < 4 || c.len() > 40 || !is_lower_hex(c) {
                    return p.back_err(format!("'@{c}' is not a commit: write @<4 to 40 lowercase hex digits>"));
                }
                (s.to_string(), Some(c.to_string()))
            }
            None => (rest.to_string(), None),
        };
        if !spec.contains('/') {
            return p.back_err(format!("'{w}' names a repository, not a file in it: write repo:<repo>/<path>@<commit>"));
        }
        (FileSource::Repo { spec, commit }, None)
    } else {
        return p.back_err(format!(
            "'{w}' is a bare path: it names a different file on every machine. Write repo:<repo>/<path>@<commit> sha256:<hash> for a file in a repository, or ce-blob:sha256:<hash> for any other content"
        ));
    };
    if pin.is_none() && p.peek_word().is_some_and(|w| w.starts_with("sha256:")) {
        pin = Some(sha(p, "the content hash")?);
    }
    let size = if p.eat_word("size") { Some(p.int("a size in bytes")?) } else { None };
    Ok(FileRef { source, sha: pin, size })
}

fn cell(p: &mut P) -> R<CellRef> {
    let w = p.word("a cell (cell:<api>@<major>)")?;
    let Some(rest) = w.strip_prefix("cell:").filter(|r| !r.is_empty()) else {
        return p.back_err(format!("'{w}' is not a cell ref: write cell:<api>@<major>, e.g. cell:printer3d.gate@1"));
    };
    let (api, major) = match rest.split_once('@') {
        Some((a, m)) => match m.parse::<u32>() {
            Ok(m) => (a, Some(m)),
            Err(_) => return p.back_err(format!("'@{m}' is not a major version: write cell:{a}@<number>")),
        },
        None => (rest, None),
    };
    if api.is_empty() || !api.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_') {
        return p.back_err(format!("'{api}' is not a cell api name ([A-Za-z0-9._-])"));
    }
    Ok(CellRef { api: api.to_string(), major })
}

fn party(p: &mut P) -> R<PartyRef> {
    if p.peek_word().is_some_and(|w| w.starts_with("cell:")) { Ok(PartyRef::Cell(cell(p)?)) } else { Ok(PartyRef::Principal(principal(p)?)) }
}

fn thread(p: &mut P) -> R<ThreadRef> {
    let w = p.word("what must be read (wechat:thread/<id>, doc:<repo>/<path>)")?;
    let (body, upto) = match w.rsplit_once('@') {
        Some((b, u)) if !u.is_empty() && !b.ends_with(':') => (b.to_string(), Some(u.to_string())),
        _ => (w.clone(), None),
    };
    if let Some(spec) = body.strip_prefix("doc:") {
        if !spec.contains('/') {
            return p.back_err(format!("'{w}': write doc:<repo>/<path>"));
        }
        return Ok(ThreadRef::Doc { spec: spec.to_string(), upto });
    }
    if body.starts_with("ce-ref://repo/") {
        return Ok(ThreadRef::Doc { spec: body, upto });
    }
    match body.split_once(":thread/") {
        Some((source, thread)) if ident(source) && !thread.is_empty() => {
            Ok(ThreadRef::Thread { source: source.to_string(), thread: thread.to_string(), upto })
        }
        _ => p.back_err(format!("'{w}' is not a thread or document ref: write <source>:thread/<id> (wechat:thread/123) or doc:<repo>/<path>")),
    }
}

fn egress_rule(p: &mut P) -> R<EgressDef> {
    let w = p.word("an egress rule (host:port)")?;
    let (hp, udp) = match w.strip_suffix("/udp") {
        Some(x) => (x, true),
        None => (w.strip_suffix("/tcp").unwrap_or(&w), false),
    };
    let Some((host, ports)) = hp.rsplit_once(':').filter(|(h, _)| !h.is_empty()) else {
        return p.back_err(format!("'{w}' is not an egress rule: write host:port, e.g. api.example.org:443, *.example.org:443 or 10.0.0.0/8:22"));
    };
    let mut out = Vec::new();
    for x in ports.split('+') {
        match x.parse::<u16>() {
            Ok(n) => out.push(n),
            Err(_) => return p.back_err(format!("'{x}' in '{w}' is not a port")),
        }
    }
    Ok(EgressDef { host: host.to_string(), ports: out, udp })
}

fn resource(p: &mut P) -> R<ResourceDef> {
    if p.eat_word("any") {
        p.keyword("node")?;
        return Ok(ResourceDef::Any);
    }
    if p.eat_word("nodes") {
        if p.eat_word("tagged") {
            if p.eat_word("all") {
                p.keyword("of")?;
                return Ok(ResourceDef::AllOf(p.list(|p| p.word("a tag"))?));
            }
            return Ok(ResourceDef::Tag(p.word("a tag")?));
        }
        return Ok(ResourceDef::Nodes(p.list(node)?));
    }
    let mut ns = p.list(node)?;
    Ok(if ns.len() == 1 { ResourceDef::Node(ns.remove(0)) } else { ResourceDef::Nodes(ns) })
}

fn ability(p: &mut P) -> R<String> {
    let w = p.word("an ability (<api>:<right>)")?;
    if w != "*" && !w.contains(':') {
        return p.back_err(format!("'{w}' is not an ability: write <api>:<right>, e.g. cell.install:install-file"));
    }
    Ok(w)
}

fn prog_ref(p: &mut P) -> R<ProgRef> {
    if p.peek() == Some(&Tok::Open) {
        return Ok(ProgRef::Inline(steps_block(p)?));
    }
    let w = p.word("a program (its name, program:<64 hex>, or { steps })")?;
    if let Some(h) = w.strip_prefix("program:") {
        return match hex32(h) {
            Some(id) => Ok(ProgRef::Id(id)),
            None => p.back_err(format!("'{w}': a program id is program:<64 lowercase hex>")),
        };
    }
    if !ident(&w) {
        return p.back_err(format!("'{w}' is not a program name"));
    }
    Ok(ProgRef::Name(w))
}

fn clause(p: &mut P) -> R<Clause> {
    let line = p.line();
    let k = p.word("a clause")?;
    Ok(match k.as_str() {
        "can" => Clause::Can(p.list(ability)?, line),
        "may" => {
            p.keyword("grant")?;
            let abilities = p.list(ability)?;
            // 'to' may start the next line of a long list
            let mut j = p.i;
            while p.toks.get(j).is_some_and(|t| t.0 == Tok::Sep) {
                j += 1;
            }
            if matches!(p.toks.get(j), Some((Tok::Word(w), _)) if w == "to") {
                p.i = j;
            }
            p.keyword("to")?;
            let to = if p.eat_word("anyone") { AudienceDef::Anyone } else { AudienceDef::Some(p.list(principal)?) };
            let depth = if p.eat_word("depth") { p.int("a depth (1 to 255)")? } else { 1 };
            if depth == 0 {
                return p.back_err("depth must be at least 1 (a link that may grant nothing simply has no 'may grant')".into());
            }
            Clause::MayGrant { abilities, to, depth, line }
        }
        "on" => Clause::On(resource(p)?, line),
        "until" => Clause::Until(TimeDef::At(p.time()?), line),
        "for" => Clause::Until(TimeDef::For(p.duration()?), line),
        "not" => {
            p.keyword("before")?;
            Clause::NotBefore(TimeDef::At(p.time()?), line)
        }
        "once" => Clause::Uses { max: 1, per: UsePer::Link, line },
        "uses" => {
            let max: u32 = p.int("a number of uses")?;
            if max == 0 {
                return p.back_err("uses must be at least 1".into());
            }
            let per = if p.eat_word("per") {
                match p.word("'link' or 'action'")?.as_str() {
                    "link" => UsePer::Link,
                    "action" => UsePer::Action,
                    w => return p.back_err(format!("'per {w}': write per link or per action")),
                }
            } else {
                UsePer::Link
            };
            Clause::Uses { max, per, line }
        }
        "limit" => {
            let name = p.word("a limit name (<api>.<name>)")?;
            if !name.contains('.') {
                return p.back_err(format!("'{name}' is not a limit name: write <api>.<name>, e.g. net.egress.bytes_out"));
            }
            let w = p.word("an amount")?;
            let max = units::amount(&w).ok_or(()).or_else(|_| p.back_err(format!("'{w}' is not an amount (10, 10MB, 1h)")))?;
            Clause::Limit { name, max, line }
        }
        "egress" => {
            if p.eat_word("none") { Clause::Egress(vec![], line) } else { Clause::Egress(p.list(egress_rule)?, line) }
        }
        "cpu" => Clause::Cpu(p.int("a number of cores")?, line),
        "memory" => Clause::MemoryMb(p.memory()?, line),
        "credits" => Clause::Credits(p.int("a number of credits")?, line),
        "ports" => {
            if p.eat_word("none") { Clause::Ports(vec![], line) } else { Clause::Ports(p.list(|p| p.int("a port"))?, line) }
        }
        "files" => {
            p.keyword("under")?;
            Clause::FilesUnder(p.abs_path()?, line)
        }
        "only" => Clause::Only(p.list(prog_ref)?, line),
        "require" => Clause::Require(require(p)?, line),
        "cosign" => Clause::CoSign(principal(p)?, line),
        "via" => Clause::Via(party(p)?, line),
        "nonce" => Clause::Nonce(p.int("a nonce (u64)")?, line),
        "inherit" => {
            p.keyword("nothing")?;
            Clause::InheritNothing(line)
        }
        "grants" | "grant" => return p.back_err("a link's clauses cannot grant: start a new link below this one with '<issuer> grants <audience> { ... }'".into()),
        other => {
            return p.back_err(format!(
                "unknown clause '{other}' (clauses: can, may grant, on, until, for, not before, once, uses, limit, egress, cpu, memory, credits, ports, files under, only, require, cosign, via, nonce, inherit nothing)"
            ));
        }
    })
}

fn require(p: &mut P) -> R<RequireDef> {
    let kind = p.word("'read' or 'fact'")?;
    let r = match kind.as_str() {
        "read" => {
            let what = thread(p)?;
            p.keyword("by")
                .map_err(|e| CalError { msg: format!("{} — say who attests the read, e.g. by cell:wechat.read@1", e.msg), ..e })?;
            let by = party(p)?;
            let within = if p.eat_word("within") { Some(p.duration()?) } else { None };
            RequireDef::Read { what, by, within }
        }
        "fact" => {
            let name = p.word("a fact name (<api>.<name>)")?;
            p.keyword("=")?;
            let value = match p.next() {
                Some(Tok::Str(s)) => s.into_bytes(),
                Some(Tok::Word(w)) if w.starts_with("hex:") => match hex::decode(&w[4..]) {
                    Ok(b) => b,
                    Err(_) => return p.back_err(format!("'{w}' is not hex")),
                },
                _ => return p.back_err("a fact value is \"text\" or hex:<bytes>".into()),
            };
            p.keyword("by")?;
            let by = party(p)?;
            let within = if p.eat_word("within") { Some(p.duration()?) } else { None };
            RequireDef::Fact { name, value, by, within }
        }
        w => return p.back_err(format!("'require {w}': write require read <thread> by <party> or require fact <name> = <value> by <party>")),
    };
    Ok(r)
}

fn steps_block(p: &mut P) -> R<Vec<StepDef>> {
    let open = p.line();
    if !p.eat(&Tok::Open) {
        return p.err("expected '{' to open the program's steps");
    }
    p.skip_seps();
    let mut steps = Vec::new();
    while !p.eat(&Tok::Close) {
        if p.peek().is_none() {
            return Err(CalError::at(open, "this program's '{' is never closed"));
        }
        steps.push(step(p)?);
        p.end_clause()?;
    }
    if steps.is_empty() {
        return Err(CalError::at(open, "a program needs at least one step"));
    }
    Ok(steps)
}

fn mode(p: &mut P) -> R<u32> {
    let w = p.word("a mode (octal, e.g. 755)")?;
    let digits = w.strip_prefix("0o").unwrap_or(&w);
    match u32::from_str_radix(digits, 8) {
        Ok(m) if m <= 0o7777 => Ok(m),
        _ => p.back_err(format!("'{w}' is not an octal mode (at most 7777)")),
    }
}

fn step(p: &mut P) -> R<StepDef> {
    let line = p.line();
    let k = p.word("a step (install, upgrade, spawn, call, include)")?;
    Ok(match k.as_str() {
        "install" | "upgrade" if p.peek_word().is_some_and(|w| w.starts_with("cell:")) => {
            let cell = cell(p)?;
            p.keyword("build")?;
            let build = sha(p, "the build id")?;
            p.keyword("on")?;
            StepDef::InstallCell { verb: k, cell, build, on: node(p)?, line }
        }
        "install" => {
            let file = file(p)?;
            p.keyword("to")?;
            let to = p.abs_path()?;
            p.keyword("on")?;
            let on = node(p)?;
            let mode = if p.eat_word("mode") { mode(p)? } else { 0o644 };
            StepDef::Install { file, to, on, mode, line }
        }
        "upgrade" => return p.back_err("upgrade takes a cell: upgrade cell:<api> build sha256:<hash> on node:<name>".into()),
        "spawn" => {
            let exe = if p.eat_word("step") {
                SpawnExe::Step(p.int("a step number")?)
            } else {
                let file = file(p)?;
                let at = if p.eat_word("at") { Some(p.abs_path()?) } else { None };
                SpawnExe::File { file, at }
            };
            p.keyword("on")?;
            let on = resource(p)?;
            let keep = if p.eat_word("keep") {
                true
            } else {
                p.eat_word("once");
                false
            };
            let mut opts = SpawnOpts::default();
            while matches!(p.peek(), Some(Tok::Word(_))) {
                spawn_opt(p, &mut opts)?;
            }
            if p.eat(&Tok::Open) {
                p.skip_seps();
                while !p.eat(&Tok::Close) {
                    if p.peek().is_none() {
                        return Err(CalError::at(line, "this spawn's '{' is never closed"));
                    }
                    spawn_opt(p, &mut opts)?;
                    while matches!(p.peek(), Some(Tok::Word(_))) {
                        spawn_opt(p, &mut opts)?;
                    }
                    p.end_clause()?;
                }
            }
            StepDef::Spawn { exe, on, keep, opts, line }
        }
        "call" => {
            let cell = cell(p)?;
            let op = p.word("an op name")?;
            p.keyword("on")?;
            let on = node(p)?;
            p.keyword("body")?;
            let body = sha(p, "the request body hash")?;
            StepDef::Call { cell, op, on, body, line }
        }
        "include" => StepDef::Include { program: prog_ref(p)?, line },
        other => return p.back_err(format!("unknown step '{other}' (steps: install, upgrade, spawn, call, include)")),
    })
}

fn spawn_opt(p: &mut P, o: &mut SpawnOpts) -> R<()> {
    let k = p.word("a spawn option")?;
    let dup = |p: &mut P, set: bool| if set { p.back_err(format!("'{k}' is given twice")) } else { Ok(()) };
    match k.as_str() {
        "args" => {
            dup(p, o.args.is_some())?;
            let mut a = vec![p.string("an argument")?];
            while matches!(p.peek(), Some(Tok::Str(_))) {
                a.push(p.string("an argument")?);
            }
            o.args = Some(a);
        }
        "env" => {
            let name = p.word("a variable name")?;
            let value = p.string("the variable's value")?;
            o.env.push((name, value));
        }
        "cwd" => {
            dup(p, o.cwd.is_some())?;
            o.cwd = Some(p.abs_path()?);
        }
        "cpu" => {
            dup(p, o.cpu.is_some())?;
            o.cpu = Some(p.int("a number of cores")?);
        }
        "memory" => {
            dup(p, o.memory_mb.is_some())?;
            o.memory_mb = Some(p.memory()?);
        }
        "time" => {
            dup(p, o.time_s.is_some())?;
            o.time_s = Some(p.duration()?);
        }
        "read" => o.read.extend(p.list(P::abs_path)?),
        "write" => o.write.extend(p.list(P::abs_path)?),
        "egress" => o.egress.extend(p.list(egress_rule)?),
        "out" => {
            dup(p, o.bytes_out.is_some())?;
            o.bytes_out = Some(p.bytes()?);
        }
        "in" => {
            dup(p, o.bytes_in.is_some())?;
            o.bytes_in = Some(p.bytes()?);
        }
        other => {
            return p.back_err(format!("unknown spawn option '{other}' (args, env, cwd, cpu, memory, time, read, write, egress, out, in)"));
        }
    }
    Ok(())
}

fn one<T>(s: &str, f: impl FnOnce(&mut P) -> R<T>) -> R<T> {
    let mut p = P { toks: lex(s)?.toks, i: 0 };
    let v = f(&mut p)?;
    if p.peek().is_some() {
        return p.err(format!("unexpected text after '{s}'"));
    }
    Ok(v)
}

/// Parse one principal as written on a command line (`agent:b`, `person:leif ed25519:<hex>`).
pub fn principal_text(s: &str) -> Result<PrincipalRef, CalError> {
    one(s, principal)
}

/// Parse one node as written on a command line (`node:pi-01`, `node:<64 hex>`).
pub fn node_text(s: &str) -> Result<NodeRef, CalError> {
    one(s, node)
}
