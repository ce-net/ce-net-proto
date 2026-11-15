//! `ce-cal`: the CAL command line (`docs/CAL.md` section 9). The Unix `cal` command prints a
//! calendar, so this one is `ce-cal`; its files end in `.cal`.
//!
//! ```text
//! ce-cal fmt <file.cal>                         the file in canonical layout
//! ce-cal compile <file.cal> [--key <file>]...   a draft (JSON), or the token once every link is signed
//! ce-cal sign <draft.json> --key <file>         sign the links whose issuer is that key
//! ce-cal explain <file.cal | token | draft>     what the chain allows and requires, in plain English
//! ce-cal decompile <token | draft>              the token as CAL
//! ce-cal check <token> --node <node> --as <principal> (--do <ability> | --program <id> [--step i] [--run n])
//!              [--request <hex>] [--proofs <hex>] [--body <file>] [--content <file>]
//! common: [--refs <book.json>] [--ce-ref] [--now <unix secs | date>] [-o <file>]
//! ```
//!
//! Exit status: 0 ok / allowed, 1 refused or invalid, 2 usage. `-` reads standard input.

use std::process::{Command, ExitCode};

use ce_net_proto::cal::refs::{FileInfo, Lookup, RefBook, Resolver};
use ce_net_proto::cal::{self, Draft, Labels, api};
use ce_net_proto::program::{Hash, NodeKey};
use ce_net_proto::v3::{Key, Link, TokenV3};
use serde_json::{Value, json};

const USAGE: &str = "usage:
  ce-cal fmt <file.cal>
  ce-cal compile <file.cal> [--key <keyfile>]... [-o <out>]
  ce-cal sign <draft.json> --key <keyfile> [-o <out>]
  ce-cal explain <file.cal | token | draft.json>
  ce-cal decompile <token | draft.json>
  ce-cal check <token> --node <node:name> --as <principal> (--do <ability> | --program <id> [--step <i>] [--run <n>])
               [--request <hex>] [--proofs <hex>] [--body <file>] [--content <file>]
options: --refs <ref-book.json>   offline ref book (default: ./cal.refs.json if present)
         --ce-ref                 also ask the ce.ref resolver (cell ref.index) for repository files
         --now <unix secs | YYYY-MM-DD[THH:MMZ]>
a key file holds ed25519:<64 hex seed> or p256:<64 hex scalar>";

struct Args {
    cmd: String,
    pos: Vec<String>,
    opts: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Args {
    fn get(&self, k: &str) -> Option<&str> {
        self.opts.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
    fn all(&self, k: &str) -> Vec<&str> {
        self.opts.iter().filter(|(n, _)| n == k).map(|(_, v)| v.as_str()).collect()
    }
    fn flag(&self, k: &str) -> bool {
        self.flags.iter().any(|f| f == k)
    }
}

fn parse_args(argv: Vec<String>) -> Result<Args, String> {
    let mut it = argv.into_iter();
    let cmd = it.next().ok_or("")?;
    let (mut pos, mut opts, mut flags) = (Vec::new(), Vec::new(), Vec::new());
    while let Some(a) = it.next() {
        match a.as_str() {
            "--ce-ref" | "--lenient" => flags.push(a),
            "-o" | "--refs" | "--now" | "--key" | "--node" | "--as" | "--do" | "--program" | "--step" | "--run" | "--request" | "--proofs" | "--body" | "--content"
            | "--tag" => {
                let v = it.next().ok_or(format!("{a} needs a value"))?;
                opts.push((a, v));
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            _ => pos.push(a),
        }
    }
    Ok(Args { cmd, pos, opts, flags })
}

fn read_input(arg: &str) -> Result<String, String> {
    if arg == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s).map_err(|e| e.to_string())?;
        return Ok(s);
    }
    if std::path::Path::new(arg).is_file() {
        return std::fs::read_to_string(arg).map_err(|e| format!("{arg}: {e}"));
    }
    if arg.len() > 8 && arg.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(arg.to_string());
    }
    Err(format!("{arg}: no such file"))
}

enum Input {
    Source(String),
    Token(TokenV3),
    Draft(Draft),
}

fn classify(text: &str) -> Result<Input, String> {
    let t = text.trim();
    if t.starts_with('{') {
        let v: Value = serde_json::from_str(t).map_err(|e| format!("not JSON: {e}"))?;
        if let Some(tok) = v.get("token").and_then(Value::as_str) {
            return TokenV3::from_hex(tok).map(Input::Token).map_err(|e| e.0);
        }
        return Draft::from_json(&v).map(Input::Draft);
    }
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return TokenV3::from_hex(t).map(Input::Token).map_err(|e| e.0);
    }
    Ok(Input::Source(text.to_string()))
}

/// The ref book, with the live ce.ref resolver over it for repository files when asked.
struct Refs {
    book: RefBook,
    live: bool,
}

fn ce_bin() -> String {
    std::env::var("CE_CAL_CE").unwrap_or_else(|_| "ce".into())
}

fn ce_call(op: &str, req: &Value) -> Result<Value, String> {
    let out = Command::new(ce_bin())
        .args(["cell", "call", "ref.index", op, &req.to_string(), "--json"])
        .output()
        .map_err(|e| format!("ce.ref unreachable ({}: {e})", ce_bin()))?;
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|_| format!("ce.ref gave no answer: {}", String::from_utf8_lossy(&out.stderr).trim()))?;
    if let Some(e) = v.get("Err") {
        return Err(format!("ce.ref: {}", e.as_object().and_then(|o| o.values().next()).and_then(Value::as_str).unwrap_or("error")));
    }
    Ok(v.get("Ok").cloned().unwrap_or(v))
}

impl Resolver for Refs {
    fn principal(&self, r: &str) -> Lookup<Key> {
        self.book.principal(r)
    }
    fn node(&self, name: &str) -> Lookup<NodeKey> {
        self.book.node(name)
    }
    fn repo(&self, name: &str) -> Lookup<String> {
        let known = self.book.repo(name)?;
        if !known.is_empty() || !self.live {
            return Ok(known);
        }
        let v = ce_call("Repositories", &json!(null))?;
        let mut out = Vec::new();
        for r in v.get("repos").and_then(Value::as_array).cloned().unwrap_or_default() {
            let origin = r.get("origin").and_then(Value::as_str).unwrap_or("");
            let last = origin.trim_end_matches('/').trim_end_matches(".git").rsplit(['/', ':']).next().unwrap_or("");
            if last.eq_ignore_ascii_case(name) {
                if r.get("ambiguous").and_then(Value::as_bool) == Some(true) {
                    return Err(format!("ce.ref holds several checkouts of {origin} and withholds them as ambiguous"));
                }
                out.push(origin.to_string());
            }
        }
        Ok(out)
    }
    fn file(&self, portable: &str) -> Lookup<FileInfo> {
        let known = self.book.file(portable)?;
        if !known.is_empty() || !self.live {
            return Ok(known);
        }
        let v = ce_call("Resolve", &json!({ "reference": portable }))?;
        match v.get("verdict").and_then(Value::as_str) {
            Some("PASS") => {
                let f = &v["file"];
                Ok(vec![FileInfo {
                    sha256: f["digest"].as_str().unwrap_or("").to_string(),
                    size: f["size"].as_u64().unwrap_or(0),
                    commit: f["commit_id"].as_str().unwrap_or("").to_string(),
                }])
            }
            Some("FAIL") => Ok(vec![]),
            _ => Err(v.get("reason").and_then(Value::as_str).unwrap_or("CANNOT DETERMINE").to_string()),
        }
    }
    fn blob(&self, sha: &Hash) -> Lookup<u64> {
        self.book.blob(sha)
    }
    fn cell_keys(&self, api: &str) -> Vec<Key> {
        self.book.cell_keys(api)
    }
    fn roots(&self) -> Vec<Key> {
        self.book.roots()
    }
    fn name_of_key(&self, k: &Key) -> Option<String> {
        self.book.name_of_key(k)
    }
    fn name_of_node(&self, n: &NodeKey) -> Option<String> {
        self.book.name_of_node(n)
    }
    fn name_of_file(&self, sha: &Hash) -> Option<String> {
        self.book.name_of_file(sha)
    }
}

fn refs(a: &Args) -> Result<Refs, String> {
    let path = a.get("--refs").map(String::from).or_else(|| std::path::Path::new("cal.refs.json").is_file().then(|| "cal.refs.json".to_string()));
    let book = match path {
        Some(p) => RefBook::from_json(&std::fs::read_to_string(&p).map_err(|e| format!("{p}: {e}"))?)?,
        None => RefBook::default(),
    };
    Ok(Refs { book, live: a.flag("--ce-ref") })
}

fn now(a: &Args) -> Result<u64, String> {
    match a.get("--now") {
        None => Ok(api::unix_now()),
        Some(s) => s.parse().ok().or_else(|| cal::units::time(s)).ok_or(format!("--now {s}: not a time")),
    }
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut b);
    }
    u64::from_le_bytes(b)
}

fn compile_source(src: &str, r: &Refs, a: &Args) -> Result<cal::Compiled, String> {
    let f = cal::parse(src).map_err(|e| e.to_string())?;
    let mut nonce = random_u64;
    let mut o = cal::Options { now: now(a)?, nonce: &mut nonce, lenient: a.flag("--lenient") };
    cal::compile(&f, r, &mut o).map_err(|e| e.to_string())
}

fn emit(a: &Args, s: &str) -> Result<(), String> {
    match a.get("-o") {
        Some(p) => std::fs::write(p, s).map_err(|e| format!("{p}: {e}")),
        None => {
            print!("{s}");
            Ok(())
        }
    }
}

fn sign_and_emit(mut d: Draft, a: &Args) -> Result<(), String> {
    for k in a.all("--key") {
        let text = std::fs::read_to_string(k).map_err(|e| format!("{k}: {e}"))?;
        let s = cal::signer_from_text(&text).map_err(|e| format!("{k}: {e}"))?;
        if d.sign(&s) == 0 {
            eprintln!("ce-cal: {k}: no unsigned link is issued by {}", cal::refs::fmt_key(&s.key()));
        }
    }
    match d.token() {
        Ok(t) => emit(a, &format!("{}\n", t.to_hex())),
        Err(_) => {
            let missing: Vec<String> = d.unsigned().iter().map(cal::refs::fmt_key).collect();
            eprintln!("ce-cal: draft written; still to sign: {}", missing.join(", "));
            emit(a, &format!("{}\n", serde_json::to_string_pretty(&d.to_json()).unwrap_or_default()))
        }
    }
}

fn links_of(t: &TokenV3) -> Result<Vec<ce_net_proto::v3::CapabilityV3>, String> {
    t.links.iter().enumerate().map(|(i, l)| match l {
        Link::V3 { cap, .. } => Ok(cap.clone()),
        Link::V1(_) => Err(format!("link {i} is a v1 link: use ce-cap-verify for v1 chains")),
    }).collect()
}

fn run(a: &Args) -> Result<bool, String> {
    let need = |i: usize| a.pos.get(i).map(String::as_str).ok_or_else(|| format!("{}: missing input\n{USAGE}", a.cmd));
    let r = refs(a)?;
    match a.cmd.as_str() {
        "fmt" | "parse" => {
            let f = cal::parse(&read_input(need(0)?)?).map_err(|e| e.to_string())?;
            emit(a, &cal::print::print(&f))?;
        }
        "compile" => {
            let c = compile_source(&read_input(need(0)?)?, &r, a)?;
            sign_and_emit(c.draft(), a)?;
        }
        "sign" => match classify(&read_input(need(0)?)?)? {
            Input::Draft(d) => sign_and_emit(d, a)?,
            _ => return Err("sign takes a draft (the JSON ce-cal compile writes)".into()),
        },
        "explain" => {
            let (links, programs, mut labels) = match classify(&read_input(need(0)?)?)? {
                Input::Source(s) => {
                    let c = compile_source(&s, &r, a)?;
                    (c.links, c.programs, c.labels)
                }
                Input::Token(t) => (links_of(&t)?, t.programs, Labels::default()),
                Input::Draft(d) => (d.links.into_iter().map(|x| x.0).collect(), d.programs, Labels::default()),
            };
            labels.learn(&links, &programs, &r);
            emit(a, &cal::explain(&links, &programs, &labels))?;
        }
        "decompile" => {
            let t = match classify(&read_input(need(0)?)?)? {
                Input::Token(t) => t,
                Input::Draft(d) => TokenV3 { links: d.links.into_iter().map(|(cap, _)| Link::V3 { cap, sig: ce_net_proto::v3::Sig::Ed25519([0; 64]) }).collect(), programs: d.programs },
                Input::Source(_) => return Err("decompile takes a token or a draft".into()),
            };
            let mut labels = Labels::default();
            labels.learn(&links_of(&t)?, &t.programs, &r);
            emit(a, &cal::decompile(&t, &labels)?)?;
        }
        "check" | "verify" => {
            let t = match classify(&read_input(need(0)?)?)? {
                Input::Token(t) => t,
                _ => return Err("check takes a signed token (hex)".into()),
            };
            let mut req = json!({});
            for (opt, k) in [("--node", "node"), ("--as", "as"), ("--do", "do"), ("--program", "program"), ("--step", "step"), ("--run", "run")] {
                if let Some(v) = a.get(opt) {
                    req[k] = json!(v);
                }
            }
            req["now"] = json!(now(a)?.to_string());
            for (opt, k) in [("--request", "request"), ("--proofs", "proofs")] {
                if let Some(v) = a.get(opt) {
                    req[k] = json!(read_input(v)?.trim());
                }
            }
            for (opt, k) in [("--body", "body"), ("--content", "content")] {
                if let Some(p) = a.get(opt) {
                    req[k] = json!(hex::encode(std::fs::read(p).map_err(|e| format!("{p}: {e}"))?));
                }
            }
            req["tags"] = json!(a.all("--tag"));
            let mut labels = Labels::default();
            labels.learn(&links_of(&t)?, &t.programs, &r);
            let v = api::verify_req(&req, &t, &r, &labels).map_err(|e| {
                let m = e["error"]["message"].as_str().unwrap_or("error").to_string();
                match e["error"]["suggestion"].as_str() {
                    Some(h) => format!("{m}\n  suggestion: {h}"),
                    None => m,
                }
            })?;
            emit(a, &v.text())?;
            return Ok(v.allowed);
        }
        "help" | "--help" | "-h" => println!("{USAGE}"),
        other => return Err(format!("unknown command '{other}'\n{USAGE}")),
    }
    Ok(true)
}

fn main() -> ExitCode {
    let a = match parse_args(std::env::args().skip(1).collect()) {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("ce-cal: {e}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&a) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) if e.contains("usage:") => {
            eprintln!("ce-cal: {e}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("ce-cal: {e}");
            ExitCode::from(1)
        }
    }
}
