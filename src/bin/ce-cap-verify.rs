//! `ce-cap-verify <chain-hex|-> --root <pubkey-hex> [--now <unix-secs>] [--revoked <issuer-hex>:<nonce>]...
//!               [--action <ability>] [--holder <pubkey-hex>]`
//!
//! Offline verification of a ce-net capability chain token against one root public key. No network.
//! Exit status: 0 = valid, 1 = invalid, 2 = usage error. `-` reads the token from stdin.

use std::io::Read;
use std::process::ExitCode;

use ce_net_proto::identity::node_id_from_hex;
use ce_net_proto::{NodeId, Resource, ability_covers, decode_chain, verify_chain};

const USAGE: &str = "usage: ce-cap-verify <chain-hex|-> --root <pubkey-hex> [--now <unix-secs>] \
[--revoked <issuer-hex>:<nonce>]... [--action <ability>] [--holder <pubkey-hex>]";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("ce-cap-verify: {e}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<bool, String> {
    let mut token: Option<String> = None;
    let mut root: Option<NodeId> = None;
    let mut now: Option<u64> = None;
    let mut revoked: Vec<(NodeId, u64)> = Vec::new();
    let mut action: Option<String> = None;
    let mut holder: Option<NodeId> = None;

    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(true);
            }
            "--root" => root = Some(node_id_from_hex(&val("--root")?).map_err(|e| e.0)?),
            "--now" => now = Some(val("--now")?.parse().map_err(|_| "--now must be unix seconds")?),
            "--action" => action = Some(val("--action")?),
            "--holder" => holder = Some(node_id_from_hex(&val("--holder")?).map_err(|e| e.0)?),
            "--revoked" => {
                let v = val("--revoked")?;
                let (i, n) = v.split_once(':').ok_or("--revoked takes <issuer-hex>:<nonce>")?;
                let n: u64 = n.parse().map_err(|_| "--revoked nonce must be a u64")?;
                revoked.push((node_id_from_hex(i).map_err(|e| e.0)?, n));
            }
            s if s.starts_with("--") => return Err(format!("unknown flag {s}")),
            _ if token.is_none() => token = Some(a),
            _ => return Err("more than one token given".into()),
        }
    }
    let mut token = token.ok_or("missing <chain-hex>")?;
    if token == "-" {
        token.clear();
        std::io::stdin().read_to_string(&mut token).map_err(|e| e.to_string())?;
    }
    let root = root.ok_or("missing --root <pubkey-hex>")?;
    let now = now.unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    });

    let chain = match decode_chain(&token) {
        Ok(c) => c,
        Err(e) => {
            println!("INVALID: {e}");
            return Ok(false);
        }
    };
    let is_revoked = |i: &NodeId, n: u64| revoked.iter().any(|(ri, rn)| ri == i && *rn == n);
    let v = match verify_chain(&chain, &root, now, &is_revoked) {
        Ok(v) => v,
        Err(e) => {
            println!("INVALID: {e}");
            return Ok(false);
        }
    };
    if let Some(h) = holder {
        if h != v.holder {
            println!("INVALID: leaf capability is not held by {}", hex::encode(h));
            return Ok(false);
        }
    }
    if let Some(a) = &action {
        if !v.abilities.iter().any(|g| ability_covers(g, a)) {
            println!("INVALID: capability does not grant '{a}'");
            return Ok(false);
        }
    }
    println!("VALID");
    println!("links:     {}", v.links);
    println!("root:      {}", hex::encode(root));
    println!("holder:    {}", hex::encode(v.holder));
    println!("abilities: {}", v.abilities.join(","));
    println!("resource:  {}", fmt_resource(&v.resource));
    let na = v.caveats.not_after;
    println!("not_after: {}", if na == 0 { "never".to_string() } else { na.to_string() });
    println!("leaf_id:   {}", hex::encode(v.ids[v.ids.len() - 1]));
    Ok(true)
}

fn fmt_resource(r: &Resource) -> String {
    match r {
        Resource::Any => "any".into(),
        Resource::Node(n) => format!("node:{}", hex::encode(n)),
        Resource::Tag(t) => format!("tag:{t}"),
        Resource::AllOf(ts) => format!("all-of:{}", ts.join(",")),
    }
}
