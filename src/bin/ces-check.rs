//! `ces-check manifest <cell.toml> [--json]`: CES-1 static checks C1.1 and C1.2 on one manifest.
//! Exit 0 valid, 1 violations, 2 no `[budget]` table (defaults apply; a warning in v0.1), 3 usage or read error.
use ce_net_proto::ces1::check_manifest;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let json = a.iter().any(|x| x == "--json");
    let (Some("manifest"), Some(path)) = (a.first().map(String::as_str), a.get(1)) else {
        eprintln!("usage: ces-check manifest <cell.toml> [--json]");
        std::process::exit(3);
    };
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("ces-check: {path}: {e}");
        std::process::exit(3)
    });
    let (code, out) = match check_manifest(&text) {
        Ok(Some(b)) => (0, serde_json::json!({ "file": path, "verdict": "valid", "budget": b })),
        Ok(None) => (2, serde_json::json!({ "file": path, "verdict": "absent", "note": "no [budget] table: CES-1 defaults apply" })),
        Err(vs) => (1, serde_json::json!({ "file": path, "verdict": "invalid", "violations": vs })),
    };
    if json {
        println!("{out}");
    } else if let Some(vs) = out["violations"].as_array() {
        for v in vs {
            println!("{path}:{}: {} {}", v["line"], v["check"].as_str().unwrap_or(""), v["msg"].as_str().unwrap_or(""));
        }
    } else {
        println!("{path}: {}", out["verdict"].as_str().unwrap_or(""));
    }
    std::process::exit(code);
}
