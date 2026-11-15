//! References (`docs/CAL.md` section 3). Everything a CAL file names is a ce-ref, and every ce-ref
//! is compiled to a pinned form that means the same thing wherever it is read:
//!
//! | Written | Pinned (what the link stores) |
//! |---|---|
//! | `repo:<repo>/<path>@<commit> sha256:<hash>` | the content hash and size; the file's portable identity is `ce-ref://repo/<sha256 of the normalized git origin>/<path>` |
//! | `ce-blob:sha256:<hash>` | the content hash (and its size) |
//! | `node:<name>` or `node:<64 hex>` | the full node id |
//! | `person:<id>`, `agent:<lane>` | the public key (`ed25519:<hex>`, `p256:<hex>`) |
//! | `cell:<api>@<major>` | the string `<api>@<major>` |
//! | `wechat:thread/<id>`, `doc:<repo>/<path>` | the source and the thread (a doc as its portable ref) |
//!
//! A [`Resolver`] answers the lookups. [`RefBook`] is the offline one (a JSON file); the `ce-cal`
//! CLI layers the live ce.ref resolver over it for repository files. A lookup answers a list:
//! empty is "not known", one is the pin, more than one is ambiguous and is refused.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::program::{Hash, NodeKey};
use crate::v3::Key;

/// What a resolver knows about one repository file (one observed variant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    /// Lowercase hex SHA-256 of the content.
    pub sha256: String,
    pub size: u64,
    /// The git commit it was observed at (may be empty).
    #[serde(default)]
    pub commit: String,
}

/// A lookup: `Ok(vec![])` not known, `Ok(one)` pinned, `Ok(many)` ambiguous, `Err` the resolver
/// could not determine (the reason is shown).
pub type Lookup<T> = Result<Vec<T>, String>;

/// Lookups CAL needs to compile, and the reverse lookups `explain` and `decompile` use to show a
/// readable name beside a pinned value.
pub trait Resolver {
    /// Keys of a principal ref such as `person:leif` or `agent:printer-guard`.
    fn principal(&self, r: &str) -> Lookup<Key>;
    /// Full ids of the node named `name` (the part after `node:`).
    fn node(&self, name: &str) -> Lookup<NodeKey>;
    /// Git origins of the repository named `name`.
    fn repo(&self, name: &str) -> Lookup<String>;
    /// The observed variants of a portable file ref `ce-ref://repo/<id>/<path>`.
    fn file(&self, portable: &str) -> Lookup<FileInfo>;
    /// The size of a blob by content hash.
    fn blob(&self, sha: &Hash) -> Lookup<u64>;
    /// Keys a node trusts for a cell party (`<api>@<major>`); used by `check`.
    fn cell_keys(&self, _api: &str) -> Vec<Key> {
        Vec::new()
    }
    /// The roots `check` accepts (owner keys).
    fn roots(&self) -> Vec<Key> {
        Vec::new()
    }
    /// A readable name for a key, if one is known (`person:leif`).
    fn name_of_key(&self, _k: &Key) -> Option<String> {
        None
    }
    /// The name of a node (`pi-01`), if one is known.
    fn name_of_node(&self, _n: &NodeKey) -> Option<String> {
        None
    }
    /// A readable file ref for a content hash (`repo:huey-scripts/run.py@3f2a1c`), if known.
    fn name_of_file(&self, _sha: &Hash) -> Option<String> {
        None
    }
}

/// A resolver that knows nothing: only pinned refs compile.
pub struct NoRefs;

impl Resolver for NoRefs {
    fn principal(&self, _: &str) -> Lookup<Key> {
        Ok(vec![])
    }
    fn node(&self, _: &str) -> Lookup<NodeKey> {
        Ok(vec![])
    }
    fn repo(&self, _: &str) -> Lookup<String> {
        Ok(vec![])
    }
    fn file(&self, _: &str) -> Lookup<FileInfo> {
        Ok(vec![])
    }
    fn blob(&self, _: &Hash) -> Lookup<u64> {
        Ok(vec![])
    }
}

/// The offline ref book: a JSON file of what each ref resolves to (`docs/CAL.md` section 3.3).
/// Every value is a list, so the book can record that a name is ambiguous.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefBook {
    /// `"person:leif"` -> `["p256:<66 hex>"]`.
    #[serde(default)]
    pub principals: BTreeMap<String, Vec<String>>,
    /// `"pi-01"` -> `["<64 hex node id>"]`.
    #[serde(default)]
    pub nodes: BTreeMap<String, Vec<String>>,
    /// `"huey-scripts"` -> `["https://github.com/<owner>/huey-scripts"]`.
    #[serde(default)]
    pub repos: BTreeMap<String, Vec<String>>,
    /// `"ce-ref://repo/<id>/<path>"` -> observed variants.
    #[serde(default)]
    pub files: BTreeMap<String, Vec<FileInfo>>,
    /// `"<sha256 hex>"` -> size in bytes.
    #[serde(default)]
    pub blobs: BTreeMap<String, u64>,
    /// `"printer3d.gate@1"` -> keys an executing node trusts for that cell (`check` only).
    #[serde(default)]
    pub cells: BTreeMap<String, Vec<String>>,
    /// Principal refs or keys accepted as roots by `check`.
    #[serde(default)]
    pub roots: Vec<String>,
}

impl RefBook {
    pub fn from_json(s: &str) -> Result<RefBook, String> {
        serde_json::from_str(s).map_err(|e| format!("ref book: {e}"))
    }

    fn keys(&self, list: &[String]) -> Lookup<Key> {
        list.iter().map(|k| parse_key(k).ok_or_else(|| format!("ref book: '{k}' is not a key"))).collect()
    }
}

impl Resolver for RefBook {
    fn principal(&self, r: &str) -> Lookup<Key> {
        self.principals.get(r).map_or(Ok(vec![]), |l| self.keys(l))
    }
    fn node(&self, name: &str) -> Lookup<NodeKey> {
        let Some(l) = self.nodes.get(name) else { return Ok(vec![]) };
        l.iter().map(|h| hex32(h).ok_or_else(|| format!("ref book: node id '{h}' is not 64 hex"))).collect()
    }
    fn repo(&self, name: &str) -> Lookup<String> {
        Ok(self.repos.get(name).cloned().unwrap_or_default())
    }
    fn file(&self, portable: &str) -> Lookup<FileInfo> {
        Ok(self.files.get(portable).cloned().unwrap_or_default())
    }
    fn blob(&self, sha: &Hash) -> Lookup<u64> {
        Ok(self.blobs.get(&hex::encode(sha)).map(|s| vec![*s]).unwrap_or_default())
    }
    fn cell_keys(&self, api: &str) -> Vec<Key> {
        self.cells.get(api).map(|l| self.keys(l).unwrap_or_default()).unwrap_or_default()
    }
    fn roots(&self) -> Vec<Key> {
        let mut out = Vec::new();
        for r in &self.roots {
            match parse_key(r) {
                Some(k) => out.push(k),
                None => out.extend(self.principal(r).unwrap_or_default()),
            }
        }
        out
    }
    fn name_of_key(&self, k: &Key) -> Option<String> {
        let want = fmt_key(k);
        let named = self.principals.iter().find(|(_, l)| l.len() == 1 && l[0] == want).map(|(n, _)| n.clone());
        named.or_else(|| self.nodes.iter().find(|(_, l)| l.len() == 1 && matches!(k, Key::Ed25519(b) if hex::encode(b) == l[0])).map(|(n, _)| format!("node:{n}")))
    }
    fn name_of_node(&self, n: &NodeKey) -> Option<String> {
        let want = hex::encode(n);
        self.nodes.iter().find(|(_, l)| l.len() == 1 && l[0] == want).map(|(name, _)| name.clone())
    }
    fn name_of_file(&self, sha: &Hash) -> Option<String> {
        let want = hex::encode(sha);
        for (portable, variants) in &self.files {
            if let Some(v) = variants.iter().find(|v| v.sha256 == want) {
                let (id, path) = parse_portable(portable).ok()?;
                let repo = self.repos.iter().find(|(_, origins)| origins.iter().any(|o| origin_id(o).is_ok_and(|(i, _)| i == id)));
                return Some(match repo {
                    Some((name, _)) if !v.commit.is_empty() => format!("repo:{name}/{path}@{}", short(&v.commit)),
                    Some((name, _)) => format!("repo:{name}/{path}"),
                    None => portable.clone(),
                });
            }
        }
        None
    }
}

/// Lowercase hex of a key with its type: `ed25519:<64 hex>` or `p256:<66 hex>`.
pub fn fmt_key(k: &Key) -> String {
    match k {
        Key::Ed25519(b) => format!("ed25519:{}", hex::encode(b)),
        Key::P256(b) => format!("p256:{}", hex::encode(b)),
    }
}

/// `ed25519:<64 hex>` or `p256:<66 hex>`.
pub fn parse_key(s: &str) -> Option<Key> {
    if let Some(h) = s.strip_prefix("ed25519:") {
        return hex32(h).map(Key::Ed25519);
    }
    let h = s.strip_prefix("p256:")?;
    if h.len() != 66 || !is_lower_hex(h) {
        return None;
    }
    let mut out = [0u8; 33];
    hex::decode_to_slice(h, &mut out).ok()?;
    let k = Key::P256(out);
    k.canonical().then_some(k)
}

pub fn is_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 64 lowercase hex digits as 32 bytes.
pub fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !is_lower_hex(s) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// The first 8 hex digits and the last 4, for prose: `3f9b0d4d…eb51`.
pub fn abbrev(h: &str) -> String {
    if h.len() <= 16 { h.to_string() } else { format!("{}…{}", &h[..8], &h[h.len() - 4..]) }
}

/// A commit as people write it: the first 7 digits.
pub fn short(commit: &str) -> &str {
    &commit[..commit.len().min(7)]
}

// ---- portable repository references (ce-ref `portable.py`, same rules and the same ids)

/// `(sha256 hex of the normalized origin, normalized origin)` of a git origin URL. GitHub HTTPS
/// and SSH origins of one repository normalize to the same identity; credentials are refused.
pub fn origin_id(origin: &str) -> Result<(String, String), String> {
    let (host, path) = if let Some(rest) = origin.strip_prefix("git@") {
        let (host, path) = rest.split_once(':').ok_or("unsupported Git origin")?;
        if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') || path.is_empty() || path.contains(char::is_whitespace) {
            return Err("unsupported Git origin".into());
        }
        (host.to_string(), path.to_string())
    } else {
        let (scheme, rest) = origin.split_once("://").ok_or("origin must be an uncredentialed HTTPS/SSH Git URL")?;
        if scheme != "https" && scheme != "ssh" {
            return Err("origin must be an uncredentialed HTTPS/SSH Git URL".into());
        }
        if rest.contains('?') || rest.contains('#') {
            return Err("origin must be an uncredentialed HTTPS/SSH Git URL".into());
        }
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (user, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        if let Some(u) = user {
            if u.contains(':') {
                return Err("origin must be an uncredentialed HTTPS/SSH Git URL".into());
            }
            if !(scheme == "ssh" && u == "git") {
                return Err("credential-bearing origin refused".into());
            }
        }
        let host = hostport.split(':').next().unwrap_or("");
        if host.is_empty() {
            return Err("origin must be an uncredentialed HTTPS/SSH Git URL".into());
        }
        (host.to_ascii_lowercase(), path.trim_start_matches('/').to_string())
    };
    let path = path.strip_suffix(".git").unwrap_or(&path).trim_matches('/').to_string();
    if path.is_empty() || path.split('/').any(|c| c == "..") || path.contains(['?', '%', '#', '\\']) {
        return Err("invalid origin path".into());
    }
    let host = host.to_ascii_lowercase();
    let mut canonical = format!("{host}/{path}");
    if host == "github.com" {
        canonical = canonical.to_ascii_lowercase();
    }
    Ok((hex::encode(Sha256::digest(canonical.as_bytes())), canonical))
}

/// A safe relative path: not absolute, no `.` or `..` component, no backslash or NUL.
pub fn safe_path(p: &str) -> Result<String, String> {
    if p.is_empty() || p.starts_with('/') || p.split('/').any(|c| c == "." || c == "..") || p.contains(['\\', '\0']) {
        return Err(format!("unsafe relative path '{p}'"));
    }
    // PurePosixPath collapses repeated and trailing slashes.
    Ok(p.split('/').filter(|c| !c.is_empty()).collect::<Vec<_>>().join("/"))
}

/// Python's `urllib.parse.quote(s, safe='/')`.
fn quote(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn unquote(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let h = std::str::from_utf8(&b[i + 1..i + 3]).map_err(|_| "bad escape")?;
            out.push(u8::from_str_radix(h, 16).map_err(|_| "bad escape")?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "path is not UTF-8".into())
}

/// `ce-ref://repo/<id>/<URL-encoded relative path>`.
pub fn portable(repo_id: &str, path: &str) -> Result<String, String> {
    if repo_id.len() != 64 || !is_lower_hex(repo_id) {
        return Err("invalid repository identity".into());
    }
    Ok(format!("ce-ref://repo/{repo_id}/{}", quote(&safe_path(path)?)))
}

/// `(repo id, relative path)` of a portable ref.
pub fn parse_portable(r: &str) -> Result<(String, String), String> {
    let rest = r.strip_prefix("ce-ref://repo/").ok_or("not a portable reference (ce-ref://repo/<id>/<path>)")?;
    if rest.contains(['?', '#']) {
        return Err("invalid portable reference".into());
    }
    let (id, path) = rest.split_once('/').ok_or("invalid portable reference")?;
    if id.len() != 64 || !is_lower_hex(id) {
        return Err("invalid repository identity".into());
    }
    Ok((id.to_string(), safe_path(&unquote(path)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_normalize_like_portable_py() {
        let a = origin_id("https://github.com/Example/Huey-Scripts.git").unwrap();
        let b = origin_id("git@github.com:example/huey-scripts").unwrap();
        let c = origin_id("ssh://git@github.com/example/huey-scripts.git").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a.1, "github.com/example/huey-scripts");
        // the id ce-ref's portable.py computes for the same origin
        assert_eq!(a.0, "b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331");
        assert!(origin_id("https://user:pw@github.com/x/y").is_err());
        assert!(origin_id("https://token@github.com/x/y").is_err());
        assert!(origin_id("http://github.com/x/y").is_err());
        assert!(origin_id("https://github.com/x/../y").is_err());
    }

    #[test]
    fn portable_round_trip() {
        let id = "a".repeat(64);
        let r = portable(&id, "docs/My File.md").unwrap();
        assert_eq!(r, format!("ce-ref://repo/{id}/docs/My%20File.md"));
        assert_eq!(parse_portable(&r).unwrap(), (id.clone(), "docs/My File.md".to_string()));
        assert!(portable(&id, "../x").is_err());
        assert!(portable(&id, "/etc/passwd").is_err());
    }

    #[test]
    fn keys() {
        let k = Key::Ed25519([7; 32]);
        assert_eq!(parse_key(&fmt_key(&k)), Some(k));
        assert_eq!(parse_key("p256:04aa"), None);
        assert_eq!(parse_key(&format!("ed25519:{}", "A".repeat(64))), None);
    }
}
