//! Counted use (`docs/CAPABILITY-PROGRAMS.md` section 7): the node-local burn log behind the
//! `burn` callback of [`authorize_v3`](super::verify::authorize_v3), and the canonical-form rule
//! that a counted link expires and names a finite set of nodes ([`check_counted`]).
//!
//! [`BurnLog::charge`] takes `&mut self` (the burn lock within a process; the file itself is held
//! under an exclusive OS lock, so a second process cannot open it), reads the counter of every
//! counted link of the chain, refuses if any is at its `max`, appends every record in one write,
//! `fsync`s, and only then reports success. A crash between the burn and the act loses the use;
//! it never grants a second one. Any write failure poisons the log: every later counted use is
//! refused until it is reopened.
//!
//! File: the 8-byte header `CEBURN1\n`, then frames `len: u32 LE || bincode(Entry) ||
//! SHA-256(body)[..4]`. A short tail (a write torn by a crash, never `fsync`ed, so never acted on)
//! or an all-zero tail is cut off on open; any other damage refuses the open.
//!
//! Cumulative limits share [`counter_key`] (scope = the limit name) but are totals kept by the
//! egress enforcer, not uses: [`BurnLog::charge`] checks their link's expiry and nothing more.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::verify::Charge;
use super::{Caveat, CapabilityV3, UsePer};
use crate::program::{CUMULATIVE_LIMITS, Hash, NodeKey};

/// Domain tag of [`counter_key`] (13 ASCII bytes, length-prefixed).
pub const USE_DOMAIN: &[u8] = b"ce-cap-use-v1";
/// A clock this many seconds below the highest `at` the log has seen refuses every counted use.
pub const CLOCK_SLACK: u64 = 300;
/// A record may be pruned once `now > not_after + PRUNE_AFTER`.
pub const PRUNE_AFTER: u64 = 86_400;
const HEADER: &[u8; 8] = b"CEBURN1\n";
const MAX_FRAME: usize = 1 << 16;

/// `SHA-256(len(13) || "ce-cap-use-v1" || cap_id(L) || self_id || string(scope))`; `scope` is ""
/// for `per: Link`, the charged action for `per: Action`, the limit name for a cumulative limit.
pub fn counter_key(link: &Hash, self_id: &NodeKey, scope: &str) -> Hash {
    let b = bincode::serialize(&(USE_DOMAIN, link, self_id, scope)).unwrap_or_default();
    Sha256::digest(b).into()
}

/// Section 7: a counted link (it carries `Uses` or a cumulative limit) sets `caveats.not_after`
/// and names a finite set of nodes (`Node` or `Nodes`); with `per: Action` its reachable
/// abilities hold no wildcard. Run by the canonical-form check of every link.
pub fn check_counted(c: &CapabilityV3) -> Result<(), String> {
    let uses = c.ext.iter().find_map(|cv| match cv {
        Caveat::Uses { per, .. } => Some(*per),
        _ => None,
    });
    let cumulative = c.ext.iter().any(|cv| match cv {
        Caveat::Limits(ls) => ls.iter().any(|l| CUMULATIVE_LIMITS.contains(&l.name.as_str())),
        _ => false,
    });
    if uses.is_none() && !cumulative {
        return Ok(());
    }
    if c.caveats.not_after == 0 {
        return Err("a counted link must set caveats.not_after".into());
    }
    if !c.resource.is_finite() {
        return Err("a counted link must name a finite resource (Node or Nodes)".into());
    }
    if uses == Some(UsePer::Action) {
        let mut reach = c.abilities.iter().chain(c.delegate.iter().flat_map(|d| d.abilities.iter()));
        if reach.any(|a| a.contains('*')) {
            return Err("Uses per Action needs abilities without wildcards".into());
        }
    }
    Ok(())
}

/// One burn, as section 7 defines it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnRecord {
    pub counter_key: Hash,
    pub count_after: u32,
    pub link: Hash,
    pub leaf: Hash,
    pub action: String,
    pub at: u64,
    pub not_after: u64,
}

/// What the log holds: burns, the `(program, run)` a `per: Link` counter was charged for (charged
/// once per run, section 6.4 rule 5), and the clock high-water mark kept across a prune.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Entry {
    Burn(BurnRecord),
    Run { counter_key: Hash, program: Hash, run: u32, at: u64, not_after: u64 },
    Clock { at: u64 },
}

impl Entry {
    fn at(&self) -> u64 {
        match self {
            Entry::Burn(r) => r.at,
            Entry::Run { at, .. } | Entry::Clock { at } => *at,
        }
    }

    fn not_after(&self) -> Option<u64> {
        match self {
            Entry::Burn(r) => Some(r.not_after),
            Entry::Run { not_after, .. } => Some(*not_after),
            Entry::Clock { .. } => None,
        }
    }
}

fn frame(e: &Entry) -> Vec<u8> {
    let body = bincode::serialize(e).unwrap_or_default();
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend(&body);
    out.extend(&Sha256::digest(&body)[..4]);
    out
}

/// Parse the frames after the header; returns the entries and the length of the valid prefix.
fn parse(b: &[u8]) -> Result<(Vec<Entry>, usize), String> {
    let mut out = Vec::new();
    let mut at = HEADER.len();
    while at < b.len() {
        let rest = &b[at..];
        if rest.iter().all(|&x| x == 0) {
            break;
        }
        if rest.len() < 4 {
            break;
        }
        let n = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if n > MAX_FRAME {
            return Err("burn log is damaged (frame too large)".into());
        }
        if rest.len() < 4 + n + 4 {
            break;
        }
        let body = &rest[4..4 + n];
        if Sha256::digest(body)[..4] != rest[4 + n..8 + n] {
            return Err("burn log is damaged (checksum)".into());
        }
        out.push(bincode::deserialize(body).map_err(|_| "burn log is damaged (record)".to_string())?);
        at += 8 + n;
    }
    Ok((out, at))
}

fn create_private(path: &Path, truncate: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true).truncate(truncate);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)
}

fn sync_dir(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => File::open(d)?.sync_all(),
        _ => File::open(".")?.sync_all(),
    }
}

fn io(what: &str) -> impl Fn(std::io::Error) -> String + '_ {
    move |e| format!("burn log {what}: {e}")
}

/// The node-local, append-only burn log.
#[derive(Debug)]
pub struct BurnLog {
    path: PathBuf,
    file: File,
    entries: Vec<Entry>,
    counts: HashMap<Hash, u32>,
    runs: HashSet<(Hash, Hash, u32)>,
    high: u64,
    poisoned: bool,
}

impl BurnLog {
    /// Open (or create, mode 0600) the log at `path` and hold it under an exclusive lock. Refuses
    /// a file group or others can read or write, a file another process holds, and a damaged one.
    pub fn open(path: &Path) -> Result<BurnLog, String> {
        let mut file = create_private(path, false).map_err(io("open"))?;
        file.try_lock().map_err(|_| "burn log is held by another process".to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file.metadata().map_err(io("stat"))?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(format!("burn log must be readable and writable only by its owner (mode {:o})", mode & 0o777));
            }
        }
        let mut b = Vec::new();
        file.read_to_end(&mut b).map_err(io("read"))?;
        if b.is_empty() {
            file.write_all(HEADER).and_then(|_| file.sync_all()).map_err(io("write"))?;
            sync_dir(path).map_err(io("sync"))?;
            b = HEADER.to_vec();
        } else if !b.starts_with(HEADER) {
            return Err("not a burn log".into());
        }
        let (entries, valid) = parse(&b)?;
        if valid < b.len() {
            file.set_len(valid as u64).and_then(|_| file.sync_all()).map_err(io("truncate"))?;
        }
        file.seek(SeekFrom::End(0)).map_err(io("seek"))?;
        let mut log = BurnLog { path: path.to_path_buf(), file, entries: Vec::new(), counts: HashMap::new(), runs: HashSet::new(), high: 0, poisoned: false };
        for e in entries {
            log.apply(e);
        }
        Ok(log)
    }

    fn apply(&mut self, e: Entry) {
        self.high = self.high.max(e.at());
        match &e {
            Entry::Burn(r) => {
                let c = self.counts.entry(r.counter_key).or_insert(0);
                *c = (*c).max(r.count_after);
            }
            Entry::Run { counter_key, program, run, .. } => {
                self.runs.insert((*counter_key, *program, *run));
            }
            Entry::Clock { .. } => {}
        }
        self.entries.push(e);
    }

    /// The count recorded for `key` (0 if none).
    pub fn count(&self, key: &Hash) -> u32 {
        self.counts.get(key).copied().unwrap_or(0)
    }

    /// The highest `at` this log has seen.
    pub fn high_water(&self) -> u64 {
        self.high
    }

    /// Charge every counted link of `c` at node `self_id`, all or none (section 7). On `Ok` the
    /// records are on disk and the caller may act.
    pub fn charge(&mut self, self_id: &NodeKey, now: u64, c: &Charge) -> Result<(), String> {
        if self.poisoned {
            return Err("burn log failed; counted use refused until it is reopened".into());
        }
        if now.saturating_add(CLOCK_SLACK) < self.high {
            return Err("clock went backwards".into());
        }
        let mut plan = Vec::new();
        let mut pending: HashMap<Hash, u32> = HashMap::new();
        for l in c.counted {
            if l.not_after == 0 {
                return Err("a counted link must set caveats.not_after".into());
            }
            if now > l.not_after {
                return Err("capability has expired".into());
            }
            let Some(Caveat::Uses { max, per }) = l.uses else { continue };
            let scope = if per == UsePer::Action { c.action.as_str() } else { "" };
            let key = counter_key(&l.link, self_id, scope);
            let run = match (per, c.program) {
                (UsePer::Link, Some((program, run))) => {
                    if self.runs.contains(&(key, program, run)) {
                        continue;
                    }
                    Some((program, run))
                }
                _ => None,
            };
            let cur = pending.get(&key).copied().unwrap_or_else(|| self.count(&key));
            if cur >= max {
                return Err("capability used up".into());
            }
            pending.insert(key, cur + 1);
            plan.push(Entry::Burn(BurnRecord { counter_key: key, count_after: cur + 1, link: l.link, leaf: c.leaf, action: c.action.clone(), at: now, not_after: l.not_after }));
            if let Some((program, run)) = run {
                plan.push(Entry::Run { counter_key: key, program, run, at: now, not_after: l.not_after });
            }
        }
        if plan.is_empty() {
            return Ok(());
        }
        let bytes: Vec<u8> = plan.iter().flat_map(frame).collect();
        if let Err(e) = self.file.write_all(&bytes).and_then(|_| self.file.sync_data()) {
            self.poisoned = true;
            return Err(format!("burn log write: {e}"));
        }
        for e in plan {
            self.apply(e);
        }
        Ok(())
    }

    /// The `burn` callback for [`authorize_v3`](super::verify::authorize_v3) at `self_id`, `now`.
    pub fn burner<'a>(&'a mut self, self_id: NodeKey, now: u64) -> impl FnMut(&Charge) -> Result<(), String> + 'a {
        move |c| self.charge(&self_id, now, c)
    }

    /// Drop the records with `now > not_after + PRUNE_AFTER`, keeping the clock high-water mark.
    /// The log is rewritten to a locked temporary file, `fsync`ed and renamed into place. Returns
    /// how many entries were dropped.
    pub fn prune(&mut self, now: u64) -> Result<usize, String> {
        if self.poisoned {
            return Err("burn log failed; reopen it before pruning".into());
        }
        if now.saturating_add(CLOCK_SLACK) < self.high {
            return Err("clock went backwards".into());
        }
        let before = self.entries.len();
        let high = self.high.max(now);
        let mut keep: Vec<Entry> =
            self.entries.iter().filter(|e| e.not_after().is_some_and(|na| now <= na.saturating_add(PRUNE_AFTER))).cloned().collect();
        keep.push(Entry::Clock { at: high });
        let tmp = self.path.with_extension("prune");
        let mut f = create_private(&tmp, true).map_err(io("prune"))?;
        f.try_lock().map_err(|_| "burn log prune file is held by another process".to_string())?;
        let mut bytes = HEADER.to_vec();
        bytes.extend(keep.iter().flat_map(frame));
        f.write_all(&bytes).and_then(|_| f.sync_all()).map_err(io("prune"))?;
        fs::rename(&tmp, &self.path).map_err(io("rename"))?;
        sync_dir(&self.path).map_err(io("sync"))?;
        self.file = f;
        self.entries.clear();
        self.counts.clear();
        self.runs.clear();
        for e in keep {
            self.apply(e);
        }
        Ok((before + 1).saturating_sub(self.entries.len()))
    }
}
