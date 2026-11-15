//! Counted use (`docs/CAPABILITY-PROGRAMS.md` section 7): the node-local burn log behind the
//! `burn` callback of [`authorize_v3`](super::authorize::authorize_v3), and the canonical-form
//! rule that a counted link expires and names a finite set of nodes ([`check_counted`]).
//!
//! [`BurnLog::charge`] takes `&mut self` (the burn lock within a process; across processes the
//! file is held under an exclusive OS lock). It reads the counter of every counted link of the
//! chain, refuses if any is at its `max`, appends every record in one write, `fsync`s, and only
//! then reports success. A refusal writes nothing. A crash between the burn and the act loses
//! the use; it never grants a second one. Any write failure poisons the log: every later counted
//! use is refused until it is reopened, and what reached the disk then counts as spent.
//!
//! What this log does not do: it does not stop one step of a program run from being asked for
//! twice. `Uses` with `per: Link` is charged once per `(leaf, program, run)`, so a repeated step
//! of a charged run costs nothing here; the cell's run log (section 6.4 rule 4) refuses it, and
//! must be consulted inside the `burn` callback before [`BurnLog::charge`].
//!
//! Cumulative limits share [`counter_key`] (scope = the limit name) but are totals kept by the
//! egress enforcer, not uses: [`BurnLog::charge`] checks their link's expiry and nothing more.
//!
//! The file format and its handling are in [`super::uses_file`].

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::authorize::Charge;
use super::uses_file::{self as file, frame};
pub use super::uses_file::{BurnRecord, Entry};
use super::{Caveat, CapabilityV3, UsePer};
use crate::program::{CUMULATIVE_LIMITS, Hash, NodeKey};

/// Domain tag of [`counter_key`] (13 ASCII bytes, length-prefixed).
pub const USE_DOMAIN: &[u8] = b"ce-cap-use-v1";
/// A clock this many seconds below the highest `at` the log has seen refuses every counted use.
pub const CLOCK_SLACK: u64 = 300;
/// A record may be pruned once `now > not_after + PRUNE_AFTER`.
pub const PRUNE_AFTER: u64 = 86_400;

/// `SHA-256(len(13) || "ce-cap-use-v1" || cap_id(L) || self_id || string(scope))`; `scope` is ""
/// for `per: Link`, the charged action for `per: Action`, the limit name for a cumulative limit.
/// Lengths are `u64` little-endian, as everywhere in the format.
pub fn counter_key(link: &Hash, self_id: &NodeKey, scope: &str) -> Hash {
    let mut h = Sha256::new();
    h.update((USE_DOMAIN.len() as u64).to_le_bytes());
    h.update(USE_DOMAIN);
    h.update(link);
    h.update(self_id);
    h.update((scope.len() as u64).to_le_bytes());
    h.update(scope.as_bytes());
    h.finalize().into()
}

/// Section 7: a counted link (it carries `Uses` or a cumulative limit) sets `caveats.not_after`
/// and names a finite set of nodes (`Node` or `Nodes`); with `per: Action` its reachable
/// abilities hold no wildcard. Run by the canonical-form check of every link, at mint and at
/// verify.
pub fn check_counted(c: &CapabilityV3) -> Result<(), String> {
    let uses = c.ext.iter().any(|cv| matches!(cv, Caveat::Uses { .. }));
    let per_action = c.ext.iter().any(|cv| matches!(cv, Caveat::Uses { per: UsePer::Action, .. }));
    let cumulative = c.ext.iter().any(|cv| match cv {
        Caveat::Limits(ls) => ls.iter().any(|l| CUMULATIVE_LIMITS.contains(&l.name.as_str())),
        _ => false,
    });
    if !uses && !cumulative {
        return Ok(());
    }
    if c.caveats.not_after == 0 {
        return Err("a counted link must set caveats.not_after".into());
    }
    if !c.resource.is_finite() {
        return Err("a counted link must name a finite resource (Node or Nodes)".into());
    }
    if per_action {
        let mut reach = c.abilities.iter().chain(c.delegate.iter().flat_map(|d| d.abilities.iter()));
        if reach.any(|a| a.contains('*')) {
            return Err("Uses per Action needs abilities without wildcards".into());
        }
    }
    Ok(())
}

/// The node-local, append-only burn log.
#[derive(Debug)]
pub struct BurnLog {
    path: PathBuf,
    file: File,
    entries: Vec<Entry>,
    counts: HashMap<Hash, u32>,
    /// `(counter_key, leaf, program, run)` already charged for a `per: Link` counter.
    runs: HashSet<(Hash, Hash, Hash, u32)>,
    high: u64,
    poisoned: bool,
}

impl BurnLog {
    /// Open (or create, mode 0600) the log at `path` and hold it under an exclusive lock. Refuses
    /// a file group or others can read or write, a file another process holds, and a damaged one.
    pub fn open(path: &Path) -> Result<BurnLog, String> {
        let (file, entries) = file::open(path)?;
        let mut log = BurnLog {
            path: path.to_path_buf(),
            file,
            entries: Vec::new(),
            counts: HashMap::new(),
            runs: HashSet::new(),
            high: 0,
            poisoned: false,
        };
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
            Entry::Run { counter_key, leaf, program, run, .. } => {
                self.runs.insert((*counter_key, *leaf, *program, *run));
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

    fn guard(&self, now: u64) -> Result<(), String> {
        if self.poisoned {
            return Err("burn log failed; counted use refused until it is reopened".into());
        }
        if now.saturating_add(CLOCK_SLACK) < self.high {
            return Err("clock went backwards".into());
        }
        Ok(())
    }

    /// Charge every counted link of `c` at node `self_id`, all or none (section 7). On `Ok` the
    /// records are on disk and the caller may act. On `Err` nothing was charged, except after a
    /// write failure, where the log is poisoned and the use may have been spent.
    pub fn charge(&mut self, self_id: &NodeKey, now: u64, c: &Charge) -> Result<(), String> {
        self.guard(now)?;
        let mut plan = Vec::new();
        let mut pending: HashMap<Hash, u32> = HashMap::new();
        for l in c.counted {
            if l.not_after == 0 {
                return Err("a counted link must set caveats.not_after".into());
            }
            if now > l.not_after {
                return Err("capability has expired".into());
            }
            let (max, per) = match &l.uses {
                None => continue,
                Some(Caveat::Uses { max, per }) => (*max, *per),
                Some(_) => return Err("counted link does not carry Uses".into()),
            };
            let scope = if per == UsePer::Action { c.action.as_str() } else { "" };
            let key = counter_key(&l.link, self_id, scope);
            // 6.4 rule 5: `per: Link` is charged once per run, and a run is `(leaf, program, run)`.
            let run = match (per, c.program) {
                (UsePer::Link, Some((program, run))) => {
                    if self.runs.contains(&(key, c.leaf, program, run)) {
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
            plan.push(Entry::Burn(BurnRecord {
                counter_key: key,
                count_after: cur + 1,
                link: l.link,
                leaf: c.leaf,
                action: c.action.clone(),
                at: now,
                not_after: l.not_after,
            }));
            if let Some((program, run)) = run {
                plan.push(Entry::Run { counter_key: key, leaf: c.leaf, program, run, at: now, not_after: l.not_after });
            }
        }
        if plan.is_empty() {
            return Ok(());
        }
        let mut bytes = Vec::new();
        for e in &plan {
            bytes.extend(frame(e)?);
        }
        if let Err(e) = self.file.write_all(&bytes).and_then(|_| self.file.sync_data()) {
            self.poisoned = true;
            return Err(format!("burn log write: {e}"));
        }
        for e in plan {
            self.apply(e);
        }
        Ok(())
    }

    /// The `burn` callback for [`authorize_v3`](super::authorize::authorize_v3) at `self_id`, `now`.
    pub fn burner<'a>(&'a mut self, self_id: NodeKey, now: u64) -> impl FnMut(&Charge) -> Result<(), String> + 'a {
        move |c| self.charge(&self_id, now, c)
    }

    /// Drop the records with `now > not_after + PRUNE_AFTER`, keeping the clock high-water mark
    /// (raised to `now`), so a clock set back cannot revive a link whose records are gone. The
    /// log is rewritten to a locked temporary file, `fsync`ed and renamed into place. Returns how
    /// many records were dropped. If the rename cannot be made durable the log is poisoned.
    pub fn prune(&mut self, now: u64) -> Result<usize, String> {
        self.guard(now)?;
        let live = |e: &&Entry| e.not_after().is_some_and(|na| now <= na.saturating_add(PRUNE_AFTER));
        let records = self.entries.iter().filter(|e| e.not_after().is_some()).count();
        let mut keep: Vec<Entry> = self.entries.iter().filter(live).cloned().collect();
        let dropped = records - keep.len();
        keep.push(Entry::Clock { at: self.high.max(now) });
        let (f, synced) = file::replace(&self.path, &keep)?;
        // The rename happened: from here the new file is the log, whatever else fails.
        self.file = f;
        self.entries.clear();
        self.counts.clear();
        self.runs.clear();
        for e in keep {
            self.apply(e);
        }
        if let Err(e) = synced {
            self.poisoned = true;
            return Err(e);
        }
        Ok(dropped)
    }
}
