//! The burn log on disk (`docs/CAPABILITY-PROGRAMS.md` section 7): its records, their framing, and
//! the file handling [`super::uses::BurnLog`] stands on.
//!
//! File: the 8-byte header `CEBURN2\n`, then frames `len: u32 LE || bincode(Entry) ||
//! SHA-256(body)[..4]`. Only whole frames are ever acted on: they are written in one append and
//! `fsync`ed before the use is allowed. So on open a short tail, or a tail of zero bytes, is a
//! write torn by a crash that nothing acted on, and it is cut off. Any other damage (a checksum
//! or record that does not parse, an oversized frame) refuses the open: a log that cannot be
//! read in full cannot say what is spent.
//!
//! The file is opened in append mode, mode 0600, under an exclusive OS lock. After locking, the
//! path is checked to still name the locked file, so a process that opened the path just before
//! a prune renamed a new file over it cannot go on to burn into the orphan.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::program::Hash;

pub(super) const HEADER: &[u8; 8] = b"CEBURN2\n";
/// The largest frame body written or read.
pub(super) const MAX_FRAME: usize = 1 << 16;

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

/// What the log holds: burns, the run a `per: Link` counter was charged for (once per
/// `(leaf, program, run)`, section 6.4), and the clock high-water mark kept across a prune.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Entry {
    Burn(BurnRecord),
    Run { counter_key: Hash, leaf: Hash, program: Hash, run: u32, at: u64, not_after: u64 },
    Clock { at: u64 },
}

impl Entry {
    pub(super) fn at(&self) -> u64 {
        match self {
            Entry::Burn(r) => r.at,
            Entry::Run { at, .. } | Entry::Clock { at } => *at,
        }
    }

    /// The expiry of the link the entry belongs to; `None` for the clock mark, which is not kept
    /// by expiry.
    pub(super) fn not_after(&self) -> Option<u64> {
        match self {
            Entry::Burn(r) => Some(r.not_after),
            Entry::Run { not_after, .. } => Some(*not_after),
            Entry::Clock { .. } => None,
        }
    }
}

/// The frame of one entry. Refuses an entry too large to be read back: writing it would make the
/// log unreadable, and with it every counter.
pub(super) fn frame(e: &Entry) -> Result<Vec<u8>, String> {
    let body = bincode::serialize(e).map_err(|_| "burn record cannot be encoded".to_string())?;
    if body.len() > MAX_FRAME {
        return Err("burn record is too large (action too long)".into());
    }
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend(&body);
    out.extend(&Sha256::digest(&body)[..4]);
    Ok(out)
}

/// Parse the frames after the header; returns the entries and the length of the valid prefix.
fn parse(b: &[u8]) -> Result<(Vec<Entry>, usize), String> {
    let mut out = Vec::new();
    let mut at = HEADER.len();
    while at < b.len() {
        let rest = &b[at..];
        if rest.len() < 4 || rest.iter().all(|&x| x == 0) {
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

pub(super) fn io(what: &str) -> impl Fn(std::io::Error) -> String + '_ {
    move |e| format!("burn log {what}: {e}")
}

fn options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o
}

fn lock(f: &File) -> Result<(), String> {
    match f.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err("burn log is held by another process".into()),
        Err(TryLockError::Error(e)) => Err(format!("burn log lock: {e}")),
    }
}

/// Does `path` still name the open file `f`?
pub(super) fn same_file(f: &File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (f.metadata(), fs::metadata(path)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = f;
        path.exists()
    }
}

pub(super) fn sync_dir(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => File::open(d)?.sync_all(),
        _ => File::open(".")?.sync_all(),
    }
}

/// Open (or create, mode 0600) the log at `path`, lock it, and read it. Refuses a file another
/// process holds, one that is not a regular file, one group or others can read or write, and a
/// damaged one. A torn tail is cut off.
pub(super) fn open(path: &Path) -> Result<(File, Vec<Entry>), String> {
    let mut file = options().create(true).open(path).map_err(io("open"))?;
    lock(&file)?;
    if !same_file(&file, path) {
        return Err("burn log was replaced while it was being opened; open it again".into());
    }
    let meta = file.metadata().map_err(io("stat"))?;
    if !meta.is_file() {
        return Err("burn log is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!("burn log must be readable and writable only by its owner (mode {:o})", mode & 0o777));
        }
    }
    let mut b = Vec::new();
    file.read_to_end(&mut b).map_err(io("read"))?;
    if b.len() < HEADER.len() && HEADER.starts_with(&b) {
        // New, or a creation torn by a crash: the header is durable before any burn is written.
        file.write_all(&HEADER[b.len()..]).and_then(|_| file.sync_all()).map_err(io("write"))?;
        sync_dir(path).map_err(io("sync"))?;
        return Ok((file, Vec::new()));
    }
    if !b.starts_with(HEADER) {
        return Err("not a burn log".into());
    }
    let (entries, valid) = parse(&b)?;
    if valid < b.len() {
        file.set_len(valid as u64).and_then(|_| file.sync_all()).map_err(io("truncate"))?;
    }
    Ok((file, entries))
}

/// Write `keep` as a whole new log next to `path` and rename it over `path`. The new file is
/// locked and `fsync`ed before the rename. `Ok((file, dir_synced))`: the rename happened and
/// `file` is now the log; `dir_synced` is false when the directory could not be `fsync`ed, so the
/// rename may not survive a crash. `Err`: the old log is untouched.
pub(super) fn replace(path: &Path, keep: &[Entry]) -> Result<(File, Result<(), String>), String> {
    let mut bytes = HEADER.to_vec();
    for e in keep {
        bytes.extend(frame(e)?);
    }
    let tmp = path.with_extension("prune");
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(io("prune")(e)),
        _ => {}
    }
    // `create_new`: never a file (or a link to one) somebody else put there.
    let mut f = options().create_new(true).open(&tmp).map_err(io("prune"))?;
    lock(&f)?;
    f.write_all(&bytes).and_then(|_| f.sync_all()).map_err(io("prune"))?;
    fs::rename(&tmp, path).map_err(io("rename"))?;
    Ok((f, sync_dir(path).map_err(io("sync"))))
}
