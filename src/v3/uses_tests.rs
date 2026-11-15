//! Burn-log tests (section 7): the counter key bytes, replay refusal through `authorize_v3`,
//! all-or-nothing charging, once per run, the clock-rollback guard, prune, torn tails and damage.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use super::mint::{Grant, root_token};
use super::sign::Signer;
use super::uses::{BurnLog, CLOCK_SLACK, PRUNE_AFTER, check_counted, counter_key};
use super::verify::{Charge, Counted, Node, Request, Roots, authorize_v3};
use super::*;
use crate::cap::Caveats;
use crate::program::ResourceV3;

const T: u64 = 2_000_000_000;
const NOW: u64 = T - 1000;
const HERE: [u8; 32] = [1; 32];
const THERE: [u8; 32] = [2; 32];

fn temp_log(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("ce-burn-{}-{}-{name}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("burn.log")
}

fn counted(link: u8, max: u32, per: UsePer, not_after: u64) -> Counted {
    Counted { link: [link; 32], uses: Some(Caveat::Uses { max, per }), cumulative: vec![], not_after }
}

fn charge<'a>(counted: &'a [Counted], action: &str, program: Option<(Hash, u32)>) -> Charge<'a> {
    Charge { leaf: [9; 32], counted, action: action.into(), program }
}

fn grant(holder: Key, max: u32) -> Grant {
    Grant {
        audience: holder,
        abilities: vec!["talk:send".into()],
        resource: ResourceV3::Node(HERE),
        caveats: Caveats { not_after: T, ..Caveats::default() },
        ext: vec![Caveat::Uses { max, per: UsePer::Link }],
        delegate: None,
        nonce: 1,
    }
}

#[test]
fn counter_key_is_the_spec_bytes() {
    let mut b = 13u64.to_le_bytes().to_vec();
    b.extend(b"ce-cap-use-v1");
    b.extend([7u8; 32]);
    b.extend(HERE);
    b.extend(9u64.to_le_bytes());
    b.extend(b"talk:send");
    let want: Hash = sha2::Sha256::digest(&b).into();
    assert_eq!(counter_key(&[7; 32], &HERE, "talk:send"), want);
    let k = counter_key(&[7; 32], &HERE, "");
    assert_ne!(k, counter_key(&[7; 32], &THERE, ""), "each node counts alone");
    assert_ne!(k, counter_key(&[8; 32], &HERE, ""), "each link counts alone");
    assert_ne!(k, want, "per Action scopes by action");
}

#[test]
fn replayed_token_finds_its_counter_spent_even_after_restart() {
    let path = temp_log("replay");
    let (issuer, holder) = (Signer::ed25519(&[1; 32]), Signer::ed25519(&[3; 32]));
    let t = root_token(&issuer, grant(holder.key(), 1)).unwrap();
    let roots = [issuer.key()];
    let r = Roots { keys: &roots, owners: &[] };
    let node = Node { id: HERE, tags: &[], host: None };
    let never = |_: &Key, _: u64| false;
    let call = Request::Call("talk:send");
    let mut log = BurnLog::open(&path).unwrap();
    assert!(authorize_v3(&node, &r, NOW, &holder.key(), &call, &t, &never, &mut log.burner(HERE, NOW)).is_ok());
    let again = authorize_v3(&node, &r, NOW + 1, &holder.key(), &call, &t, &never, &mut log.burner(HERE, NOW + 1));
    assert_eq!(again.unwrap_err(), "capability used up");
    drop(log);
    let mut log = BurnLog::open(&path).unwrap();
    let after = authorize_v3(&node, &r, NOW + 2, &holder.key(), &call, &t, &never, &mut log.burner(HERE, NOW + 2));
    assert_eq!(after.unwrap_err(), "capability used up", "the burn survives a restart");
    let elsewhere = Node { id: THERE, ..node };
    let other = authorize_v3(&elsewhere, &r, NOW, &holder.key(), &call, &t, &never, &mut log.burner(THERE, NOW));
    assert!(other.is_err(), "a node outside the link's finite resource is never charged: it is refused");
}

#[test]
fn max_uses_then_refused_and_counted_per_node() {
    let mut log = BurnLog::open(&temp_log("max")).unwrap();
    let c = [counted(1, 2, UsePer::Link, T)];
    assert!(log.charge(&HERE, NOW, &charge(&c, "a", None)).is_ok());
    assert!(log.charge(&HERE, NOW, &charge(&c, "a", None)).is_ok());
    assert_eq!(log.charge(&HERE, NOW, &charge(&c, "a", None)).unwrap_err(), "capability used up");
    assert_eq!(log.count(&counter_key(&[1; 32], &HERE, "")), 2);
    assert!(log.charge(&THERE, NOW, &charge(&c, "a", None)).is_ok(), "another node has its own share");
}

#[test]
fn per_action_counts_each_action() {
    let mut log = BurnLog::open(&temp_log("action")).unwrap();
    let c = [counted(1, 1, UsePer::Action, T)];
    assert!(log.charge(&HERE, NOW, &charge(&c, "talk:send", None)).is_ok());
    assert!(log.charge(&HERE, NOW, &charge(&c, "talk:read", None)).is_ok());
    assert_eq!(log.charge(&HERE, NOW, &charge(&c, "talk:send", None)).unwrap_err(), "capability used up");
}

#[test]
fn every_link_is_charged_or_none() {
    let mut log = BurnLog::open(&temp_log("all")).unwrap();
    let parent = [counted(1, 1, UsePer::Link, T)];
    assert!(log.charge(&HERE, NOW, &charge(&parent, "a", None)).is_ok());
    let both = [counted(1, 1, UsePer::Link, T), counted(2, 5, UsePer::Link, T)];
    assert_eq!(log.charge(&HERE, NOW, &charge(&both, "a", None)).unwrap_err(), "capability used up");
    assert_eq!(log.count(&counter_key(&[2; 32], &HERE, "")), 0, "the child was not charged");
}

#[test]
fn per_link_is_charged_once_per_program_run() {
    let path = temp_log("run");
    let mut log = BurnLog::open(&path).unwrap();
    let c = [counted(1, 1, UsePer::Link, T)];
    let p = [5; 32];
    assert!(log.charge(&HERE, NOW, &charge(&c, "step0", Some((p, 1)))).is_ok());
    assert!(log.charge(&HERE, NOW, &charge(&c, "step1", Some((p, 1)))).is_ok(), "same run");
    drop(log);
    let mut log = BurnLog::open(&path).unwrap();
    assert!(log.charge(&HERE, NOW, &charge(&c, "step2", Some((p, 1)))).is_ok(), "same run after restart");
    assert_eq!(log.charge(&HERE, NOW, &charge(&c, "step0", Some((p, 2)))).unwrap_err(), "capability used up");
    assert_eq!(log.charge(&HERE, NOW, &charge(&c, "x", None)).unwrap_err(), "capability used up");
}

#[test]
fn clock_rollback_refuses_counted_use() {
    let path = temp_log("clock");
    let mut log = BurnLog::open(&path).unwrap();
    let c = [counted(1, 10, UsePer::Link, T)];
    assert!(log.charge(&HERE, NOW, &charge(&c, "a", None)).is_ok());
    assert!(log.charge(&HERE, NOW - CLOCK_SLACK, &charge(&c, "a", None)).is_ok(), "within the slack");
    assert_eq!(log.charge(&HERE, NOW - CLOCK_SLACK - 1, &charge(&c, "a", None)).unwrap_err(), "clock went backwards");
    drop(log);
    let mut log = BurnLog::open(&path).unwrap();
    assert_eq!(log.high_water(), NOW);
    assert_eq!(log.charge(&HERE, NOW - 1000, &charge(&c, "a", None)).unwrap_err(), "clock went backwards");
}

#[test]
fn prune_drops_old_records_but_keeps_the_clock() {
    let path = temp_log("prune");
    let mut log = BurnLog::open(&path).unwrap();
    let old = [counted(1, 1, UsePer::Link, 1000)];
    let live = [counted(2, 1, UsePer::Link, T)];
    assert!(log.charge(&HERE, 900, &charge(&old, "a", None)).is_ok());
    assert!(log.charge(&HERE, NOW, &charge(&live, "a", None)).is_ok());
    assert_eq!(log.prune(1000 + PRUNE_AFTER + 1).unwrap_err(), "clock went backwards");
    assert_eq!(log.prune(NOW).unwrap(), 1);
    assert_eq!(log.count(&counter_key(&[1; 32], &HERE, "")), 0);
    drop(log);
    let mut log = BurnLog::open(&path).unwrap();
    assert_eq!(log.charge(&HERE, NOW, &charge(&live, "a", None)).unwrap_err(), "capability used up");
    assert_eq!(log.charge(&HERE, 900, &charge(&old, "a", None)).unwrap_err(), "clock went backwards", "an expired link stays dead");
    assert_eq!(log.charge(&HERE, NOW, &charge(&old, "a", None)).unwrap_err(), "capability has expired");
}

#[test]
fn burn_refuses_unbounded_or_expired_links() {
    let mut log = BurnLog::open(&temp_log("expiry")).unwrap();
    let forever = [counted(1, 1, UsePer::Link, 0)];
    assert_eq!(log.charge(&HERE, NOW, &charge(&forever, "a", None)).unwrap_err(), "a counted link must set caveats.not_after");
    let gone = [counted(1, 1, UsePer::Link, NOW - 1)];
    assert_eq!(log.charge(&HERE, NOW, &charge(&gone, "a", None)).unwrap_err(), "capability has expired");
}

#[test]
fn torn_tail_is_cut_and_damage_refused() {
    let path = temp_log("torn");
    let c = [counted(1, 3, UsePer::Link, T)];
    BurnLog::open(&path).unwrap().charge(&HERE, NOW, &charge(&c, "a", None)).unwrap();
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(&[40, 0, 0, 0, 1, 2]).unwrap();
    let mut log = BurnLog::open(&path).unwrap();
    assert_eq!(log.count(&counter_key(&[1; 32], &HERE, "")), 1);
    log.charge(&HERE, NOW, &charge(&c, "a", None)).unwrap();
    drop(log);
    assert_eq!(BurnLog::open(&path).unwrap().count(&counter_key(&[1; 32], &HERE, "")), 2);
    let mut b = std::fs::read(&path).unwrap();
    b[14] ^= 1;
    std::fs::write(&path, &b).unwrap();
    assert!(BurnLog::open(&path).unwrap_err().starts_with("burn log is damaged"));
}

#[test]
fn log_is_exclusive_and_private() {
    let path = temp_log("lock");
    let log = BurnLog::open(&path).unwrap();
    assert_eq!(BurnLog::open(&path).unwrap_err(), "burn log is held by another process");
    drop(log);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(BurnLog::open(&path).unwrap_err().starts_with("burn log must be readable and writable only by its owner"));
    }
}

#[test]
fn counted_links_name_finite_nodes_and_expire() {
    let t = root_token(&Signer::ed25519(&[1; 32]), grant(Signer::ed25519(&[3; 32]).key(), 1)).unwrap();
    let Link::V3 { cap, .. } = &t.links[0] else { unreachable!() };
    assert!(check_counted(cap).is_ok());
    let mut c = cap.clone();
    c.caveats.not_after = 0;
    assert_eq!(check_counted(&c).unwrap_err(), "a counted link must set caveats.not_after");
    for r in [ResourceV3::Any, ResourceV3::Tag("lab".into())] {
        let mut c = cap.clone();
        c.resource = r;
        assert_eq!(check_counted(&c).unwrap_err(), "a counted link must name a finite resource (Node or Nodes)");
    }
    let mut c = cap.clone();
    c.ext = vec![Caveat::Uses { max: 1, per: UsePer::Action }];
    c.abilities = vec!["talk:*".into()];
    assert_eq!(check_counted(&c).unwrap_err(), "Uses per Action needs abilities without wildcards");
    let mut c = cap.clone();
    c.ext.clear();
    c.caveats.not_after = 0;
    c.resource = ResourceV3::Any;
    assert!(check_counted(&c).is_ok(), "an uncounted link needs neither");
}
