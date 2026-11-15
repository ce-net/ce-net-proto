//! The refusal vectors of sections 12.1 to 12.3: each changes one thing in a chain, signing the
//! changed link directly (not through the minter, which would refuse it) so the verifier alone
//! must catch it.

use ce_net_proto::program::{EgressRule, HostPat, Program, Proto, ResourceV3, Step};
use ce_net_proto::v3::{AudienceSet, CapabilityV3, Caveat, Delegate, Link};

use crate::cases::*;

fn pi_with(f: impl FnOnce(&mut CapabilityV3)) -> Vec<u8> {
    let (l0, l1) = pi_links();
    token(&[&l0, &resign(&signer(WIN), &l1, f)], &[&pi_program()])
}

/// The long chain with link `i` changed by `f` (re-signed by its issuer, except link 0, which keeps
/// Leif's old signature), and link 2 re-signed under a changed link 1 so that only link `i` is wrong.
fn long_with(i: usize, f: impl FnOnce(&mut CapabilityV3)) -> Vec<u8> {
    let [mut l0, mut l1, mut l2] = long_links();
    match i {
        0 => {
            // changed after Leif signed it: the old signature is kept
            let Link::V3 { cap, sig } = &l0 else { unreachable!() };
            let mut cap = cap.clone();
            f(&mut cap);
            l0 = Link::V3 { cap, sig: sig.clone() };
        }
        1 => {
            l1 = resign(&signer(FRIEND), &l1, f);
            let id = l1.id();
            l2 = resign(&signer(FRIEND_AGENT), &l2, |c| c.parent = Some(id));
        }
        _ => l2 = resign(&signer(FRIEND_AGENT), &l2, f),
    }
    token(&[&l0, &l1, &l2], &[&job_program()])
}

/// Byte offset of the first `ext` caveat's variant tag of link 0 of a decoded-layout token.
fn first_caveat_tag(t: &[u8]) -> usize {
    let tok = ce_net_proto::v3::TokenV3::decode(t).unwrap();
    let Link::V3 { cap, .. } = &tok.links[0] else { unreachable!() };
    let head = bincode::serialize(&(cap.v, &cap.issuer, &cap.audience, &cap.abilities, &cap.resource, &cap.caveats)).unwrap();
    // magic, seq<Link> length, Link variant tag, the fields before ext, ext length
    4 + 8 + 4 + head.len() + 8
}

fn set_u32(mut t: Vec<u8>, at: usize, v: u32) -> Vec<u8> {
    t[at..at + 4].copy_from_slice(&v.to_le_bytes());
    t
}

fn chain_only(name: &'static str, note: &'static str, token: Vec<u8>, want: &'static str) -> Case {
    Case { name, note, token, now: T + 60, cells: vec![], verify: Err(want), uses: vec![] }
}

pub fn negative() -> Vec<Case> {
    let now = T + 60;
    let pi = pi_program();
    let b = |req, want| Use { at: AT_PI, shown: None, requester: AGENT_B, token: None, req, want };
    let evil = Program::new(vec![Step::Install { on: node(PI), path: "/opt/x/run.py".into(), sha256: sha(b"rm -rf /\n"), size: 9, mode: 0o755 }]);
    let (l0, l1) = pi_links();
    let mut wrong_file = exec(&pi, 1, 0);
    if let Req::Exec { req: Step::Install { sha256, .. }, .. } = &mut wrong_file {
        *sha256 = sha(b"rm -rf /\n");
    }
    let mut both = vec![node(PI), node(BOX)];
    both.sort();
    let pi_case = |name, note, token, verify, uses| Case { name, note, token, now, cells: vec![], verify, uses };
    let root = first_root();
    let (desk_leaf, desk_p) = first_leaf(&root, "talk.messages", AT_DESK, 104);
    let desk_token = token(&[&root, &desk_leaf], &[&desk_p]);
    let ins = |at, run, want| Use { at, shown: None, requester: INSTALLER, token: None, req: exec(&desk_p, run, 0), want };
    let wide_suffix = |host: &str| Caveat::Egress(vec![EgressRule { host: HostPat::Suffix(host.into()), ports: vec![443], proto: Proto::Tcp }]);
    vec![
        chain_only("pi-widened-ability", "12.1 L1 adds proc.spawn:run, which L0 does not grant", pi_with(|c| c.abilities.push("proc.spawn:run".into())), "link 1: abilities exceed the parent's grant"),
        chain_only("pi-widened-resource", "12.1 L1 names pi-01 and box-1 under L0's pi-01", pi_with(|c| c.resource = ResourceV3::Nodes(both)), "link 1: resource is broader than the parent"),
        pi_case("pi-wrong-audience", "12.1 token presented by planner, not agent B (L1's audience)", pi_token(), Ok(()), vec![Use { at: AT_PI, shown: None, requester: WIN, token: None, req: exec(&pi, 1, 0), want: Err("leaf capability is not held by the request sender") }]),
        pi_case("pi-root-holder-cannot-use", "12.1 [L0] alone: planner may grant but not use (L0 has no abilities)", token(&[&l0], &[&pi]), Ok(()), vec![Use { at: AT_PI, shown: None, requester: WIN, token: None, req: exec(&pi, 1, 0), want: Err("the capability does not grant 'cell.install:install-file'") }]),
        pi_case("pi-wrong-program", "12.1 another program (another file hash) carried in the token, not the one Programs names", token(&[&l0, &l1], &[&pi, &evil]), Ok(()), vec![b(exec(&evil, 1, 0), Err("program is not the one granted"))]),
        pi_case("pi-wrong-file-hash", "12.1 the granted program, but the request installs a file with another hash", pi_token(), Ok(()), vec![b(wrong_file, Err("the request is not program step 0"))]),
        pi_case("pi-replayed", "12.1 a second install (run 2) finds both counters spent", pi_token(), Ok(()), vec![b(exec(&pi, 1, 0), Ok(())), b(exec(&pi, 2, 0), Err("capability used up"))]),
        Case { name: "pi-expired", note: "12.1 one second after L1's not_after (T+1d)", token: pi_token(), now: T + DAY + 1, cells: vec![], verify: Err("link 1: capability has expired"), uses: vec![b(exec(&pi, 1, 0), Err("link 1: capability has expired"))] },
        chain_only("pi-unknown-caveat-variant", "12.1 L0's first caveat tag set to 7, the first Caveat variant index not assigned (0 to 6 are)", set_u32(pi_token(), first_caveat_tag(&pi_token()), 7), "malformed v3 capability token"),
        chain_only("pi-unknown-link-variant", "12.1 the first Link tag set to 2 (neither V1 nor V3)", set_u32(pi_token(), 12, 2), "malformed v3 capability token"),
        chain_only("long-l0-widened-after-signing", "12.2 L0 not_after moved to T+30d after Leif signed it", long_with(0, |c| c.caveats.not_after = T + 30 * DAY), "link 0: invalid signature"),
        chain_only("long-l0-widened-by-friend", "12.2 L0 widened to 30 days and signed by the friend, who is no root", {
            let [_, l1, l2] = long_links();
            let l0 = resign(&signer(FRIEND), &long_links()[0], |c| {
                c.issuer = key(FRIEND);
                c.caveats.not_after = T + 30 * DAY;
            });
            token(&[&l0, &l1, &l2], &[&job_program()])
        }, "capability chain does not root at an accepted authority"),
        chain_only("long-l1-widened-uses", "12.2 L1 Uses 6 under L0's 5", long_with(1, |c| c.ext[0] = Caveat::Uses { max: 6, per: ce_net_proto::v3::UsePer::Link }), "link 1: caveats are broader than the parent"),
        chain_only("long-l1-widened-egress", "12.2 L1 Egress *.org under L0's *.example.org", long_with(1, |c| c.ext[2] = wide_suffix(".org")), "link 1: caveats are broader than the parent"),
        chain_only("long-l1-widened-limit", "12.2 L1 bytes_in 600 MB under L0's 500 MB", long_with(1, |c| c.ext[1] = limits(600_000_000, 10_000_000, 600)), "link 1: caveats are broader than the parent"),
        chain_only("long-l1-depth-not-dropping", "12.2 L1 keeps depth 2 under L0's depth 2", long_with(1, |c| c.delegate.as_mut().unwrap().depth = 2), "link 1: delegation depth exceeds the parent"),
        chain_only("long-l2-widened-ability", "12.2 the process link adds proc.spawn:run; L1 lets the agent grant only net.egress:connect", long_with(2, |c| c.abilities.push("proc.spawn:run".into())), "link 2: abilities exceed the parent's grant"),
        chain_only("long-l2-widened-egress", "12.2 the process link allows *.example.org under L1's api.example.org", long_with(2, |c| c.ext[2] = wide_suffix(".example.org")), "link 2: caveats are broader than the parent"),
        chain_only("long-l2-redelegates", "12.2 the process link grants one more layer; L1's depth 1 allows none", long_with(2, |c| {
            c.delegate = Some(Delegate { abilities: s(&["net.egress:connect"]), audience: AudienceSet::Any, depth: 1 })
        }), "link 2: delegation depth exceeds the parent"),
        pi_case("first-use-replayed", "12.3 the talk.messages@leif-desk leaf presented twice", desk_token.clone(), Ok(()), vec![ins(AT_DESK, 1, Ok(())), ins(AT_DESK, 2, Err("capability used up"))]),
        pi_case("first-use-wrong-node", "12.3 the leif-desk leaf presented at the MacBook", desk_token, Ok(()), vec![ins(AT_MAC, 1, Err("link 1: resource does not match this node"))]),
        chain_only("first-use-ungranted-cell", "12.3 a leaf for a cell Leif did not name (ce.secret)", {
            let leaf = resign(&signer(WIN), &desk_leaf, |c| c.abilities[1] = "cell.install:install:ce.secret@leif-desk".into());
            token(&[&root, &leaf], &[&desk_p])
        }, "link 1: abilities exceed the parent's grant"),
    ]
}
