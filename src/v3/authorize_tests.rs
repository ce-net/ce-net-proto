//! `authorize_v3` tests (section 5.2 and, for a program step, 6.4): what one node checks for one
//! request on top of the chain. Conditions are in `verify_cond_tests.rs`.

use std::cell::RefCell;

use super::types::AudienceSet;
use super::verify::{Charge, Node, Request, Roots, VerifiedV3, authorize_v3};
use super::verify_tests::*;
use super::*;
use crate::program::{ResourceV3, Step};

pub(super) fn node() -> Node<'static> {
    Node { id: HERE, tags: &[], host: Some("pi") }
}

/// A burn refuses once `burns` holds this many charges.
const USED_UP: usize = 3;

/// Authorize at `HERE` with ed(1) as the one root; `burns` records each charged action.
fn auth(t: &TokenV3, requester: Key, req: Request, burns: &RefCell<Vec<String>>) -> Result<VerifiedV3, String> {
    let mut burn = |c: &Charge| {
        assert_eq!(c.counted.len(), 2, "every counted link is charged");
        if burns.borrow().len() >= USED_UP {
            return Err("capability used up".to_string());
        }
        burns.borrow_mut().push(c.action.clone());
        Ok(())
    };
    authorize_v3(&node(), &Roots { keys: &[ed(1).key()], owners: &[] }, NOW, &requester, &req, t, &never, &mut burn)
}

#[test]
fn authorize_a_call() {
    let burns = RefCell::new(vec![]);
    let send = Request::Call("talk:send");
    let t = chain(|_| {});
    let v = auth(&t, ed(3).key(), send, &burns).unwrap();
    assert_eq!((v.holder, v.leaf()), (ed(3).key(), t.links[1].id()));
    assert_eq!(*burns.borrow(), vec!["talk:send".to_string()]);
    let not_held = "leaf capability is not held by the request sender";
    assert_eq!(auth(&t, ed(4).key(), send, &burns).unwrap_err(), not_held);
    // neither the root nor the issuer of the leaf may wield it
    assert_eq!(auth(&t, ed(1).key(), send, &burns).unwrap_err(), not_held);
    assert_eq!(auth(&t, p256(2).key(), send, &burns).unwrap_err(), not_held);
    assert_eq!(auth(&t, ed(3).key(), Request::Call("talk:read"), &burns).unwrap_err(), "capability does not grant 'talk:read'");
    assert_eq!(auth(&t, ed(3).key(), Request::Call("cell.install:install"), &burns).unwrap_err(), "capability does not grant 'cell.install:install'");
    // the leaf's right to grant never authorizes a call
    let t = chain(|c| {
        c.abilities = vec![];
        c.delegate = delegate(&["talk:send"], AudienceSet::Any, 1);
    });
    assert_eq!(auth(&t, ed(3).key(), send, &burns).unwrap_err(), "capability does not grant 'talk:send'");
    // the root link alone: its holder may grant, not use
    let root = token(vec![chain(|_| {}).links[0].clone()]);
    let mut none = |_: &Charge| Ok(());
    let r = Roots { keys: &[ed(1).key()], owners: &[] };
    assert_eq!(authorize_v3(&node(), &r, NOW, &p256(2).key(), &send, &root, &never, &mut none).unwrap_err(), "capability does not grant 'talk:send'");
    assert_eq!(burns.borrow().len(), 1, "no burn on a refusal");
}

#[test]
fn every_link_must_name_this_node_and_chain_checks_still_run() {
    let burns = RefCell::new(vec![]);
    let send = Request::Call("talk:send");
    let t = chain(|c| c.resource = ResourceV3::Node(THERE));
    assert_eq!(auth(&t, ed(3).key(), send, &burns).unwrap_err(), "link 1: resource does not match this node");
    let t = chain2(|g| g.resource = ResourceV3::Node(THERE), |c| c.resource = ResourceV3::Node(THERE));
    assert_eq!(auth(&t, ed(3).key(), send, &burns).unwrap_err(), "link 0: resource does not match this node");
    // 5.1 holds at a node too: narrowing, expiry, revocation, roots
    let t = chain(|c| c.abilities.push("proc.spawn:run".into()));
    assert_eq!(auth(&t, ed(3).key(), Request::Call("proc.spawn:run"), &burns).unwrap_err(), "link 1: abilities exceed the parent's grant");
    let t = chain(|_| {});
    let r = Roots { keys: &[ed(1).key()], owners: &[] };
    let mut none = |_: &Charge| Ok(());
    assert_eq!(authorize_v3(&node(), &r, T - 9, &ed(3).key(), &send, &t, &never, &mut none).unwrap_err(), "link 1: capability has expired");
    let revoked = |k: &Key, n: u64| (*k, n) == (ed(1).key(), 1);
    assert_eq!(authorize_v3(&node(), &r, NOW, &ed(3).key(), &send, &t, &revoked, &mut none).unwrap_err(), "link 0: capability revoked");
    let no_roots = Roots { keys: &[], owners: &[] };
    assert_eq!(
        authorize_v3(&node(), &no_roots, NOW, &ed(3).key(), &send, &t, &never, &mut none).unwrap_err(),
        "capability chain does not root at an accepted authority"
    );
    // the node's own key is a root at that node only
    let Key::Ed25519(own) = ed(1).key() else { unreachable!() };
    let own_grant = |g: &mut mint::Grant| g.resource = ResourceV3::Nodes(sorted(vec![own, HERE, THERE]));
    let t = chain2(own_grant, |c| c.resource = ResourceV3::Nodes(sorted(vec![own, HERE])));
    let at = |id| Node { id, tags: &[], host: None };
    assert!(authorize_v3(&at(own), &no_roots, NOW, &ed(3).key(), &send, &t, &never, &mut none).is_ok());
    assert_eq!(
        authorize_v3(&at(HERE), &no_roots, NOW, &ed(3).key(), &send, &t, &never, &mut none).unwrap_err(),
        "capability chain does not root at an accepted authority"
    );
    assert!(burns.borrow().is_empty());
}

fn sorted(mut v: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    v.sort();
    v
}

#[test]
fn counters_are_charged_last_and_their_refusal_is_the_answer() {
    let burns = RefCell::new(vec![]);
    let t = chain(|_| {});
    for _ in 0..USED_UP {
        assert!(auth(&t, ed(3).key(), Request::Call("talk:send"), &burns).is_ok());
    }
    assert_eq!(auth(&t, ed(3).key(), Request::Call("talk:send"), &burns).unwrap_err(), "capability used up");
    // an uncounted chain never reaches the burn log
    let t = chain2(|g| g.ext.clear(), |c| c.ext.clear());
    let mut burn = |_: &Charge| -> Result<(), String> { panic!("nothing to charge") };
    let r = Roots { keys: &[ed(1).key()], owners: &[] };
    assert!(authorize_v3(&node(), &r, NOW, &ed(3).key(), &Request::Call("talk:send"), &t, &never, &mut burn).is_ok());
}

fn inst(path: &str, size: u64, mode: u32) -> Step {
    Step::Install { on: HERE, path: path.into(), sha256: [9; 32], size, mode }
}

fn install() -> Step {
    inst("/opt/x/app/run.py", 10, 0o755)
}

fn exec(program: Hash, step: &Step) -> Request<'_> {
    Request::Execute { program, run: 0, step: 0, req: step }
}

#[test]
fn authorize_a_program_step() {
    let burns = RefCell::new(vec![]);
    let p = Program::new(vec![install()]);
    let id = p.id();
    let mut t = chain(|c| c.ext.push(Caveat::Programs(vec![id])));
    t.programs = vec![p.clone()];
    assert!(auth(&t, ed(3).key(), exec(id, &install()), &burns).is_ok());
    assert_eq!(*burns.borrow(), vec!["cell.install:install-file".to_string()]);
    assert_eq!(auth(&t, ed(3).key(), Request::Call("talk:send"), &burns).unwrap_err(), "capability is bound to a program");
    assert_eq!(auth(&t, ed(4).key(), exec(id, &install()), &burns).unwrap_err(), "leaf capability is not held by the request sender");
    // another body in the (unsigned) program list is not the one the signed chain names
    let other = Program::new(vec![inst("/opt/x/app/run.py", 11, 0o755)]);
    t.programs.push(other.clone());
    assert_eq!(auth(&t, ed(3).key(), exec(other.id(), &other.steps[0]), &burns).unwrap_err(), "program is not the one granted");
    let wrong = inst("/opt/x/app/run.py", 10, 0o777);
    assert_eq!(auth(&t, ed(3).key(), exec(id, &wrong), &burns).unwrap_err(), "the request is not program step 0");
    t.programs.clear();
    assert!(auth(&t, ed(3).key(), exec(id, &install()), &burns).unwrap_err().contains("is not in the token"));
    // an unbound chain still executes a program, typed the same way under the leaf
    let mut t = chain(|_| {});
    let bad = Program::new(vec![inst("/opt/x/other", 10, 0o755)]);
    t.programs = vec![p.clone(), bad.clone()];
    assert!(auth(&t, ed(3).key(), exec(id, &install()), &burns).is_ok());
    assert!(auth(&t, ed(3).key(), exec(bad.id(), &bad.steps[0]), &burns).unwrap_err().contains("is outside /opt/x/app"));
    // the leaf must grant the step's ability
    let mut t = chain(|c| c.abilities = strs(&["talk:send"]));
    t.programs = vec![p];
    assert!(auth(&t, ed(3).key(), exec(id, &install()), &burns).unwrap_err().contains("does not grant 'cell.install:install-file'"));
    assert_eq!(burns.borrow().len(), 2, "no burn on a refusal");
}
