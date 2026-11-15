//! Section 12.4: Leif's three condition rules as chains, each met once and each refused, and
//! children that drop or loosen an inherited condition.
//!
//! - "have you read the wechat chat before writing": `Requires`, attested by the wechat cell.
//! - "always verify the auth code and talk to this all through the same systems agent": `CoSign`
//!   and `Via` naming the same guardian key.
//! - "always talk to this agent if you want to access the 3d printer": `Via` the printer's gate cell.
//!
//! Every chain is Leif -> planner (may grant, may not use) -> the agent that acts. The proofs are
//! signed here with the fixed keys; a refusal changes one thing in what the use presents.

use ce_net_proto::Caveats;
use ce_net_proto::program::ResourceV3;
use ce_net_proto::v3::mint::{Grant, attenuate, mint_root};
use ce_net_proto::v3::{
    Attestation, AttestationBody, AudienceSet, Caveat, Claim, CoSignPer, CoSigner, Delegate, Link, Party, Proof,
    Requirement, UseRequest, attest_bytes, cosign_bytes, via_bytes,
};

use crate::cases::*;

const BROADER: &str = "link 1: caveats are broader than the parent";
const NOW: u64 = T + 60;

/// One rule: who may do what where, under which conditions.
#[derive(Clone)]
struct Rule {
    ability: &'static str,
    at: At,
    holder: u8,
    conds: Vec<Caveat>,
    /// The keys the node trusts per cell api.
    cells: Vec<(&'static str, u8)>,
    nonce: u64,
}

fn grant(r: &Rule, leaf: bool, ext: Vec<Caveat>) -> Grant {
    let own = s(&[r.ability]);
    Grant {
        audience: key(if leaf { r.holder } else { WIN }),
        abilities: if leaf { own.clone() } else { vec![] },
        resource: ResourceV3::Node(node(r.at.seed)),
        caveats: Caveats { not_after: T + if leaf { DAY } else { 7 * DAY }, ..Caveats::default() },
        ext,
        delegate: (!leaf).then(|| Delegate { abilities: own, audience: AudienceSet::Any, depth: 1 }),
        nonce: r.nonce + leaf as u64,
    }
}

/// `[L0, L1]`: Leif sets the conditions, planner hands the right on with all of them.
fn links(r: &Rule) -> (Link, Link) {
    let l0 = mint_root(&signer(LEIF), grant(r, false, r.conds.clone())).unwrap();
    let l1 = attenuate(&signer(WIN), &l0, grant(r, true, r.conds.clone())).unwrap();
    (l0, l1)
}

/// The chain with L1's conditions replaced by `ext`. The minter must refuse it; it is then signed
/// by planner directly, so the verifier alone has to.
fn loosened(r: &Rule, ext: Vec<Caveat>) -> Vec<u8> {
    let (l0, l1) = links(r);
    assert!(attenuate(&signer(WIN), &l0, grant(r, true, ext.clone())).is_err(), "the minter let a condition go");
    token(&[&l0, &resign(&signer(WIN), &l1, |c| c.ext = ext)], &[])
}

/// What one use of a rule's chain presents: its request, signed off by whoever `proofs` asks.
struct Call<'a> {
    rule: &'a Rule,
    leaf: [u8; 32],
    body: &'static [u8],
    nonce: u64,
}

impl Call<'_> {
    /// The honest request for `body` at the rule's node, made now.
    fn request(&self) -> UseRequest {
        self.request_for(self.body)
    }

    fn request_for(&self, body: &[u8]) -> UseRequest {
        let r = self.rule;
        UseRequest { leaf: self.leaf, node: node(r.at.seed), requester: key(r.holder), action: r.ability.into(), body: sha(body), at: NOW, nonce: self.nonce }
    }

    /// The use: `request` and `proofs` presented with the body the node receives.
    fn with(&self, request: UseRequest, proofs: Vec<Proof>, want: Result<(), &'static str>) -> Use {
        let r = self.rule;
        let shown = Some(Shown { request, proofs, body: self.body.to_vec() });
        Use { at: r.at, requester: r.holder, token: None, req: Req::Call(r.ability), shown, want }
    }

    fn shows(&self, proofs: Vec<Proof>, want: Result<(), &'static str>) -> Use {
        self.with(self.request(), proofs, want)
    }

    /// The same call with no request and no proofs at all (`authorize_v3`).
    fn bare(&self, want: &'static str) -> Use {
        let r = self.rule;
        Use { at: r.at, requester: r.holder, token: None, req: Req::Call(r.ability), shown: None, want: Err(want) }
    }
}

fn attested(witness: u8, subject: u8, thread: &str, at: u64) -> Proof {
    let claim = Claim::ReadThrough { source: "wechat".into(), thread: thread.into(), upto_msg: Some("m42".into()) };
    let body = AttestationBody { witness: key(witness), subject: key(subject), claim, at };
    Proof::Attested(Attestation { sig: signer(witness).sign_bytes(&attest_bytes(&body)), body })
}

fn cosigned(by: u8, r: &UseRequest) -> Proof {
    Proof::CoSigned { by: key(by), sig: signer(by).sign_bytes(&cosign_bytes(r)) }
}

fn brokered(by: u8, r: &UseRequest) -> Proof {
    Proof::Brokered { broker: key(by), sig: signer(by).sign_bytes(&via_bytes(r)) }
}

fn read_family(fresh: u64) -> Caveat {
    let claim = Claim::ReadThrough { source: "wechat".into(), thread: "family".into(), upto_msg: None };
    Caveat::Requires(vec![Requirement { witness: Party::Cell("wechat.read".into()), claim, fresh_within_s: Some(fresh) }])
}

fn cosign_guardian() -> Caveat {
    Caveat::CoSign(vec![CoSigner { by: key(GUARDIAN), per: CoSignPer::Use }])
}

fn case(name: &'static str, note: &'static str, r: &Rule, token: Vec<u8>, verify: Result<(), &'static str>, uses: Vec<Use>) -> Case {
    Case { name, note, token, now: NOW, cells: r.cells.clone(), verify, uses }
}

pub fn conditions() -> Vec<Case> {
    let wechat = Rule { ability: "wechat.send:send", at: AT_DESK, holder: WRITER, conds: vec![read_family(600)], cells: vec![("wechat.read", WECHAT_CELL)], nonce: 30 };
    let door = Rule {
        ability: "door.gate:pass",
        at: AT_BOX,
        holder: AGENT_B,
        conds: vec![cosign_guardian(), Caveat::Via(vec![Party::Key(key(GUARDIAN))])],
        cells: vec![],
        nonce: 40,
    };
    let printer = Rule {
        ability: "printer3d:print",
        at: AT_PRINTER,
        holder: AGENT_B,
        conds: vec![Caveat::Via(vec![Party::Cell("printer3d.gate".into())])],
        cells: vec![("printer3d.gate", PRINTER_AGENT)],
        nonce: 50,
    };
    let tok = |r: &Rule| {
        let (l0, l1) = links(r);
        (token(&[&l0, &l1], &[]), l1.id())
    };
    let (requires, cosign, via) = (Err("condition not met: requires"), Err("condition not met: cosign"), Err("condition not met: via"));

    // "have you read the wechat chat before writing"
    let (w_tok, w_leaf) = tok(&wechat);
    let w = |nonce| Call { rule: &wechat, leaf: w_leaf, body: b"hello family", nonce };
    // "always verify the auth code and talk to this all through the same systems agent"
    let (d_tok, d_leaf) = tok(&door);
    let d = |nonce| Call { rule: &door, leaf: d_leaf, body: b"open door 2", nonce };
    let approved = |c: &Call| vec![cosigned(GUARDIAN, &c.request()), brokered(GUARDIAN, &c.request())];
    let door_1 = d(4).request_for(b"open door 1");
    // "always talk to this agent if you want to access the 3d printer"
    let (p_tok, p_leaf) = tok(&printer);
    let p = |nonce| Call { rule: &printer, leaf: p_leaf, body: b"print bracket.gcode", nonce };
    let other_job = p(3).request_for(b"print keys.gcode");
    // The printer chain whose leaf adds a condition of its own: the guardian co-signs too.
    let guarded = Rule { conds: vec![cosign_guardian(), printer.conds[0].clone()], nonce: 60, ..printer.clone() };
    let g_l0 = mint_root(&signer(LEIF), grant(&guarded, false, printer.conds.clone())).unwrap();
    let g_l1 = attenuate(&signer(WIN), &g_l0, grant(&guarded, true, guarded.conds.clone())).unwrap();
    let g = |nonce| Call { rule: &guarded, leaf: g_l1.id(), body: b"print bracket.gcode", nonce };
    let no_cells = Rule { cells: vec![], ..printer.clone() };

    vec![
        case("wechat-read-then-write", "12.4 the wechat cell attests the writer read thread 'family' through m42 two minutes ago; the send is allowed", &wechat, w_tok.clone(), Ok(()), vec![
            w(1).shows(vec![attested(WECHAT_CELL, WRITER, "family", NOW - 120)], Ok(())),
        ]),
        case("wechat-write-unread", "12.4 the same send refused: no request or proofs; no attestation; one 601 s old (limit 600); one of thread 'work'; one about planner, not the writer; one the writer signed itself; one dated 1 s ahead", &wechat, w_tok, Ok(()), vec![
            w(2).bare("condition not met: requires"),
            w(2).shows(vec![], requires),
            w(3).shows(vec![attested(WECHAT_CELL, WRITER, "family", NOW - 601)], requires),
            w(4).shows(vec![attested(WECHAT_CELL, WRITER, "work", NOW - 120)], requires),
            w(5).shows(vec![attested(WECHAT_CELL, WIN, "family", NOW - 120)], requires),
            w(6).shows(vec![attested(WRITER, WRITER, "family", NOW - 120)], requires),
            w(7).shows(vec![attested(WECHAT_CELL, WRITER, "family", NOW + 1)], requires),
        ]),
        case("guardian-approves-and-brokers", "12.4 the guardian (having checked the auth code) signs the exact request as co-signer and as broker; agent B passes, twice, each use with its own signatures", &door, d_tok.clone(), Ok(()), vec![
            d(1).shows(approved(&d(1)), Ok(())),
            d(2).shows(approved(&d(2)), Ok(())),
        ]),
        case("guardian-not-asked", "12.4 refused: no request or proofs; co-signed but not brokered; brokered but not co-signed; the guardian's signatures are for 'open door 1' and the request is 'open door 2'; the request claims the approved body but the node received another; agent B signs for the guardian itself; the request is 301 s old", &door, d_tok.clone(), Ok(()), vec![
            d(3).bare("condition not met: cosign"),
            d(3).shows(vec![cosigned(GUARDIAN, &d(3).request())], via),
            d(3).shows(vec![brokered(GUARDIAN, &d(3).request())], cosign),
            d(4).shows(vec![cosigned(GUARDIAN, &door_1), brokered(GUARDIAN, &door_1)], cosign),
            d(4).with(door_1.clone(), vec![cosigned(GUARDIAN, &door_1), brokered(GUARDIAN, &door_1)], Err("use request is not this use (body)")),
            d(5).shows(vec![cosigned(AGENT_B, &d(5).request()), brokered(AGENT_B, &d(5).request())], cosign),
            {
                let old = UseRequest { at: NOW - 301, ..d(6).request() };
                d(6).with(old.clone(), vec![cosigned(GUARDIAN, &old), brokered(GUARDIAN, &old)], Err("use request is outside the 300 s window"))
            },
        ]),
        case("guardian-approval-replayed", "12.4 one approved request presented twice: the second is a replay", &door, d_tok, Ok(()), vec![
            d(7).shows(approved(&d(7)), Ok(())),
            d(7).shows(approved(&d(7)), Err("request replayed")),
        ]),
        case("printer-through-its-agent", "12.4 the printer node trusts printer-agent for printer3d.gate; with its signed approval of this job the print is accepted", &printer, p_tok.clone(), Ok(()), vec![
            p(1).shows(vec![brokered(PRINTER_AGENT, &p(1).request())], Ok(())),
        ]),
        case("printer-around-its-agent", "12.4 refused: straight to the printer with no request or proofs; no approval; agent B approves itself; the agent's approval is for another job; the approval is offered as a co-signature", &printer, p_tok.clone(), Ok(()), vec![
            p(2).bare("condition not met: via"),
            p(2).shows(vec![], via),
            p(2).shows(vec![brokered(AGENT_B, &p(2).request())], via),
            p(3).shows(vec![brokered(PRINTER_AGENT, &other_job)], via),
            p(4).shows(vec![cosigned(PRINTER_AGENT, &p(4).request())], via),
        ]),
        case("printer-node-knows-no-agent", "12.4 a node that holds no key for printer3d.gate cannot tell who the broker is and refuses a correct approval", &no_cells, p_tok, Ok(()), vec![
            p(5).shows(vec![brokered(PRINTER_AGENT, &p(5).request())], via),
        ]),
        case("printer-child-adds-guardian", "12.4 planner's leaf adds CoSign(guardian) to Leif's Via: a child may add conditions; the print needs both and gets both; with the broker alone it is refused", &guarded, token(&[&g_l0, &g_l1], &[]), Ok(()), vec![
            g(1).shows(vec![brokered(PRINTER_AGENT, &g(1).request())], cosign),
            g(2).shows(vec![cosigned(GUARDIAN, &g(2).request()), brokered(PRINTER_AGENT, &g(2).request())], Ok(())),
        ]),
        case("wechat-child-drops-requires", "12.4 planner's leaf leaves out the Requires Leif set", &wechat, loosened(&wechat, vec![]), Err(BROADER), vec![]),
        case("wechat-child-loosens-freshness", "12.4 planner's leaf allows an attestation 3600 s old under Leif's 600 s", &wechat, loosened(&wechat, vec![read_family(3600)]), Err(BROADER), vec![]),
        case("guardian-child-drops-via", "12.4 planner's leaf keeps CoSign(guardian) and leaves out Via(guardian)", &door, loosened(&door, vec![cosign_guardian()]), Err(BROADER), vec![]),
        case("guardian-child-drops-cosign", "12.4 planner's leaf keeps Via(guardian) and leaves out CoSign(guardian)", &door, loosened(&door, vec![door.conds[1].clone()]), Err(BROADER), vec![]),
        case("printer-child-swaps-broker", "12.4 planner's leaf names agent B as the broker instead of the printer3d.gate cell", &printer, loosened(&printer, vec![Caveat::Via(vec![Party::Key(key(AGENT_B))])]), Err(BROADER), vec![]),
    ]
}
