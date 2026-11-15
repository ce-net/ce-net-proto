//! Fixed keys, programs and the three chains of `docs/CAPABILITY-PROGRAMS.md` sections 12.1 to
//! 12.3, and the positive vectors built from them. Their refusals are in `negative.rs`; the
//! condition chains of section 12.5 (`Requires`, `CoSign`, `Via`) are in `conditions.rs`.

use ce_net_proto::Caveats;
use ce_net_proto::program::{EgressRule, EnvVar, Exe, Hash, HostPat, Limit, NodeKey, Program, Proto, ResourceV3, RunBox, RunMode, Step};
use ce_net_proto::v3::mint::{Grant, attenuate, mint_root};
use ce_net_proto::v3::sign::Signer;
use ce_net_proto::v3::{AudienceSet, CapabilityV3, Caveat, Delegate, Key, Link, Proof, TokenV3, UsePer, UseRequest};
use sha2::{Digest, Sha256};

/// The signing time `T` of section 12.
pub const T: u64 = 1_800_000_000;
pub const HOUR: u64 = 3_600;
pub const DAY: u64 = 86_400;

pub const LEIF: u8 = 0x11;
pub const WIN: u8 = 0x21;
pub const AGENT_B: u8 = 0x22;
pub const INSTALLER: u8 = 0x23;
pub const WRITER: u8 = 0x24;
pub const FRIEND: u8 = 0x31;
pub const FRIEND_AGENT: u8 = 0x32;
pub const PROCESS: u8 = 0x33;
pub const PI: u8 = 0x41;
pub const BOX: u8 = 0x42;
pub const DESK: u8 = 0x43;
pub const MAC: u8 = 0x44;
pub const PRINTER: u8 = 0x45;
pub const GUARDIAN: u8 = 0x51;
pub const PRINTER_AGENT: u8 = 0x52;
pub const WECHAT_CELL: u8 = 0x53;

/// Every test key: name and seed byte (the secret is 32 copies of it; `LEIF` is P-256).
pub const KEYS: &[(&str, u8)] = &[
    ("leif-iphone", LEIF),
    ("planner", WIN),
    ("agent-b", AGENT_B),
    ("installer-lane", INSTALLER),
    ("writer-agent", WRITER),
    ("friend", FRIEND),
    ("friend-agent", FRIEND_AGENT),
    ("process-k", PROCESS),
    ("pi-01", PI),
    ("box-1", BOX),
    ("leif-desk", DESK),
    ("macbook", MAC),
    ("printer-1", PRINTER),
    ("system-guardian", GUARDIAN),
    ("printer-agent", PRINTER_AGENT),
    ("wechat.read", WECHAT_CELL),
];

pub fn signer(seed: u8) -> Signer {
    if seed == LEIF { Signer::p256(&[seed; 32]).unwrap() } else { Signer::ed25519(&[seed; 32]) }
}

pub fn key(seed: u8) -> Key {
    signer(seed).key()
}

pub fn node(seed: u8) -> NodeKey {
    match key(seed) {
        Key::Ed25519(k) => k,
        Key::P256(_) => unreachable!("nodes are Ed25519"),
    }
}

pub fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

pub fn sha(b: &[u8]) -> Hash {
    Sha256::digest(b).into()
}

/// The node a use arrives at.
#[derive(Clone, Copy)]
pub struct At {
    pub seed: u8,
    pub host: &'static str,
}
pub const AT_PI: At = At { seed: PI, host: "pi-01" };
pub const AT_BOX: At = At { seed: BOX, host: "box-1" };
pub const AT_DESK: At = At { seed: DESK, host: "leif-desk" };
pub const AT_MAC: At = At { seed: MAC, host: "macbook" };
pub const AT_PRINTER: At = At { seed: PRINTER, host: "printer-1" };

pub enum Req {
    Call(&'static str),
    Exec { program: Hash, run: u32, step: u32, req: Step },
}

/// What a use presents beside its token (section 4.1): its exact request, the proofs, and the
/// body bytes the node received (the node hashes them itself).
pub struct Shown {
    pub request: UseRequest,
    pub proofs: Vec<Proof>,
    pub body: Vec<u8>,
}

/// One request, in order, against the node's burn log and replay log; `token` overrides the
/// vector's. Without `shown` it goes to `authorize_v3`, with it to `authorize_use_v3`.
pub struct Use {
    pub at: At,
    pub requester: u8,
    pub token: Option<Vec<u8>>,
    pub req: Req,
    pub shown: Option<Shown>,
    /// `Err(s)`: the refusal contains `s`.
    pub want: Result<(), &'static str>,
}

pub struct Case {
    pub name: &'static str,
    pub note: &'static str,
    pub token: Vec<u8>,
    pub now: u64,
    /// The keys the executing nodes trust per cell api (`Party::Cell`): `(api, key seed)`.
    pub cells: Vec<(&'static str, u8)>,
    /// Decode then `verify_chain_v3`: the first failure.
    pub verify: Result<(), &'static str>,
    pub uses: Vec<Use>,
}

pub fn exec(p: &Program, run: u32, step: u32) -> Req {
    Req::Exec { program: p.id(), run, step, req: p.steps[step as usize].clone() }
}

/// `cap` (changed by `f`) signed by `s` as is, without the minter's checks.
pub fn resign(s: &Signer, l: &Link, f: impl FnOnce(&mut CapabilityV3)) -> Link {
    let Link::V3 { cap, .. } = l else { panic!("v3 link expected") };
    let mut cap = cap.clone();
    f(&mut cap);
    Link::V3 { sig: s.sign(&cap), cap }
}

pub fn token(links: &[&Link], programs: &[&Program]) -> Vec<u8> {
    TokenV3 { links: links.iter().map(|l| (*l).clone()).collect(), programs: programs.iter().map(|p| (*p).clone()).collect() }.encode()
}

// ---- 12.1 The Raspberry Pi

pub const PI_SCRIPT: &[u8] = b"print('hello from pi-01')\n";

pub fn pi_program() -> Program {
    Program::new(vec![Step::Install { on: node(PI), path: "/opt/x/run.py".into(), sha256: sha(PI_SCRIPT), size: PI_SCRIPT.len() as u64, mode: 0o755 }])
}

/// `[L0, L1]`: Leif -> planner (may grant, may not use) -> agent B (may install once).
pub fn pi_links() -> (Link, Link) {
    let ext = vec![Caveat::Uses { max: 1, per: UsePer::Link }, Caveat::Programs(vec![pi_program().id()])];
    let pre = || Some("/opt/x".to_string());
    let l0 = mint_root(&signer(LEIF), Grant {
        audience: key(WIN),
        abilities: vec![],
        resource: ResourceV3::Node(node(PI)),
        caveats: Caveats { not_after: T + 7 * DAY, path_prefix: pre(), ..Caveats::default() },
        ext: ext.clone(),
        delegate: Some(Delegate { abilities: s(&["cell.install:install-file"]), audience: AudienceSet::Any, depth: 1 }),
        nonce: 1,
    })
    .unwrap();
    let l1 = attenuate(&signer(WIN), &l0, Grant {
        audience: key(AGENT_B),
        abilities: s(&["cell.install:install-file"]),
        resource: ResourceV3::Node(node(PI)),
        caveats: Caveats { not_after: T + DAY, path_prefix: pre(), ..Caveats::default() },
        ext,
        delegate: None,
        nonce: 2,
    })
    .unwrap();
    (l0, l1)
}

pub fn pi_token() -> Vec<u8> {
    let (l0, l1) = pi_links();
    token(&[&l0, &l1], &[&pi_program()])
}

// ---- 12.2 The long chain

pub fn job_program() -> Program {
    let job = b"import urllib.request\nurllib.request.urlopen('https://api.example.org/')\n";
    Program::new(vec![
        Step::Install { on: node(BOX), path: "/srv/jobs/f/job.py".into(), sha256: sha(job), size: job.len() as u64, mode: 0o755 },
        Step::Run {
            on: ResourceV3::Node(node(BOX)),
            exe: Exe::Output(0),
            argv: s(&["job.py"]),
            env: Vec::<EnvVar>::new(),
            cwd: "/srv/jobs/f".into(),
            mode: RunMode::Once,
            sandbox: RunBox {
                cpu: 1,
                mem_mb: 512,
                wall_s: 600,
                read: vec![],
                write: s(&["/srv/jobs/f/out"]),
                egress: vec![api_rule()],
                bytes_out: 10_000_000,
                bytes_in: 100_000_000,
            },
        },
    ])
}

pub fn api_rule() -> EgressRule {
    EgressRule { host: HostPat::Name("api.example.org".into()), ports: vec![443], proto: Proto::Tcp }
}

pub fn limits(bytes_in: u64, bytes_out: u64, wall_s: u64) -> Caveat {
    let l = |n: &str, max| Limit { name: n.into(), max };
    Caveat::Limits(vec![l("net.egress.bytes_in", bytes_in), l("net.egress.bytes_out", bytes_out), l("proc.spawn.wall_s", wall_s)])
}

/// `[L0, L1, L2]`: Leif -> friend -> friend's agent -> process key K.
pub fn long_links() -> [Link; 3] {
    let pre = || Some("/srv/jobs/f".to_string());
    let suffix = EgressRule { host: HostPat::Suffix(".example.org".into()), ports: vec![443], proto: Proto::Tcp };
    let l0 = mint_root(&signer(LEIF), Grant {
        audience: key(FRIEND),
        abilities: vec![],
        resource: ResourceV3::Node(node(BOX)),
        caveats: Caveats { not_after: T + DAY, max_cpu: Some(2), max_mem_mb: Some(1024), path_prefix: pre(), ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 5, per: UsePer::Link }, limits(500_000_000, 50_000_000, 3600), Caveat::Egress(vec![suffix])],
        delegate: Some(Delegate {
            abilities: s(&["cell.install:install-file", "net.egress:connect", "proc.spawn:run"]),
            audience: AudienceSet::Any,
            depth: 2,
        }),
        nonce: 10,
    })
    .unwrap();
    let caveats = Caveats { not_after: T + 12 * HOUR, max_cpu: Some(1), max_mem_mb: Some(512), path_prefix: pre(), ..Caveats::default() };
    let ext1 = vec![Caveat::Uses { max: 2, per: UsePer::Link }, limits(100_000_000, 10_000_000, 600), Caveat::Egress(vec![api_rule()])];
    let l1 = attenuate(&signer(FRIEND), &l0, Grant {
        audience: key(FRIEND_AGENT),
        abilities: s(&["cell.install:install-file", "proc.spawn:run"]),
        resource: ResourceV3::Node(node(BOX)),
        caveats: caveats.clone(),
        ext: ext1.clone(),
        delegate: Some(Delegate { abilities: s(&["net.egress:connect"]), audience: AudienceSet::Any, depth: 1 }),
        nonce: 11,
    })
    .unwrap();
    let mut ext2 = ext1;
    ext2.push(Caveat::Programs(vec![job_program().id()]));
    let l2 = attenuate(&signer(FRIEND_AGENT), &l1, Grant {
        audience: key(PROCESS),
        abilities: s(&["net.egress:connect"]),
        resource: ResourceV3::Node(node(BOX)),
        caveats,
        ext: ext2,
        delegate: None,
        nonce: 12,
    })
    .unwrap();
    [l0, l1, l2]
}

// ---- 12.3 First real use

pub const CELLS: &[&str] = &["feed.att", "feed.view", "talk.messages"];

pub fn first_root() -> Link {
    let mut nodes = vec![node(DESK), node(MAC)];
    nodes.sort();
    let mut abilities = s(&["cell.install:install", "cell.install:manage"]);
    for verb in ["install", "manage"] {
        for api in CELLS {
            for host in [AT_DESK.host, AT_MAC.host] {
                abilities.push(format!("cell.install:{verb}:{api}@{host}"));
            }
        }
    }
    mint_root(&signer(LEIF), Grant {
        audience: key(WIN),
        abilities: vec![],
        resource: ResourceV3::Nodes(nodes),
        caveats: Caveats { not_after: T + 7 * DAY, ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 1, per: UsePer::Action }],
        delegate: Some(Delegate { abilities, audience: AudienceSet::Any, depth: 1 }),
        nonce: 20,
    })
    .unwrap()
}

pub fn cell_program(api: &str, at: At) -> Program {
    Program::new(vec![Step::InstallCell { on: node(at.seed), verb: "install".into(), api: api.into(), build: sha(format!("{api} build 1").as_bytes()) }])
}

/// planner's leaf to the installer lane for one install of `api` at `at`.
pub fn first_leaf(root: &Link, api: &str, at: At, nonce: u64) -> (Link, Program) {
    let p = cell_program(api, at);
    let leaf = attenuate(&signer(WIN), root, Grant {
        audience: key(INSTALLER),
        abilities: vec!["cell.install:install".into(), format!("cell.install:install:{api}@{}", at.host)],
        resource: ResourceV3::Node(node(at.seed)),
        caveats: Caveats { not_after: T + HOUR, ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 1, per: UsePer::Action }, Caveat::Programs(vec![p.id()])],
        delegate: None,
        nonce,
    })
    .unwrap();
    (leaf, p)
}

pub fn positive() -> Vec<Case> {
    let now = T + 60;
    let pi = pi_program();
    let job = job_program();
    let [l0, l1, l2] = long_links();
    let root = first_root();
    let mut installs = Vec::new();
    let mut nonce = 100;
    for api in CELLS {
        for at in [AT_DESK, AT_MAC] {
            let (leaf, p) = first_leaf(&root, api, at, nonce);
            nonce += 1;
            installs.push(Use { at, shown: None, requester: INSTALLER, token: Some(token(&[&root, &leaf], &[&p])), req: exec(&p, 1, 0), want: Ok(()) });
        }
    }
    let (again, p_again) = first_leaf(&root, "talk.messages", AT_DESK, 200);
    installs.push(Use {
        at: AT_DESK,
        shown: None, requester: INSTALLER,
        token: Some(token(&[&root, &again], &[&p_again])),
        req: exec(&p_again, 1, 0),
        want: Err("capability used up"),
    });
    let (desk_leaf, desk_p) = first_leaf(&root, "talk.messages", AT_DESK, 104);
    let agent = |run, step, want| Use { at: AT_BOX, shown: None, requester: FRIEND_AGENT, token: None, req: exec(&job, run, step), want };
    vec![
        Case {
            name: "pi-install-once",
            note: "12.1: agent B installs the one hashed script on pi-01 (L0 and L1 Uses 1 per Link burn)",
            token: pi_token(),
            now,
            cells: vec![], verify: Ok(()),
            uses: vec![Use { at: AT_PI, shown: None, requester: AGENT_B, token: None, req: exec(&pi, 1, 0), want: Ok(()) }],
        },
        Case {
            name: "long-agent-runs-twice",
            note: "12.2 [L0, L1]: the friend's agent installs and runs job.py in run 1 and run 2; run 3 exceeds L1's Uses 2",
            token: token(&[&l0, &l1], &[&job]),
            now,
            cells: vec![], verify: Ok(()),
            uses: vec![agent(1, 0, Ok(())), agent(1, 1, Ok(())), agent(2, 0, Ok(())), agent(3, 0, Err("capability used up"))],
        },
        Case {
            name: "long-process-key",
            note: "12.2 [L0, L1, L2]: the chain verifies with holder K and the Egress, Limits and Programs K's sandbox enforces; K itself may not install or spawn",
            token: token(&[&l0, &l1, &l2], &[&job]),
            now,
            cells: vec![], verify: Ok(()),
            uses: vec![
                Use { at: AT_BOX, shown: None, requester: PROCESS, token: None, req: exec(&job, 1, 1), want: Err("the capability does not grant") },
                Use { at: AT_BOX, shown: None, requester: PROCESS, token: None, req: Req::Call("net.egress:connect"), want: Err("capability is bound to a program") },
            ],
        },
        Case {
            name: "first-use-six-installs",
            note: "12.3: each of the six install rights once, each through its own leaf; a seventh leaf for talk.messages@leif-desk is refused by L0's counter",
            token: token(&[&root, &desk_leaf], &[&desk_p]),
            now,
            cells: vec![], verify: Ok(()),
            uses: installs,
        },
    ]
}
