# CES-7: wrapped software (v0.1 draft)

An existing program, written with no knowledge of ce-net, becomes one cell or a few, with no hand-written code. A
wrapped cell keeps CES-1 and CES-2 by construction: nobody calling it means no process.

## 1. Three steps

1. **Detect.** The program runs once in an `I1` box (CES-4) in report mode. The wrapper records `wrap.toml`: the
   ports it listens on and what speaks there (HTTP with or without OpenAPI, gRPC reflection, MCP, a database
   wire), CLI subcommands and flags from `--help`, files and folders written, environment read, egress attempted,
   resident memory, idle CPU and wake-ups.
2. **Plan.** `wrap.toml` becomes cells: one for a small program, or one per surface (a port, a CLI command group,
   the data folder). Each gets a generated typed contract, one right per op, a `[budget]` from the measured run,
   its egress as explicit capabilities, and its isolation class.
3. **Up.** The cells are installed and started through the runtime. The adapter lives in the runtime: started on
   the first call, stopped when idle, connections reused, retries backed off.

## 2. Rules

1. **Rights from verbs.** An op is `read` when its HTTP method is `GET`, `HEAD` or `OPTIONS`, or its CLI command is
   one of `list`, `ls`, `show`, `get`, `status`, `info`, `version`, `help`, `search`, `cat`, `describe`; otherwise
   `write`. The right is `<api>:<read|write>`. A plan MUST NOT give one right to every op.
2. **Budget from the run.** `[budget]` is the measured idle numbers rounded up to the next CES-1 step (`0.1`,
   `0.2`, `0.5` for CPU; `1`, `2`, `5`, `10` for wake-ups; a power of two MB for memory, at least 64M), each above
   the default with the reason "measured by ce-wrap detect". A program measured above the hard limits is not
   wrapped as idle-stoppable: `up` refuses it with the numbers.
3. **Egress.** Every host and port the detect run tried becomes an egress capability the owner must grant; none is
   granted by the plan.
4. **Zero at rest.** A wrapped cell MUST have no process while nobody calls it, and MUST pass CES-2 C2.1 and C2.2.
5. **Names.** Generated op names are `UpperCamel` of the path or command (`GET /users/{id}` to `GetUsersId`); two
   ops with one name get `_2`, `_3`.

## 3. Checks

| Check | Rule | Fails when |
|---|---|---|
| C7.1 | 1, 5 | an op's right or name differs from the rule |
| C7.2 | 2 | the planned `[budget]` is not the measured value rounded up, or fails CES-1 C1.1 |
| C7.3 | 3 | the plan grants egress |
| C7.4 | 4 | a wrapped cell has a process with nobody calling, or fails C2.1 or C2.2 |

## 4. Conformance and vectors

`tests/ces7/plan.json`: `{name, detect, expect}`: a `wrap.toml` detect record and the planned ops (name, right)
and `[budget]`. The Rust crate reproduces them (`ce_net_proto::ces7`, `cargo test --test ces7`).
