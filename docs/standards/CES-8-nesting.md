# CES-8: nested cells and recursive capabilities (v0.1 draft)

A cell may hold a box, the box holds an inner door and inner cells, and an inner cell may itself hold a box.
From outside, a holder is an ordinary cell with a typed contract. This standard says how a capability crosses
each boundary so that it only ever narrows, whatever the depth.

## 1. Model

- **Box instance path.** Each box instance has an id; a box inside a box is named by its path from the
  outermost one: `a7`, then `a7/b2`.
- **Inner door.** A door started inside the box with its own key, made for that instance. Its only route out is
  the box's socket to the outer door. It carries one tag per prefix of its path: `box:a7`, `box:a7/b2`.
- **Names.** Inner cells are addressed `cell:<holder>/<inner>`. A path does not resolve outside the holder.
- **Export.** `[box.export]` in the holder's `cell.toml` lists the holder's own ops; callers anywhere call those
  and nothing else. `[box.export.<Op>] inner = [...]` lists the abilities the inner network needs for that op.
- **Uplink.** `[box.uplink]` lists the outside abilities inner cells may use. Anything else from inside is
  refused at the inner door.

## 2. A capability crossing a boundary

The holder is the audience of its caller's chain. To act inside, it adds a cap v3 link
([CAPABILITY-PROGRAMS.md](../CAPABILITY-PROGRAMS.md)) to the inner door's key. Cap v3 already makes every link
equal or narrower (abilities, audience, resource, caveats) and drops `delegate.depth` by at least one. CES-8
adds:

| Rule | MUST |
|---|---|
| B1 scope | A link entering box `P` carries `resource = AllOf(box tags of P)`. It enters at most one box deeper than its parent link, inside the parent's box; a later link never leaves a box. |
| B2 exact box | The leaf is scoped to exactly the box of the door checking it. A link made for an outer box is not used inside an inner one, and by B1 plus cap v3 resource matching a link replayed in another instance of the box fails. |
| B3 time | A link entering a box has an expiry. Cap v3 already keeps it at most the parent's; a per-call link SHOULD expire at the call's deadline. |
| B4 depth | `delegate.depth` drops at each boundary (cap v3 does this on every link). |
| B5 nesting | A node refuses a box path deeper than its `nest_max` (default 4). |
| B6 rights | A link entering box `P` lists only abilities (its own and its `delegate.abilities`) that the holder declared for the op in `[box.export.<Op>] inner`. |

Also, outside what a token can show:

- **Budget.** A child box's CES-1 `[budget]` MUST fit inside its parent's (cgroups nest, so the runtime enforces it).
- **Revocation and stop.** Revoking any link voids everything below it. Stopping a holder kills its cgroup, so
  every level below it ends.
- **Calls.** `hops_left` and the deadline (CES-1 rule 6) cross boundaries unchanged, so recursion cannot loop.
- **Isolation.** The strongest isolation is needed once, at the outermost boundary where a stranger's code
  begins; boxes inside it may use a lighter class.

## 3. What an inner door runs

`ce_net_proto::ces8::authorize_inner(door_key, door_path, roots, now, requester, ability, token, nest_max, declared)`:
cap v3 `authorize_v3` at a node whose tags are the box tags of `door_path`, then `check_boundaries` (B1, B2,
B3, B5, B6). A refusal names its rule (`CES-8 B2: ...`) or is the cap v3 reason.

## 4. Example

```
Leif            -> nest.outer   abilities: -            may grant notes.app:add, notes.app:list, calc.exec:eval, net:connect  depth 4  until T
nest.outer      -> door a7      scope box:a7            may grant notes.app:add, calc.exec:eval                                depth 3  until T-100
door a7         -> calc.run     scope box:a7            may grant calc.exec:eval                                               depth 2  until T-200
calc.run        -> door a7/b2   scope box:a7, box:a7/b2 may grant calc.exec:eval                                               depth 1  until T-300
door a7/b2      -> calc.exec    scope box:a7, box:a7/b2 abilities: calc.exec:eval                                                       until T-400
```

At each boundary the rights, depth and expiry shrink and the scope gets one box deeper.

## 5. Conformance

`tests/ces8/vectors.json` holds chains across one and two boundaries that MUST pass and chains that MUST fail,
each with its outcome: `pass`, `v3` (cap v3 refuses it), or the CES-8 rule `B1` to `B6`. The cases: a wider
right below, no box scope, a later expiry below, depth not reduced, a token replayed in another box instance, an
outer box's link used inside an inner box, one link jumping two boundaries, a boundary link with no expiry, a
path deeper than `nest_max`, a right not declared for the op, and the same right declared. A checker conforms
when it reproduces every outcome. `cargo test --test ces8_vectors` regenerates the vectors in memory, compares
them with the file, and re-runs each from the file alone.

Status: one implementation (Rust). A second, independent checker is needed before v1 (CES-0 rule 6).
