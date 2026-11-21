# CES-4: the cell container (v0.1 draft)

A node may run code it did not write, including a stranger's, as a cell. The container is not a new sandbox: it
is the cell contract (a typed boundary, a capability chain, a CES-1 budget) put around runtimes that exist. The
only thing that crosses the boundary is a typed call. There is no shell op and no command execution.

## 1. Isolation classes

| Class | Mechanism | For |
|---|---|---|
| `W` | WebAssembly: fuel-metered, memory-capped, imports only from the contract's host functions | pure functions; anyone |
| `I1` | user, mount, pid, net and ipc namespaces; read-only image by digest; tmpfs; one data volume; seccomp allow list; Landlock; `no_new_privs`; a cgroup v2 leaf | code whose author holds a grant from the node owner |
| `I2` | `I1` plus a user-space kernel (gVisor or equal) | native strangers' code where there is no KVM |
| `I3` | a microVM (Firecracker, Cloud Hypervisor, Apple Virtualization) | native strangers' code where KVM exists |

A node advertises the classes it has. Its owner sets a policy (section 3).

## 2. Rules

1. **Class by signer.** The image's signer decides the class. An author holding a grant from the node owner MAY
   run at `I1`. Anyone else is a stranger: a wasm image runs at `W`, a native image at `I2` or `I3`.
2. **Fail closed.** A node without the class a launch needs MUST refuse it (`no_isolation_class`, naming the class
   wanted and the classes it has). It MUST NOT run the code one class down. A caller MAY ask for a stronger class
   than the rule needs; never a weaker one.
3. **Policy.** A launch the owner's policy does not allow is refused (`policy_refused`). The policy holds: the
   classes allowed, whether strangers may run at all, and the share of the machine strangers may use (default 25%
   of CPU, 25% of memory). On a node whose owner has not said yes, `strangers = false`.
4. **Touch nothing of the host.** Files: the image, read-only, by content hash; one data volume within
   `disk_bytes`. Network: none, except a socket to the door; egress only as a call to an egress capability naming
   host and port. Secrets: never inside; the keys cell does the operation, or gives a short-lived token bound to
   the box instance.
5. **Budget.** The box is one cgroup (or the wasm store's fuel and memory). CES-1 numbers are hard there: a fork
   bomb meets `pids`, a leak meets `mem_bytes`, a spin meets fuel or `cpu_max_pct` and the lease `ttl_s`.
6. **Typed boundary.** The runtime checks every request and every answer against the contract's schema, its size
   limit and its deadline before it crosses. An answer off the contract fails the call (`off_contract`) and is a
   strike against the image.
7. **Screening.** Before a stranger's launch the runtime runs its screen (known-bad digests, strikes, an image
   refused node-wide after an escape attempt). A refused image is `image_refused` with its strike count.
8. **Paid by the caller.** Every stranger's launch carries a spend capability (CES-6); none is `no_spend`.
9. **Metering from outside** (CES-3): `cpu_usec`, `mem_peak`, `mem_byte_seconds`, `io_bytes`, `egress_bytes`,
   `wall_ms`, `calls`, read from the cgroup or the wasm store, never from the guest.

## 3. Types

```
Class = W | I1 | I2 | I3                          (ordered by strength: W and I1 below I2 below I3; W is its own kind)
Image  { digest, kind: wasm | native, signer, size }
Policy { classes: [Class], strangers: bool, cpu_share_pct, mem_share_pct }
Launch { image, granted_author: bool, wanted: Option<Class>, has_spend: bool, strikes: u32 }
BoxError = no_isolation_class { wanted, node_has } | policy_refused(why) | image_refused(strikes)
         | over_budget(cpu | mem | pids | wall) | off_contract { op, why } | no_spend | expired | guard(why)
```

`choose(launch, node_classes, policy) -> Class | BoxError` is section 2 rules 1 to 3, 7 and 8 in this order:
`no_spend`, `image_refused` (strikes at or above 3), `policy_refused`, `no_isolation_class`. The class chosen is
the weakest the rules allow that the node has and the policy allows: `W` for wasm, `I1` for a granted native image,
else `I2`, else `I3`. A wasm image is never run natively.

## 4. Checks

| Check | Rule | Fails when |
|---|---|---|
| C4.1 | 1, 2 | a launch runs at a class the signer rule does not allow, or one class down |
| C4.2 | 3 | a launch the policy refuses runs |
| C4.3 | 5 | a box exceeds `pids`, `mem_bytes`, fuel or `ttl_s` and the call does not end in `over_budget` |
| C4.4 | 6 | an answer off the schema, over size or past the deadline reaches the caller |
| C4.5 | 4 | a box reads a host path, opens a socket other than the door's, or reads a secret |
| C4.6 | 8 | a stranger's launch without spend runs |

## 5. Conformance and vectors

`tests/ces4/choose.json`: `{name, launch, node, policy, expect}`, `expect` a class or `{"error": kind}`.
`tests/ces4/boundary.json`: `{name, limits, answer, expect}` for rule 6 (size, deadline, schema flag).
The Rust crate reproduces them (`ce_net_proto::ces4`, `cargo test --test ces4`). C4.3 and C4.5 are checked by
hostile images run against a real runtime (the five images of the cell.box proof).
