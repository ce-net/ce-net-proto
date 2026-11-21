# CES-5: run records and metering receipts (v0.1 draft)

Every call into a container (CES-4) or lease of one leaves a record the provider signs and the caller can check,
so use can be settled (CES-6) and disputed without trusting either side's word alone.

## 1. The run record

```
RunRecord {
  v: 1,
  image_digest, contract_hash,           // hex
  request_hash, answer_hash,             // SHA-256 of the exact bytes that crossed
  class: "W" | "I1" | "I2" | "I3",
  meter { cpu_usec, mem_peak, mem_byte_seconds, io_bytes, egress_bytes, wall_ms, calls },
  start_ms, end_ms,
  caller, provider,                      // hex Ed25519 public keys
  cap_chain_hash,                        // the spend chain the run was charged to
  parent,                                // hash of the provider's previous record for this caller, or 64 zeros
  evidence: "none" | "reexec:<record hash>" | "tee:<quote hash>",
}
```

The record's hash is SHA-256 over its canonical JSON: keys sorted, no whitespace, integers as integers. The
provider signs the hash with Ed25519 (`provider_sig`); the caller countersigns the same hash (`caller_sig`).

## 2. Rules

1. **Chained.** Records between one caller and one provider form a chain: each `parent` is the hash of the one
   before it (64 zeros for the first). A provider MUST NOT fork a chain; two records with the same parent are a
   fork and a strike.
2. **Measured by the node** (CES-3 rule 1). `meter` is read from the cgroup or the wasm store.
3. **Receipt.** A record with both signatures is a receipt. The caller countersigns or disputes within the window
   (default 86400 s after `end_ms`); after it, an uncountersigned record counts as accepted.
4. **Dispute.** A dispute names the record hash and a reason; a disputed record is not settled until resolved (a
   re-execution on a second node, `evidence = reexec`, or the two parties).
5. **Honest limits.** A node signature proves what the node claims, not what ran. Stronger evidence is the
   `evidence` field. Deterministic work is sampled for re-execution.
6. **Consistent.** `end_ms >= start_ms`; `wall_ms <= end_ms - start_ms + 1000`; a record whose meter exceeds the
   lease's limits is refused.

## 3. Checks

| Check | Rule | Fails when |
|---|---|---|
| C5.1 | 1 | a record's `parent` is not the hash of the previous record in its chain, or two records share a parent |
| C5.2 | 3 | `provider_sig` or `caller_sig` does not verify over the record hash |
| C5.3 | 6 | the times or meter are inconsistent |
| C5.4 | 3, 4 | a record is settled while disputed, or counted as accepted inside its window |

## 4. Conformance and vectors

`tests/ces5/records.json`: `{name, records, expect}`: each record with its hash and signatures, and `expect` the
verdict of C5.1 to C5.3 for the chain. Keys are fixed test seeds (stated in the file). The Rust crate reproduces
them (`ce_net_proto::ces5`, `cargo test --test ces5`).
