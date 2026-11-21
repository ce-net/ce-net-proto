# CES-6: offers, orders and settlement (v0.1 draft)

Anyone may offer compute and anyone may buy it, with open formats so another party can run its own market. Units
are internal: this standard moves no money. Pay-in, pay-out, a price in a currency, tax and terms are outside it.

## 1. Types

```
Offer   { provider, what: { contract_hash? , class, cpu_max_pct, mem_bytes }, price: { per_cpu_s, per_gb_s,
          per_gb_egress, per_call }, region, valid_until_ms, sig }
Need    { class_at_least, mem_bytes, contract_hash?, region?, max_price_per_cpu_s? }
Lease   { id, offer, caller, spend_chain_hash, ttl_s, start_ms }
Balance { pair: (caller, provider), period, units_owed }
```

## 2. Spend is a capability

1. Spending is a capability on the ability `spend:unit` with a `uses` caveat `{ max, per }`: at most `max` units
   per lease (`per = "lease"`) or for the link's life (`per = "life"`).
2. **Attenuation.** A child link's `max` MUST be at most its parent's remaining units. A cell that sub-contracts
   hands down a smaller link; it never gets more.
3. **Every link is charged.** A use of `n` units at the executing node is charged to every link of the chain, leaf
   to root. If any link would go past its `max`, the whole charge is refused (`no_spend`) and nothing is charged.
   So a nested network cannot spend more than its caller granted, however deep it is (CES-8).
4. **Units.** One unit is `per_cpu_s` CPU-seconds and so on by the offer's prices, rounded up per record; a charge
   is computed from the CES-5 meter, never from the guest.

## 3. Offers and orders

1. An offer is signed by its provider and valid until `valid_until_ms`; an expired or unsigned offer is not found.
2. `Find(need)` answers offers whose class is at least the need's (`W` counts only for wasm needs), memory at
   least the need's, region and price within it, sorted by price per CPU-second, then by the provider's trust.
3. `Accept(offer, spend)` gives a lease when the spend link's remaining units are above 0 and it names the offer's
   provider; else `no_spend`.
4. **Settlement.** `Net(pair, period)` sums the units of that pair's receipts (CES-5) in the period, leaving out
   disputed ones. Balances are internal units.

## 4. Checks

| Check | Rule | Fails when |
|---|---|---|
| C6.1 | 2.2 | a child link with `max` above its parent's remaining verifies |
| C6.2 | 2.3 | a charge goes through that takes any link past its `max`, or a refused charge charged some link |
| C6.3 | 3.2 | `Find` answers an offer that does not meet the need, or out of order |
| C6.4 | 3.4 | `Net` counts a disputed receipt or misses an accepted one |

## 5. Conformance and vectors

`tests/ces6/spend.json`: `{name, chain, charges, expect}`: a chain of `max` values, a list of charges, and after
each the remaining units per link or `no_spend`. `tests/ces6/find.json`: `{name, offers, need, now_ms, expect}`.
The Rust crate reproduces them (`ce_net_proto::ces6`, `cargo test --test ces6`).
