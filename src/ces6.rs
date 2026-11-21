//! CES-6 v0.1, offers, orders and settlement in internal units (docs/standards/CES-6-market.md).
//!
//! - [`Spend`]: a spend chain, root first; [`Spend::delegate`] (rule 2.2) and [`Spend::charge`] (rule 2.3: every
//!   link is charged, all or nothing).
//! - [`find`]: rule 3.2. [`net`]: rule 3.4.
use crate::ces4::Class;
use serde::{Deserialize, Serialize};

/// One link of a spend chain: its `max` and what it has spent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub max: u64,
    #[serde(default)]
    pub spent: u64,
}

impl Link {
    pub fn left(&self) -> u64 {
        self.max.saturating_sub(self.spent)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendError {
    /// Rule 2.2: a child asked more than its parent has left.
    Widen,
    /// Rule 2.3: a charge would take a link past its max.
    NoSpend,
}

/// A spend chain, root (the caller's grant) first, the executing link last.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spend {
    pub links: Vec<Link>,
}

impl Spend {
    pub fn root(max: u64) -> Spend {
        Spend { links: vec![Link { max, spent: 0 }] }
    }

    /// Rule 2.2: hand down a link of at most what the last link has left. The new chain shares the ancestors'
    /// counters through the caller keeping one `Spend`; [`Spend::charge`] on it charges every link.
    pub fn delegate(&mut self, max: u64) -> Result<(), SpendError> {
        let left = self.links.last().map(Link::left).unwrap_or(0);
        if max > left {
            return Err(SpendError::Widen);
        }
        self.links.push(Link { max, spent: 0 });
        Ok(())
    }

    /// Rule 2.3 at depth `at` (the index of the executing link): charge `n` to it and every link above, or nothing.
    pub fn charge_at(&mut self, at: usize, n: u64) -> Result<(), SpendError> {
        if at >= self.links.len() || self.links[..=at].iter().any(|l| l.left() < n) {
            return Err(SpendError::NoSpend);
        }
        for l in &mut self.links[..=at] {
            l.spent += n;
        }
        Ok(())
    }

    /// [`Spend::charge_at`] the last link.
    pub fn charge(&mut self, n: u64) -> Result<(), SpendError> {
        self.charge_at(self.links.len().saturating_sub(1), n)
    }

    /// Ends the deepest link (a sub-contract finished); its spend stays charged to its ancestors.
    pub fn pop(&mut self) {
        if self.links.len() > 1 {
            self.links.pop();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Price {
    pub per_cpu_s: f64,
    #[serde(default)]
    pub per_gb_s: f64,
    #[serde(default)]
    pub per_gb_egress: f64,
    #[serde(default)]
    pub per_call: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Offer {
    pub id: String,
    pub provider: String,
    pub class: Class,
    pub mem_bytes: u64,
    pub price: Price,
    #[serde(default)]
    pub region: String,
    pub valid_until_ms: u64,
    #[serde(default)]
    pub signed: bool,
    /// The provider's trust score (higher first on a price tie).
    #[serde(default)]
    pub trust: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Need {
    pub class_at_least: Class,
    pub mem_bytes: u64,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub max_price_per_cpu_s: Option<f64>,
}

fn rank(c: Class) -> u8 {
    match c {
        Class::W => 0,
        Class::I1 => 1,
        Class::I2 => 2,
        Class::I3 => 3,
    }
}

/// Rule 3.2: a W need is met only by W offers; a native need by any native class at least as strong.
fn class_meets(offer: Class, need: Class) -> bool {
    if need == Class::W || offer == Class::W {
        return offer == need;
    }
    rank(offer) >= rank(need)
}

/// Rule 3.1 and 3.2: the offers meeting the need at `now_ms`, cheapest first, then by trust, then by id.
pub fn find<'a>(offers: &'a [Offer], need: &Need, now_ms: u64) -> Vec<&'a Offer> {
    let mut v: Vec<&Offer> = offers
        .iter()
        .filter(|o| o.signed && o.valid_until_ms > now_ms)
        .filter(|o| class_meets(o.class, need.class_at_least) && o.mem_bytes >= need.mem_bytes)
        .filter(|o| need.region.as_ref().is_none_or(|r| &o.region == r))
        .filter(|o| need.max_price_per_cpu_s.is_none_or(|m| o.price.per_cpu_s <= m))
        .collect();
    v.sort_by(|a, b| {
        a.price.per_cpu_s.partial_cmp(&b.price.per_cpu_s).unwrap_or(std::cmp::Ordering::Equal).then(b.trust.partial_cmp(&a.trust).unwrap_or(std::cmp::Ordering::Equal)).then(a.id.cmp(&b.id))
    });
    v
}

/// Rule 2.4: units of one run from its meter and the offer's prices, rounded up.
pub fn units(price: &Price, cpu_usec: u64, mem_byte_seconds: u64, egress_bytes: u64, calls: u64) -> u64 {
    let gb = (1u64 << 30) as f64;
    let u = cpu_usec as f64 / 1e6 * price.per_cpu_s + mem_byte_seconds as f64 / gb * price.per_gb_s + egress_bytes as f64 / gb * price.per_gb_egress + calls as f64 * price.per_call;
    u.ceil().max(0.0) as u64
}

/// One receipt as settlement sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub caller: String,
    pub provider: String,
    pub at_ms: u64,
    pub units: u64,
    #[serde(default)]
    pub accepted: bool,
    #[serde(default)]
    pub disputed: bool,
}

/// Rule 3.4: units the caller owes the provider for receipts in `[from_ms, to_ms)`, accepted and not disputed.
pub fn net(entries: &[Entry], caller: &str, provider: &str, from_ms: u64, to_ms: u64) -> u64 {
    entries.iter().filter(|e| e.caller == caller && e.provider == provider && e.at_ms >= from_ms && e.at_ms < to_ms && e.accepted && !e.disputed).map(|e| e.units).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nested_network_cannot_spend_more_than_its_caller_granted() {
        let mut s = Spend::root(1000);
        s.charge(600).unwrap();
        assert_eq!(s.delegate(500), Err(SpendError::Widen));
        s.delegate(300).unwrap();
        s.charge(300).unwrap();
        assert_eq!(s.charge(1), Err(SpendError::NoSpend));
        s.pop();
        assert_eq!(s.links[0].left(), 100);
        assert_eq!(s.charge(101), Err(SpendError::NoSpend));
        s.charge(100).unwrap();
    }
}
