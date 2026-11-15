use ce_net_proto::cal::{self, RefBook};
fn main() {
    let refs = RefBook::from_json(include_str!("cal.refs.json")).expect("ref book");
    let file = cal::parse(include_str!("raspberry-pi.cal")).unwrap_or_else(|e| panic!("{e}"));
    let mut nonce = || 0; // unused: every link of this file names its nonce
    let c = cal::compile(&file, &refs, &mut cal::Options { now: 0, nonce: &mut nonce, lenient: false }).unwrap_or_else(|e| panic!("{e}"));
    let mut labels = c.labels.clone();
    labels.learn(&c.links, &c.programs, &refs);
    print!("{}", cal::explain(&c.links, &c.programs, &labels));
}
