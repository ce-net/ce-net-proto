//! The wasm-bindgen face of CAL: one function, `call(op, requestJson) -> responseJson`, the same
//! JSON API as every other SDK (`ce_net_proto::cal::api`). `ce-cal.ts` wraps it in typed calls.

use wasm_bindgen::prelude::*;

/// Run one CAL op (`parse`, `compile`, `sign`, `explain`, `decompile`, `verify`) on a JSON request.
#[wasm_bindgen]
pub fn call(op: &str, request: &str) -> String {
    ce_net_proto::cal::api::call(op, request)
}
