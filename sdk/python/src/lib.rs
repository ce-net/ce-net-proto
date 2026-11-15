//! CAL behind a C ABI: `ce_cal_call(op, request_json)` returns a newly allocated JSON string that
//! the caller frees with `ce_cal_free`. The JSON API is `ce_net_proto::cal::api`'s, the same in
//! every SDK. Both arguments are NUL-terminated UTF-8.
//!
//! ```c
//! char *ce_cal_call(const char *op, const char *request_json);
//! void ce_cal_free(char *response);
//! ```

use std::ffi::{CStr, CString, c_char};

fn text(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller passes a valid NUL-terminated string (the documented contract).
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(str::to_string)
}

/// Run one CAL op on a JSON request; the answer is JSON. Free it with [`ce_cal_free`].
#[unsafe(no_mangle)]
pub extern "C" fn ce_cal_call(op: *const c_char, request: *const c_char) -> *mut c_char {
    let out = match (text(op), text(request)) {
        (Some(op), Some(req)) => ce_net_proto::cal::api::call(&op, &req),
        _ => r#"{"ok":false,"error":{"line":0,"message":"op and request must be UTF-8 C strings","suggestion":null}}"#.to_string(),
    };
    CString::new(out).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// Free a string returned by [`ce_cal_call`].
#[unsafe(no_mangle)]
pub extern "C" fn ce_cal_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: `s` came from `CString::into_raw` in `ce_cal_call` and is freed once.
        drop(unsafe { CString::from_raw(s) });
    }
}
