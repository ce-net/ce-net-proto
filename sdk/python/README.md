# ce-cal C ABI (for Python and any C FFI)

CAL (the cell auth language, [`docs/CAL.md`](../../docs/CAL.md)) behind a C ABI
([`ce_cal.h`](ce_cal.h)): `ce_cal_call(op, request_json)` returns a JSON string that the caller
frees with `ce_cal_free`. The ops and their JSON are those of docs/CAL.md section 8 (`parse`,
`compile`, `sign`, `explain`, `decompile`, `verify`); every answer is the Rust verifier's own.

```
cargo build --release -p ce-cal-ffi     # target/release/libce_cal_ffi.so
```

From Python, `ctypes.CDLL("libce_cal_ffi.so")`, with `ce_cal_call.restype = ctypes.c_void_p`,
reads the answer with `ctypes.string_at` and frees it with `ce_cal_free`. The ctypes wrapper
package is not in this repository yet.
