# ce-cal for Python

CAL (the cell auth language, [`docs/CAL.md`](../../docs/CAL.md)) for Python: `ce_cal.parse`,
`compile`, `sign`, `explain`, `decompile`, `verify`, a ctypes wrapper over the crate's C ABI
([`ce_cal.h`](ce_cal.h): `ce_cal_call(op, json)` / `ce_cal_free`), which any language with a C
FFI can call the same way. Every answer is the Rust verifier's own.

```
cargo build --release -p ce-cal-ffi     # target/release/libce_cal_ffi.so (or set CE_CAL_LIB)
python3 -m unittest                     # in sdk/python
python3 example.py
```

[`example.py`](example.py) explains the Raspberry Pi example, compiles and signs it with the test
keys of the conformance vectors, and verifies two requests.
