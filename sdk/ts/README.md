# ce-cal for TypeScript and JavaScript

CAL (the cell auth language, [`docs/CAL.md`](../../docs/CAL.md)) in WebAssembly: the Rust crate
built with wasm-bindgen, with typed calls in [`ce-cal.ts`](ce-cal.ts): `parse`, `compile`, `sign`,
`explain`, `decompile`, `verify`. Every answer is the Rust verifier's own.

```
npm install
npm run build:wasm      # cargo build --target wasm32-unknown-unknown + wasm-bindgen (wasm-bindgen-cli 0.2.130)
npm test                # checks the examples' explain text, compile, sign, verify, refusals
npm run example         # example.ts
```

[`example.ts`](example.ts) explains the Raspberry Pi example, compiles and signs it with the test
keys of the conformance vectors, and verifies two requests.
