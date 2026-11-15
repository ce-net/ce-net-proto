// Run with `npm test`: the TypeScript SDK gives the Rust crate's answers.
import { strict as assert } from "assert";
import { readFileSync } from "fs";
import { CalError, compile, decompile, explain, parse, sign, verify } from "./ce-cal";

const ex = `${__dirname}/../../../examples`;
const refs = JSON.parse(readFileSync(`${ex}/cal.refs.json`, "utf8"));
const source = readFileSync(`${ex}/raspberry-pi.cal`, "utf8");

// explain is the checked-in text, byte for byte
assert.equal(explain({ source }, refs), readFileSync(`${ex}/raspberry-pi.explain.txt`, "utf8"));
assert.ok(parse(source).startsWith("cal 1\n"));

// compile, sign with the vectors' test keys, verify
let { draft, ids } = compile(source, refs);
assert.deepEqual(ids, ["4ce03fc8c57a2d136147dd67007b4df65024fe63d2d90659fbc9547594169459", "59f297cf33922e62a6310048dab6f1e6879f95eb3167bacd719cf69d7b30c2a2"]);
let token: string | null = null;
for (const key of ["p256:" + "11".repeat(32), "ed25519:" + "21".repeat(32)]) ({ draft, token } = sign(draft, key));
assert.ok(token);
const ask = { node: "node:pi-01", as: "agent:agent-b", program: "b94f", step: 0, now: 1800000060 };
assert.equal(verify(token!, ask, refs).allowed, true);
const content = Buffer.from("print('pwned')\n").toString("hex");
assert.match(verify(token!, { ...ask, content }, refs).reason!, /^content hash mismatch/);
assert.equal(verify(token!, { ...ask, as: "agent:planner" }, refs).reason, "leaf capability is not held by the request sender");
assert.match(decompile({ token: token! }, refs), /install repo:huey-scripts\/run.py@3f2a1c7 sha256:3f9b0d4d/);

// an ambiguous or unpinned ref is refused, with a suggestion
try {
  compile(source.replace(/sha256:3f9b0d4d[0-9a-f]+/, "sha256:3f9b"), refs);
  assert.fail("compiled a hash prefix");
} catch (e) {
  assert.ok(e instanceof CalError);
  assert.match((e as CalError).suggestion!, /sha256:3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51/);
}
console.log("ts sdk: all checks passed");
