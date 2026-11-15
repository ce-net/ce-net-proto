import { readFileSync } from "fs";
import { compile, explain, sign, verify } from "./ce-cal";
const ex = `${__dirname}/../../../examples`, refs = JSON.parse(readFileSync(`${ex}/cal.refs.json`, "utf8"));
const source = readFileSync(`${ex}/raspberry-pi.cal`, "utf8");
console.log(explain({ source }, refs).split("\n")[0]);
let { draft } = compile(source, refs), token: string | null = null;
for (const key of ["p256:" + "11".repeat(32), "ed25519:" + "21".repeat(32)]) ({ draft, token } = sign(draft, key)); // test keys
const v = verify(token!, { node: "node:pi-01", as: "agent:agent-b", program: "b94f", step: 0, now: 1800000060 }, refs);
console.log(v.allowed ? "allowed" : `refused: ${v.reason}`);
console.log(verify(token!, { node: "node:pi-01", as: "agent:planner", program: "b94f", now: 1800000060 }, refs).text);
