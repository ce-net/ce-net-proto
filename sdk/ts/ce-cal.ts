// CAL (cell auth language) for TypeScript and JavaScript: typed calls over the WebAssembly build
// of the Rust crate, so every answer is the Rust verifier's own. Docs: docs/CAL.md section 8.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const wasm: { call(op: string, request: string): string } = require("./pkg/ce_cal_wasm.js");

/** A ref book (docs/CAL.md 3.3): what each ce-ref names, pinned. */
export interface RefBook {
  principals?: Record<string, string[]>;
  nodes?: Record<string, string[]>;
  repos?: Record<string, string[]>;
  files?: Record<string, { sha256: string; size: number; commit?: string }[]>;
  blobs?: Record<string, number>;
  cells?: Record<string, string[]>;
  roots?: string[];
}

/** A refusal: where, what, and what to write instead. */
export class CalError extends Error {
  constructor(public line: number, message: string, public suggestion: string | null) {
    super(line > 0 ? `line ${line}: ${message}` : message);
  }
}

export interface Draft {
  cal_draft: 1;
  links: { id: string; issuer: string; cap: string; sig: string | null }[];
  programs: string[];
}

export interface Verdict {
  allowed: boolean;
  reason: string | null;
  why: string[];
  text: string;
}

function call<T>(op: string, req: object): T {
  const out = JSON.parse(wasm.call(op, JSON.stringify(req)));
  if (!out.ok) throw new CalError(out.error.line, out.error.message, out.error.suggestion);
  return out as T;
}

/** A random u64 (as a decimal string) from the platform CSPRNG: a link nonce. */
function nonce(): string {
  const b = new Uint8Array(8);
  const c = (globalThis as any).crypto;
  if (c && c.getRandomValues) c.getRandomValues(b);
  else require("crypto").randomFillSync(b);
  return new DataView(b.buffer).getBigUint64(0, true).toString();
}

/** The file in canonical layout (throws CalError on a syntax error). */
export function parse(source: string): string {
  return call<{ formatted: string }>("parse", { source }).formatted;
}

/** Pin every ref and build the unsigned links; refuses ambiguous or unpinned refs. */
export function compile(source: string, refs: RefBook = {}, now?: number): { draft: Draft; ids: string[]; programs: string[] } {
  const nonces = Array.from({ length: 64 }, nonce);
  return call("compile", { source, refs, now, nonces });
}

/** Sign the links of `draft` issued by `key` (`ed25519:<64 hex>` or `p256:<64 hex>`). */
export function sign(draft: Draft, key: string): { draft: Draft; signed: number; token: string | null } {
  return call("sign", { draft, key });
}

/** What a chain allows and requires, in plain English (from a .cal source, a token or a draft). */
export function explain(input: { source?: string; token?: string; draft?: Draft }, refs: RefBook = {}, now?: number): string {
  return call<{ text: string }>("explain", { ...input, refs, now }).text;
}

/** A token (or draft) back to CAL. */
export function decompile(input: { token?: string; draft?: Draft }, refs: RefBook = {}): string {
  return call<{ source: string }>("decompile", { ...input, refs }).source;
}

/** Run the verifier for one request, as the node would, and say why it is refused. */
export function verify(token: string, ask: {
  node: string; as: string; do?: string; program?: string; step?: number; run?: number; now?: number;
  request?: string; proofs?: string; body?: string; content?: string;
}, refs: RefBook = {}): Verdict {
  return call<Verdict>("verify", { token, refs, ...ask, now: ask.now ?? Math.floor(Date.now() / 1000) });
}
