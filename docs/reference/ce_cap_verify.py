#!/usr/bin/env python3
"""Independent reimplementation of docs/TOKEN-FORMAT.md (decode, cap_bytes, cap_id, verify_chain),
written from the document only. Checks every vector in tests/vectors.json.
Requires: Python 3.9+, `cryptography` (Ed25519). Usage: python3 docs/reference/ce_cap_verify.py [vectors.json]"""
import hashlib, json, struct, sys, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class R:
    def __init__(s, b): s.b, s.i = b, 0
    def take(s, n):
        if s.i + n > len(s.b): raise ValueError("truncated")
        v = s.b[s.i:s.i + n]; s.i += n; return v
    def u(s, n, f): return struct.unpack("<" + f, s.take(n))[0]
    def u16(s): return s.u(2, "H")
    def u32(s): return s.u(4, "I")
    def u64(s): return s.u(8, "Q")
    def b32(s): return s.take(32)
    def string(s): return s.take(s.u64()).decode("utf-8")
    def seq(s, f): return [f() for _ in range(s.u64())]
    def opt(s, f):
        t = s.take(1)[0]
        if t > 1: raise ValueError("bad option tag")
        return f() if t else None

def resource(r):
    v = r.u32()
    if v == 0: return ("Any",)
    if v == 1: return ("Node", r.b32())
    if v == 2: return ("Tag", r.string())
    if v == 3: return ("AllOf", r.seq(r.string))
    raise ValueError("bad resource variant")

def capability(r):
    start = r.i
    c = dict(issuer=r.b32(), audience=r.b32(), abilities=r.seq(r.string), resource=resource(r),
             caveats=dict(not_before=r.u64(), not_after=r.u64(), max_cpu=r.opt(r.u32), max_mem_mb=r.opt(r.u32),
                          max_credits=r.opt(r.u64), allowed_ports=r.opt(lambda: r.seq(r.u16)), path_prefix=r.opt(r.string)),
             nonce=r.u64(), parent=r.opt(r.b32))
    c["body"] = r.b[start:r.i]  # Capability encoding as on the wire
    return c

def decode_chain(hexstr):
    r = R(bytes.fromhex(hexstr.strip()))
    def link():
        c = capability(r)
        if r.u64() != 64: raise ValueError("sig length")
        c["sig"] = r.take(64); return c
    return r.seq(link)

DOMAIN = b"ce-cap-v1"
def cap_bytes(c): return struct.pack("<Q", len(DOMAIN)) + DOMAIN + c["body"]
def cap_id(c): return hashlib.sha256(cap_bytes(c)).digest()

def covers(g, n):
    if g == n or g == "*": return True
    if g.endswith(":*"): p = g[:-1]; return len(n) > len(p) and n.startswith(p)
    return False

def res_subset(c, p):
    if p[0] == "Any": return True
    if p[0] == "Node": return c == p
    if p[0] == "Tag": return (c[0] == "Tag" and c[1] == p[1]) or (c[0] == "AllOf" and p[1] in c[1])
    if c[0] == "AllOf": return all(x in c[1] for x in p[1])
    if c[0] == "Tag": return all(x == c[1] for x in p[1])
    return False

def le_opt(c, p): return p is None or (c is not None and c <= p)
def within(c, p):
    c, p = c.rstrip("/"), p.rstrip("/"); return p == "" or c == p or c.startswith(p + "/")

def cav_narrower(c, p):
    if p["not_after"] and (not c["not_after"] or c["not_after"] > p["not_after"]): return False
    if c["not_before"] < p["not_before"]: return False
    if not all(le_opt(c[k], p[k]) for k in ("max_cpu", "max_mem_mb", "max_credits")): return False
    if p["allowed_ports"] is not None and (c["allowed_ports"] is None or not all(x in p["allowed_ports"] for x in c["allowed_ports"])): return False
    if p["path_prefix"] is not None and (c["path_prefix"] is None or not within(c["path_prefix"], p["path_prefix"])): return False
    return True

def verify_chain(chain, root, now, revoked):
    if not chain: return "no capability presented"
    if chain[0]["issuer"] != root: return "capability chain does not root at an accepted authority"
    for i, c in enumerate(chain):
        try: Ed25519PublicKey.from_public_bytes(c["issuer"]).verify(c["sig"], cap_bytes(c))
        except Exception: return f"link {i}: invalid signature"
        cv = c["caveats"]
        if cv["not_before"] and now < cv["not_before"]: return f"link {i}: capability not yet valid"
        if cv["not_after"] and now > cv["not_after"]: return f"link {i}: capability has expired"
        if (c["issuer"], c["nonce"]) in revoked: return f"link {i}: capability revoked"
        if i == 0:
            if c["parent"] is not None: return "root capability must not name a parent"
            continue
        p = chain[i - 1]
        if c["issuer"] != p["audience"]: return f"link {i}: issuer is not the parent's audience"
        if c["parent"] != cap_id(p): return f"link {i}: parent hash does not match the chain"
        if not all(any(covers(g, a) for g in p["abilities"]) for a in c["abilities"]): return f"link {i}: abilities exceed the parent"
        if not res_subset(c["resource"], p["resource"]): return f"link {i}: resource is broader than the parent"
        if not cav_narrower(cv, p["caveats"]): return f"link {i}: caveats are broader than the parent"
    return None

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "../../tests/vectors.json")
    v = json.load(open(path)); bad = 0
    for vec in v["chains"]:
        chain = decode_chain(vec["chain_hex"])
        for c, l in zip(chain, vec["links"]):
            assert cap_bytes(c).hex() == l["cap_bytes"] and cap_id(c).hex() == l["cap_id"] and c["sig"].hex() == l["sig"], vec["name"]
        rev = {(bytes.fromhex(r["issuer"]), r["nonce"]) for r in vec["revoked"]}
        got = verify_chain(chain, bytes.fromhex(vec["root"]), vec["now"], rev)
        want = vec["verify_chain"].get("error")
        ok = got == want; bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {vec['name']}: {got or 'valid'}")
    for r in v["revocations"]:
        b = bytes.fromhex(r["encoded"]); rb = struct.pack("<Q", 16) + b"ce-cap-revoke-v1" + b[:48]
        assert rb.hex() == r["revoke_bytes"] and struct.unpack("<Q", b[48:56])[0] == 64
        Ed25519PublicKey.from_public_bytes(b[:32]).verify(b[56:120], rb)
        print(f"ok   revocation {r['name']}")
    sys.exit(1 if bad else 0)

if __name__ == "__main__": main()
