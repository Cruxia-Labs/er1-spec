#!/usr/bin/env python3
"""ER1 — the reference offline verifier for Epistemic Receipts (constraint-state receipts).

ONE self-contained file. Drop it on any machine — it has NO external project imports, only
the Python stdlib plus `cryptography` (for Ed25519). It recomputes the verdict from the
receipt's own recorded constraint snapshot, checks the signature, the action binding, and the
state-root, and prints VERIFIED or FAILED. Tamper a single byte and it fails.

    $ pip install cryptography
    $ er1-verify receipt.json          # (or: python er1_verify.py receipt.json)

An ER1 receipt binds the CONSTRAINT STATE (the active, deterministic constraint set — a
"context-lineage" snapshot) an agent's action was produced under. This verifier vendors the
canonical-JSON serializer (RFC 8785) and the conflict predicate verbatim from the spec, so it
is byte-identical to the producer; any conformant re-implementation (Rust/WASM/TS/Go) must
reproduce golden_vectors.json (see CONFORMANCE.md).

What it certifies: the verdict correctly follows from the recorded, signed pre-state — NOT the
empirical truth of the constraints ("garbage in, certified garbage out"). receipt_id /
created_at are signed metadata, excluded from the verdict recomputation. Full breach
definition: SCOPE_OF_CERTIFICATION.md.

(Note: the on-wire array of constraints is named `beliefs[]` in the frozen v1 schema for
signature compatibility; it is the constraint / context-lineage set.)
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import sys
import unicodedata
from typing import Any, Optional

# ── canonical JSON (RFC 8785–compatible) — vendored verbatim from the spec ──

def _utf16_key(s: str):
    out = []
    for ch in s:
        cp = ord(ch)
        if cp <= 0xFFFF:
            out.append(cp)
        else:
            cp -= 0x10000
            out.append(0xD800 + (cp >> 10))
            out.append(0xDC00 + (cp & 0x3FF))
    return tuple(out)


def _escape(s: str) -> str:
    s = unicodedata.normalize("NFC", s)
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        elif cp < 0x7F:
            out.append(ch)
        elif cp <= 0xFFFF:
            out.append(f"\\u{cp:04x}")
        else:
            v = cp - 0x10000
            out.append(f"\\u{0xD800 + (v >> 10):04x}\\u{0xDC00 + (v & 0x3FF):04x}")
    out.append('"')
    return "".join(out)


def _number(n) -> str:
    if isinstance(n, bool):
        return "true" if n else "false"
    if isinstance(n, int):
        return str(n)
    if math.isnan(n) or math.isinf(n):
        raise ValueError("non-finite number")
    if n == 0.0:
        return "0"
    if float(n).is_integer() and abs(n) < 1e16:
        return str(int(n))
    s = repr(n)
    if "e" in s or "E" in s:
        mant, _, exp = s.partition("e") if "e" in s else s.partition("E")
        sign = ""
        if exp.startswith("+"):
            exp = exp[1:]
        if exp.startswith("-"):
            sign, exp = "-", exp[1:]
        exp = exp.lstrip("0") or "0"
        s = f"{mant}e{sign}{exp}"
    return s


def _canon(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return _number(v)
    if isinstance(v, str):
        return _escape(v)
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=_utf16_key)
        return "{" + ",".join(_escape(k) + ":" + _canon(v[k]) for k in keys) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_canon(x) for x in v) + "]"
    raise TypeError(f"cannot canonicalize {type(v)}")


def canonical_json(v: Any) -> bytes:
    return _canon(v).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ── the conflict predicate — vendored verbatim from the spec ──

def _parse_ver(s):
    out = []
    for part in str(s).strip().split("."):
        num = ""
        for ch in part:
            if "0" <= ch <= "9":          # ASCII digits only — matches er1_verify.mjs (no Unicode digits)
                num += ch
            else:
                break
        out.append(int(num) if num else 0)
    return tuple(out)


def _ver_cmp(a, b):
    pa, pb = _parse_ver(a), _parse_ver(b)
    n = max(len(pa), len(pb))
    pa += (0,) * (n - len(pa))
    pb += (0,) * (n - len(pb))
    return (pa > pb) - (pa < pb)


def _compatible(proposed, constraint):
    # PEP 440 compatible-release (~=): proposed >= constraint AND shares its prefix (all but the
    # constraint's last component must match). ~=2.0 allows 2.5 not 3.0; ~=2.0.1 allows 2.0.5 not 2.1.0.
    if _ver_cmp(proposed, constraint) < 0:
        return False
    cv = _parse_ver(constraint)
    if len(cv) < 2:
        return True
    prefix = cv[:-1]
    pv = _parse_ver(proposed)
    pv += (0,) * (len(prefix) - len(pv))
    return pv[:len(prefix)] == prefix


def _satisfies(proposed, constraint):
    c = constraint.strip()
    for op in (">=", "<=", "==", "~=", ">", "<", "="):
        if c.startswith(op):
            target = c[len(op):].strip()
            if op == "~=":
                return _compatible(proposed, target)
            cmp = _ver_cmp(proposed, target)
            return {">=": cmp >= 0, ">": cmp > 0, "<=": cmp <= 0, "<": cmp < 0,
                    "==": cmp == 0, "=": cmp == 0}[op]
    return _ver_cmp(proposed, c) == 0


def _conflict(beliefs, asserts):
    """Return (belief_id, reason_code) of the first conflict, or None."""
    for b in beliefs:
        if b.get("status", "active") != "active" or b.get("source_kind") != "deterministic":
            continue
        ent, rule, val = b["entity"], b["rule"], b["value"]
        if rule == "excludes":
            if ent in asserts:
                return b["belief_id"], "BANNED_ENTITY"
        elif ent in asserts:
            proposed = str(asserts[ent])
            if rule == "equals" and proposed != val:
                return b["belief_id"], "SUPERSEDED_VALUE"
            if rule == "satisfies" and not _satisfies(proposed, val):
                return b["belief_id"], "CONSTRAINT_VIOLATION"
    return None


# ── verification ──

def _body(receipt: dict) -> dict:
    b = dict(receipt)
    b["signature"] = None
    return b


def receipt_hash(receipt: dict) -> str:
    return _sha256_hex(canonical_json(_body(receipt)))


def verify_signature(receipt: dict) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    sb = receipt.get("signature")
    if not sb or sb.get("algorithm") != "ed25519":
        return False

    def _d(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    try:
        # The signed message is the SHA-256 digest of the canonical body (not the raw body). The
        # signer and BOTH reference verifiers agree on this, and golden_vectors.json pins it, so it
        # is the conformance contract. This is plain Ed25519 over a 32-byte message (NOT Ed25519ph);
        # a port that instead signs the raw body is simply non-conformant, not "more correct".
        digest = hashlib.sha256(canonical_json(_body(receipt))).digest()
        Ed25519PublicKey.from_public_bytes(_d(sb["public_key"])).verify(_d(sb["signature"]), digest)
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def verify(receipt: dict) -> dict:
    errs = []
    checks = {}

    checks["signature"] = verify_signature(receipt)
    if not checks["signature"]:
        errs.append("signature: invalid or missing")

    action = receipt.get("action", {})
    expect = _sha256_hex(canonical_json(
        {"tool": action.get("tool", ""), "asserts": action.get("asserts", {}),
         "resource": action.get("resource", "")}))
    checks["binding"] = receipt.get("action_binding", {}).get("args_hash") == expect
    if not checks["binding"]:
        errs.append("action_binding: args_hash mismatch")

    beliefs = receipt.get("beliefs", [])
    checks["state_root"] = receipt.get("pre_state_root") == _sha256_hex(canonical_json(beliefs))
    if not checks["state_root"]:
        errs.append("pre_state_root mismatch")

    c = _conflict(beliefs, action.get("asserts", {}))
    recomputed = "HALT" if c is not None else "ALLOW"
    recorded = receipt.get("decision", {})
    checks["verdict"] = recomputed == recorded.get("verdict")
    if not checks["verdict"]:
        errs.append(f"verdict: recomputed {recomputed} vs recorded {recorded.get('verdict')!r}")
    if c is not None:
        if recorded.get("conflicting_belief_id") != c[0]:
            errs.append("verdict: conflicting_belief_id mismatch")
        if recorded.get("reason_code") != c[1]:
            errs.append("verdict: reason_code mismatch")

    return {"ok": not errs, "recomputed_verdict": recomputed, "checks": checks, "errors": errs}


def _receipts_from(doc: Any, label: str) -> list:
    """A golden_vectors bundle wraps each receipt as {name, receipt, ...}; a bare receipt has a
    top-level `decision`. Yields (label, receipt) pairs so the CLI handles both."""
    if isinstance(doc, dict) and isinstance(doc.get("receipts"), list):
        return [(f"{label}:{w.get('name')}", w["receipt"]) for w in doc["receipts"]]
    return [(label, doc)]


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: er1-verify <receipt.json | golden_vectors.json> [...]   "
              "(or: python er1_verify.py <file.json>)", file=sys.stderr)
        return 2
    all_ok = True
    for path in argv:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        for label, receipt in _receipts_from(doc, path):
            res = verify(receipt)
            d = receipt.get("decision", {})
            status = "VERIFIED ✓" if res["ok"] else "FAILED ✗"
            print(f"{status}  {label}  verdict={d.get('verdict')} "
                  f"(recomputed {res['recomputed_verdict']})  hash={receipt_hash(receipt)[:18]}…")
            for e in res["errors"]:
                print(f"    ! {e}")
            all_ok = all_ok and res["ok"]
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
