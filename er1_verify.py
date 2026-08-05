#!/usr/bin/env python3
"""ER1 — the reference offline verifier for Epistemic Receipts (constraint-state receipts).

ONE self-contained file. Drop it on any machine — it has NO external project imports, only
the Python stdlib plus `cryptography` (for Ed25519). It recomputes the verdict from the
receipt's own recorded constraint snapshot, checks the signature, the action binding, and the
state-root, and prints VERIFIED or FAILED. Tamper a signed content byte and it fails.

    $ pip install cryptography
    $ er1-verify receipt.json               # (or: python er1_verify.py receipt.json)
    $ er1-verify --pubkey <key> receipt.json   # pin the signer you actually trust

An ER1 receipt binds the CONSTRAINT STATE (the active, deterministic constraint set — a
"context-lineage" snapshot) an agent's action was produced under.

What it certifies: the verdict correctly follows from the recorded, signed pre-state — NOT the
empirical truth of the constraints ("garbage in, certified garbage out"). receipt_id /
created_at are signed metadata, excluded from the verdict recomputation. Full breach
definition: SCOPE_OF_CERTIFICATION.md.

SOUNDNESS RULES (v1.1, after the 2026-08-04 adversarial review). Each closes a class of
attack in which a receipt no one should trust printed VERIFIED:

  FAIL CLOSED. Anything unrecognized — an unknown enum value, a missing field on an active
  constraint, a wrong JSON type, an unparseable version — makes the receipt UNVERIFIABLE, not
  permissible. Previously such receipts skipped the constraint and verified as ALLOW, so a
  single character ("ACTIVE" for "active") silently disarmed a gate.

  IDENTITY IS ASCII, AND NOTHING IS NORMALIZED. NFC is bound to the runtime's Unicode version
  (CPython 3.12 ships 15.0, Node 24 ships 16.0, and 20 code points compose in one and not the
  other), so normalizing inside the canonical form made the SIGNED BYTES depend on which
  interpreter you ran — one verifier let a decomposed spelling past an excludes gate while
  another halted on the same file. The canonical form therefore does not normalize at all,
  which is also what RFC 8785 does. Identity stays unambiguous by a different route: the names
  used to LOOK A CONSTRAINT UP (belief.entity, the keys of action.asserts, belief_id) must be
  printable ASCII, where normalization is the identity function in every Unicode version. Free
  text — values, tool, resource — is unrestricted and compared with exact code-point equality.

  ONE NUMBER GRAMMAR. Canonical JSON accepts only integers that are exactly representable in
  both IEEE-754 doubles and Python ints (|n| <= 2**53 - 1). Floats and larger integers are
  rejected rather than serialized, because no number grammar exists that Python and
  ECMAScript both emit identically — 1e21, 1e16, 1e-6 and every integer above 2**53 differed,
  which let a tampered body keep a colliding hash in one language and not the other.

  ONE READING PER DOCUMENT. Duplicate keys, unpaired surrogates and non-object top levels are
  refused at the parse boundary, before anything reads the document — a file has exactly one
  reading or none. JSON parsers silently keep the last of a duplicated key, which let
  contradictory decoy content ride inside a signed file that still verified.

  A RECEIPT IS NOT A BUNDLE. A document that looks like both is ambiguous and is rejected.
  Previously an unsigned top-level `receipts` array decided what got verified, so a forged
  receipt carrying one genuine receipt printed VERIFIED and exited 0 — pinning did not help.

  DEGENERATE KEYS ARE REJECTED. Small-order Ed25519 points make one constant signature block
  verify against any message, so a signature nobody produced would verify.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
import sys
from typing import Any, Optional

# ── limits ──
# Both bounds exist so adversarial input yields a verdict instead of a traceback.
MAX_DEPTH = 100                      # nesting; Python's recursion limit is not a security control
MAX_SAFE_INT = 2 ** 53 - 1           # the exactly-representable range shared with ECMAScript
MAX_BYTES = 8 * 1024 * 1024          # a receipt is a constraint snapshot, not a payload


class Er1MalformedReceipt(ValueError):
    """The receipt cannot be evaluated. Never silently ALLOW — the caller turns this into
    FAILED, the only safe verdict for input we are unable to check."""


# ── canonical JSON — vendored verbatim from the spec ──
#
# RFC 8785 with two PINNED deviations you must match to interoperate (both documented in
# CONFORMANCE.md): every non-ASCII character is escaped as \\uXXXX rather than emitted
# literally, and the number grammar is restricted to exactly-representable integers. Strings
# are NOT normalized — that deviation was removed on 2026-08-04 because it made the canonical
# bytes depend on the runtime's Unicode version.

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


# Printable ASCII, the character set the IDENTITY fields are restricted to — the names used to
# look a constraint up: belief.entity, the keys of action.asserts, belief_id. Within it,
# normalization is the identity function in every Unicode version, so two implementations
# cannot disagree about which constraint an action touches, whatever their runtimes ship.
# Free text (values, tool, resource) stays unrestricted: it is compared with exact code-point
# equality, which is well defined everywhere.
ID_CHARS = frozenset(chr(c) for c in range(0x20, 0x7F))


def _is_id_safe(s: str) -> bool:
    return all(ch in ID_CHARS for ch in s)


def _escape(s: str) -> str:
    # Deliberately NOT normalized. NFC is bound to the runtime's Unicode version (CPython 3.12
    # ships 15.0, Node 24 ships 16.0, and 20 code points compose in one and not the other), so
    # normalizing here made the canonical bytes — and therefore the signature — depend on which
    # interpreter you ran. RFC 8785 does not normalize either; this is now the standard
    # behaviour, and identity is kept unambiguous by restricting decision-bearing fields to
    # ASCII instead.
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
    """Integers only, and only those both languages represent exactly.

    Anything else is refused rather than guessed at. The alternative — emitting a float in a
    per-language format — means two conformant verifiers can disagree on the canonical bytes
    of the same document, and a disagreement about bytes is a disagreement about whether a
    receipt was tampered with."""
    if isinstance(n, bool):
        return "true" if n else "false"
    if isinstance(n, int):
        if abs(n) > MAX_SAFE_INT:
            raise Er1MalformedReceipt(
                f"integer {n} is outside the exactly-representable range (|n| <= 2**53-1)")
        return str(n)
    if isinstance(n, float):
        if n.is_integer() and abs(n) <= MAX_SAFE_INT:
            return str(int(n))
        raise Er1MalformedReceipt(
            f"non-integral number {n} is not canonicalizable (integers only)")
    raise Er1MalformedReceipt(f"cannot canonicalize number of type {type(n)}")


def _canon(v: Any, depth: int = 0) -> str:
    if depth > MAX_DEPTH:
        raise Er1MalformedReceipt(f"nesting deeper than {MAX_DEPTH} levels")
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return _number(v)
    if isinstance(v, str):
        return _escape(v)
    if isinstance(v, dict):
        # NO normalization. Keys are serialized exactly as parsed and ordered by UTF-16
        # code unit. Do not add an NFC pass here "to be safe" — NFC is bound to the
        # runtime's Unicode version, so normalizing is what made the signed bytes depend on
        # which interpreter ran. Identity is kept unambiguous by restricting the
        # decision-bearing names to ASCII instead (see validate_receipt).
        for k in v.keys():
            if not isinstance(k, str):
                raise Er1MalformedReceipt("object key is not a string")
        keys = sorted(v.keys(), key=_utf16_key)
        return "{" + ",".join(_escape(k) + ":" + _canon(v[k], depth + 1) for k in keys) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_canon(x, depth + 1) for x in v) + "]"
    raise Er1MalformedReceipt(f"cannot canonicalize {type(v)}")


def canonical_json(v: Any) -> bytes:
    return _canon(v).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ── structural validation — runs BEFORE the predicate, and fails closed ──

VERDICTS = {"ALLOW", "HALT"}
RULES = {"equals", "excludes", "satisfies"}
STATUSES = {"active", "superseded"}
SOURCE_KINDS = {"deterministic", "nl_extracted"}
BELIEF_CLASSES = {"CERTIFIED", "BEST_EFFORT"}


def _jt(v: Any) -> str:
    """JSON type names, not language type names — the error strings are part of the spec and
    must read identically from every implementation (tests/test_browser_cross_language.py
    compares them literally)."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, (list, tuple)):
        return "array"
    return "object"


def _js_shape(v: Any) -> Any:
    """Integral floats print as `1.0` in Python and `1` in JavaScript. Error text is compared
    literally across implementations, so a value quoted into a message is normalized to the
    shape JSON.stringify would render."""
    if isinstance(v, float) and not isinstance(v, bool) and v.is_integer() and abs(v) <= 2**53 - 1:
        return int(v)
    if isinstance(v, dict):
        return {k: _js_shape(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_js_shape(x) for x in v]
    return v


def _q(v: Any) -> str:
    """JSON.stringify-compatible rendering of a value inside an error message. Compact
    separators, because a malformed-field message may now quote a whole array or object and
    Python's default `, ` would not match the JavaScript verifier byte for byte."""
    try:
        return json.dumps(_js_shape(v), ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        return str(v)


def _in_enum(v: Any, allowed: set) -> bool:
    """`v in some_set` HASHES v, so an enum field holding a list or an object raised
    TypeError — an uncaught traceback where JavaScript's Set.has() simply returned false and
    the receipt was reported FAILED. A crash is not a verdict. Every enum here holds strings,
    so a value that is not a string is never a member."""
    return isinstance(v, str) and v in allowed


def _require_str(obj: dict, field: str, where: str, id_safe: bool = False) -> str:
    v = obj.get(field)
    if not isinstance(v, str):
        raise Er1MalformedReceipt(f"{where}.{field} must be a string, got {_jt(v)}")
    if id_safe and not _is_id_safe(v):
        # Decision-bearing fields are restricted to printable ASCII so that identity cannot
        # depend on a runtime's Unicode version, whitespace set, or case rules.
        raise Er1MalformedReceipt(
            f"{where}.{field} must be printable ASCII (it names a constraint)")
    return v


def validate_receipt(receipt: Any) -> None:
    """Reject anything we cannot evaluate exactly. An unrecognized enum value is a defect in
    the producer, not a permission — before this existed, `status: "ACTIVE"` disarmed a gate
    and the receipt verified as ALLOW."""
    if not isinstance(receipt, dict):
        raise Er1MalformedReceipt("receipt is not a JSON object")

    # A receipt must not also claim to be a bundle (see the document-discrimination rule).
    if "receipts" in receipt:
        raise Er1MalformedReceipt(
            "document carries both receipt fields and a `receipts` array — ambiguous")

    action = receipt.get("action")
    if not isinstance(action, dict):
        raise Er1MalformedReceipt("action must be an object")
    _require_str(action, "tool", "action")
    _require_str(action, "resource", "action")
    asserts = action.get("asserts")
    if not isinstance(asserts, dict):
        raise Er1MalformedReceipt("action.asserts must be an object")
    for k, val in asserts.items():
        if not isinstance(k, str):
            raise Er1MalformedReceipt("action.asserts key is not a string")
        # Strings only. Coercing other types would reintroduce a divergence: Python's
        # str(True) is "True" and ECMAScript's String(true) is "true", so the two verifiers
        # would compare different proposed values against the same constraint.
        if not _is_id_safe(k):
            raise Er1MalformedReceipt(
                f"action.asserts key {_q(k)} must be printable ASCII (it names a constraint)")
        if not isinstance(val, str):
            raise Er1MalformedReceipt(
                f"action.asserts[{_q(k)}] must be a string, got {_jt(val)}")

    binding = receipt.get("action_binding")
    if not isinstance(binding, dict):
        raise Er1MalformedReceipt("action_binding must be an object")

    beliefs = receipt.get("beliefs")
    if not isinstance(beliefs, list):
        raise Er1MalformedReceipt("beliefs must be an array")
    for i, b in enumerate(beliefs):
        if not isinstance(b, dict):
            raise Er1MalformedReceipt(f"beliefs[{i}] is not an object")
        # No implicit default: `.get(k, "active")` and JavaScript's `?? "active"` disagree on
        # an explicit null, so one verifier read the constraint as active and the other
        # rejected the receipt. The field must be present and explicit.
        status = b.get("status")
        if not _in_enum(status, STATUSES):
            raise Er1MalformedReceipt(
                f"beliefs[{i}].status {_q(status)} is not a known status")
        source_kind = b.get("source_kind")
        if not _in_enum(source_kind, SOURCE_KINDS):
            raise Er1MalformedReceipt(
                f"beliefs[{i}].source_kind {_q(source_kind)} is not a known source_kind")
        if "belief_class" in b and not _in_enum(b["belief_class"], BELIEF_CLASSES):
            raise Er1MalformedReceipt(
                f"beliefs[{i}].belief_class {_q(b['belief_class'])} is not a known belief_class")
        # Only constraints that can gate must be fully specified; a superseded or
        # nl_extracted entry is inert either way, but its shape must still be sane.
        if status == "active" and source_kind == "deterministic":
            _require_str(b, "belief_id", f"beliefs[{i}]", id_safe=True)
            _require_str(b, "entity", f"beliefs[{i}]", id_safe=True)
            rule = _require_str(b, "rule", f"beliefs[{i}]", id_safe=True)
            if rule not in RULES:
                raise Er1MalformedReceipt(
                    f"beliefs[{i}].rule {_q(rule)} is not a known rule")
            if rule != "excludes":
                _require_str(b, "value", f"beliefs[{i}]")

    decision = receipt.get("decision")
    if not isinstance(decision, dict):
        raise Er1MalformedReceipt("decision must be an object")
    if not _in_enum(decision.get("verdict"), VERDICTS):
        raise Er1MalformedReceipt(
            f"decision.verdict {_q(decision.get('verdict'))} is not one of ALLOW, HALT")

    # The whole body must be canonicalizable, anywhere in the document — not just the parts
    # this verifier reads. A receipt carrying a number or a nesting depth we cannot serialize
    # exactly has no well-defined signed form, so it is refused with a reason rather than
    # reported as a mere signature failure.
    canonical_json(_body(receipt))


# ── the conflict predicate — vendored verbatim from the spec ──

def _parse_ver(s):
    """Strict dotted-numeric parse. Returns None when the string is not a version.

    The old parser mapped any non-numeric component to 0, so `<2.0` was satisfied by
    "latest", "main", "v3.0" and "" — every one of them a gate bypass."""
    # No strip(): Python's str.strip and ECMAScript's String.trim remove different whitespace
    # sets, which flipped verdicts between the two reference verifiers on the same bytes.
    text = s if isinstance(s, str) else str(s)
    if not text:
        return None
    out = []
    for part in text.split("."):
        if not part or not all("0" <= ch <= "9" for ch in part):   # ASCII digits only
            return None
        val = int(part)
        if val > MAX_SAFE_INT:      # stay inside the range both languages compare exactly
            return None
        out.append(val)
    return tuple(out)


def _ver_cmp(a, b):
    pa, pb = a, b
    n = max(len(pa), len(pb))
    pa += (0,) * (n - len(pa))
    pb += (0,) * (n - len(pb))
    return (pa > pb) - (pa < pb)


def _compatible(proposed, constraint):
    # PEP 440 compatible-release (~=): proposed >= constraint AND shares its prefix (all but
    # the constraint's last component must match). ~=2.0 allows 2.5 not 3.0.
    if _ver_cmp(proposed, constraint) < 0:
        return False
    if len(constraint) < 2:
        # PEP 440: ~=2 is not a valid compatible-release clause — it would degenerate into an
        # unbounded >=2 and the pin would never gate anything.
        raise Er1MalformedReceipt("~= needs at least two version components")
    prefix = constraint[:-1]
    pv = proposed + (0,) * (len(prefix) - len(proposed))
    return pv[:len(prefix)] == prefix


def _satisfies(proposed_raw, constraint_raw):
    c = constraint_raw if isinstance(constraint_raw, str) else str(constraint_raw)
    for op in (">=", "<=", "==", "~=", ">", "<", "="):
        if c.startswith(op):
            target = _parse_ver(c[len(op):])
            proposed = _parse_ver(proposed_raw)
            if target is None or proposed is None:
                raise Er1MalformedReceipt(
                    f"cannot evaluate {op} between {_q(str(proposed_raw))} and {_q(c)}: not versions")
            if op == "~=":
                return _compatible(proposed, target)
            cmp = _ver_cmp(proposed, target)
            return {">=": cmp >= 0, ">": cmp > 0, "<=": cmp <= 0, "<": cmp < 0,
                    "==": cmp == 0, "=": cmp == 0}[op]
    # No operator: exact equality of the version, or — when neither side is a version —
    # exact string equality, which is well defined and language-independent.
    target, proposed = _parse_ver(c), _parse_ver(proposed_raw)
    if target is None or proposed is None:
        return str(proposed_raw) == c
    return _ver_cmp(proposed, target) == 0


def _conflict(beliefs, asserts):
    """Return (belief_id, reason_code) of the first conflict, or None.

    Assumes validate_receipt() has already run: every active deterministic constraint here is
    fully specified with known enum values."""
    # Exact comparison, no normalization: validate_receipt has already restricted entity
    # names and assert keys to printable ASCII, where NFC is the identity function in every
    # Unicode version. That restriction — not a normalization pass — is what stops one
    # signed byte-string from carrying two identities.
    for b in beliefs:
        if b["status"] != "active" or b["source_kind"] != "deterministic":
            continue
        ent, rule = b["entity"], b["rule"]
        if rule == "excludes":
            if ent in asserts:
                return b["belief_id"], "BANNED_ENTITY"
        elif ent in asserts:
            proposed = str(asserts[ent])
            val = b["value"]
            if rule == "equals" and proposed != val:
                return b["belief_id"], "SUPERSEDED_VALUE"
            if rule == "satisfies" and not _satisfies(proposed, val):
                return b["belief_id"], "CONSTRAINT_VIOLATION"
    return None


# ── signature ──

# Small-order Ed25519 point encodings (libsodium's has_small_order blacklist). A signature
# built from these verifies against ANY message, so one constant block would forge every
# receipt. Rejected for both the public key and the signature's R component.
_SMALL_ORDER = {
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
}


_B64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _b64d(s, expect_len: int):
    """Strict, hand-rolled base64url. Every runtime's decoder has its own leniency — Node,
    CPython and WebCrypto accepted three different sets of malformed inputs, so the same file
    verified in one implementation and failed in another. Nothing here is delegated."""
    if not isinstance(s, str):
        raise Er1MalformedReceipt("signature field is not a string")
    if any(ch not in _B64_ALPHABET for ch in s):
        raise Er1MalformedReceipt("signature field is not unpadded base64url")
    expect_chars = (expect_len * 8 + 5) // 6
    if len(s) != expect_chars:
        raise Er1MalformedReceipt(
            f"signature field must be exactly {expect_chars} base64url characters")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if len(raw) != expect_len:
        raise Er1MalformedReceipt(f"signature field must decode to {expect_len} bytes")
    # The final character carries unused trailing bits that the decoder silently discards,
    # so several spellings decode to identical bytes. Re-encoding and comparing pins the one
    # canonical spelling — otherwise a stricter peer implementation refuses a signature block
    # this one accepts.
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != s:
        raise Er1MalformedReceipt("signature field is not canonical base64url")
    return raw


class Er1MissingCrypto(RuntimeError):
    """`cryptography` is absent or too old. Not a verdict about the receipt — a verdict about
    this machine, and the two must never be confused."""


def verify_signature(receipt: dict) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise Er1MissingCrypto(
            f"cannot check signatures: {exc}. Install it with `pip install cryptography`."
        ) from None
    if not isinstance(receipt, dict):
        return False
    sb = receipt.get("signature")
    if not isinstance(sb, dict) or sb.get("algorithm") != "ed25519":
        return False
    try:
        pub_raw = _b64d(sb["public_key"], 32)
        sig_raw = _b64d(sb["signature"], 64)
        if pub_raw in _SMALL_ORDER or sig_raw[:32] in _SMALL_ORDER:
            return False                      # a signature nobody produced must not verify
        # The signed message is the SHA-256 digest of the canonical body (not the raw body).
        # The signer and every reference verifier agree on this, and golden_vectors.json pins
        # it, so it is the conformance contract. Plain Ed25519 over a 32-byte message.
        digest = hashlib.sha256(canonical_json(_body(receipt))).digest()
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw, digest)
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError, binascii.Error):
        # Adversarial receipts are the expected input: wrong types, bad base64,
        # non-canonicalizable bodies. Every one of them is FAILED, never a crash.
        return False


def _body(receipt: dict) -> dict:
    b = dict(receipt)
    b["signature"] = None
    return b


def receipt_hash(receipt: dict) -> str:
    return _sha256_hex(canonical_json(_body(receipt)))


# ── verification ──

def verify(receipt: Any, trusted_keys: Optional[set] = None) -> dict:
    """Verify one receipt. `trusted_keys` optionally pins the acceptable signer public keys;
    without it a receipt still verifies against the key it carries (see
    SCOPE_OF_CERTIFICATION.md), and the CLI prints that key so the relying party can pin it."""
    errs: list = []
    checks: dict = {}

    signer = None
    if isinstance(receipt, dict):
        sb = receipt.get("signature")
        if isinstance(sb, dict) and isinstance(sb.get("public_key"), str):
            signer = sb["public_key"]

    # The signature is checked FIRST and unconditionally: it cannot crash (every adversarial
    # shape returns False) and it is the answer a relying party most wants, so a tampered
    # receipt reports the tamper even when it is also structurally invalid.
    checks["signature"] = verify_signature(receipt)
    if not checks["signature"]:
        errs.append("signature: invalid or missing")

    try:
        validate_receipt(receipt)
    except Er1MalformedReceipt as exc:
        return {"ok": False, "recomputed_verdict": None, "checks": checks,
                "errors": errs + [f"malformed receipt: {exc}"], "signer": signer}

    if trusted_keys is not None:
        # Compare the 32 key BYTES, not the base64 text: the same key has several valid
        # spellings (padding, +/- vs -/_), and pinning must not be defeated by re-spelling it.
        try:
            signer_bytes = _b64d(signer, 32) if isinstance(signer, str) else None
        except Er1MalformedReceipt:
            signer_bytes = None
        pinned_bytes = set()
        for k in trusted_keys:
            try:
                pinned_bytes.add(_b64d(k, 32))
            except (Er1MalformedReceipt, TypeError):
                pass
        checks["trusted_signer"] = signer_bytes is not None and signer_bytes in pinned_bytes
        if not checks["trusted_signer"]:
            errs.append(f"signer not in pinned key set: {signer!r}")

    try:
        action = receipt["action"]
        asserts = action["asserts"]
        expect = _sha256_hex(canonical_json(
            {"tool": action["tool"], "asserts": asserts, "resource": action["resource"]}))
        binding = receipt["action_binding"]
        checks["binding"] = binding.get("args_hash") == expect
        if not checks["binding"]:
            errs.append("action_binding: args_hash mismatch")
        # The binding names the request it binds to. If it names a different tool or resource
        # than the action, the receipt contradicts itself — the signature covers both, so this
        # can only be a producer defect.
        if binding.get("tool") != action["tool"]:
            errs.append("action_binding: tool does not mirror action.tool")
        if binding.get("resource") != action["resource"]:
            errs.append("action_binding: resource does not mirror action.resource")

        beliefs = receipt["beliefs"]
        checks["state_root"] = receipt.get("pre_state_root") == _sha256_hex(canonical_json(beliefs))
        if not checks["state_root"]:
            errs.append("pre_state_root mismatch")

        c = _conflict(beliefs, asserts)
        recomputed = "HALT" if c is not None else "ALLOW"
        recorded = receipt["decision"]
        checks["verdict"] = recomputed == recorded.get("verdict")
        if not checks["verdict"]:
            errs.append(f"verdict: recomputed {recomputed} vs recorded {recorded.get('verdict')!r}")
        if c is not None:
            if recorded.get("conflicting_belief_id") != c[0]:
                errs.append("verdict: conflicting_belief_id mismatch")
            if recorded.get("reason_code") != c[1]:
                errs.append("verdict: reason_code mismatch")

        # er1.schema.json: post_state_root equals pre_state_root on ALLOW and is null on HALT
        # (the action did not take effect).
        post = receipt.get("post_state_root")
        if recomputed == "HALT":
            checks["post_state_root"] = post is None
            if not checks["post_state_root"]:
                errs.append("post_state_root: must be null on HALT")
        else:
            checks["post_state_root"] = post == receipt.get("pre_state_root")
            if not checks["post_state_root"]:
                errs.append("post_state_root: must equal pre_state_root on ALLOW")
    except (Er1MalformedReceipt, KeyError, ValueError, TypeError, AttributeError) as exc:
        return {"ok": False, "recomputed_verdict": None, "checks": checks,
                "errors": errs + [f"malformed receipt: {exc}"], "signer": signer}

    return {"ok": not errs, "recomputed_verdict": recomputed, "checks": checks,
            "errors": errs, "signer": signer}


# ── CLI ──

def _receipts_from(doc: Any, label: str) -> list:
    """Discriminate a bundle from a bare receipt UNAMBIGUOUSLY.

    A golden_vectors bundle wraps each receipt as {name, receipt, ...}; a bare receipt has its
    own `decision`/`signature`. A document that presents as both is rejected: an unsigned
    top-level `receipts` array used to decide what got verified, so a forged receipt carrying
    one genuine receipt printed VERIFIED and exited 0."""
    if isinstance(doc, dict) and isinstance(doc.get("receipts"), list):
        if any(k in doc for k in ("decision", "signature", "action", "beliefs")):
            return [(label, "AMBIGUOUS")]
        out = []
        for i, w in enumerate(doc["receipts"]):
            if isinstance(w, dict) and isinstance(w.get("receipt"), dict):
                out.append((f"{label}:{w.get('name')}", w["receipt"]))
            else:
                out.append((f"{label}:entry[{i}]", None))
        return out
    return [(label, doc)]


def _no_duplicate_keys(pairs):
    """JSON parsers silently keep the last of a duplicated key, so 245 bytes of contradictory
    decoy content could ride inside a signed file that still verified. A document whose text
    does not have one unambiguous reading is refused."""
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise Er1MalformedReceipt(f"duplicate object key in the document text: {k!r}")
        seen[k] = v
    return seen


def _reject_lone_surrogates(v: Any) -> None:
    """A lone surrogate cannot be encoded as UTF-8, so it has no canonical byte form. Python
    raised on it and JavaScript happily hashed a replacement character."""
    if isinstance(v, str):
        for ch in v:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise Er1MalformedReceipt("string contains an unpaired surrogate")
    elif isinstance(v, dict):
        for k, x in v.items():
            _reject_lone_surrogates(k)
            _reject_lone_surrogates(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            _reject_lone_surrogates(x)


def load_document(text: str) -> Any:
    """The one parse path. Every rule that makes a document's reading unambiguous lives here,
    so the CLI and any embedder get the same guarantees."""
    def _reject_constant(c):
        # Python's json accepts NaN/Infinity/-Infinity; they are not JSON, and the JS
        # verifiers refuse them, so a document could VERIFY here and fail there.
        raise Er1MalformedReceipt(f"{c} is not valid JSON")

    doc = json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
    _reject_lone_surrogates(doc)
    if not isinstance(doc, dict):
        raise Er1MalformedReceipt(f"top-level JSON must be an object, got {_jt(doc)}")
    return doc


USAGE = ("usage: er1-verify [--pubkey KEY]... <receipt.json | golden_vectors.json> [...]\n"
         "  --pubkey KEY   pin a trusted signer (repeatable). Without it, a receipt is\n"
         "                 verified against the key it carries — see SCOPE_OF_CERTIFICATION.md.")


def main(argv=None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    pinned, paths = set(), []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--pubkey":
            if i + 1 >= len(argv):
                print("error: --pubkey needs a value\n" + USAGE, file=sys.stderr)
                return 2
            pinned.add(argv[i + 1])
            i += 2
            continue
        if a in ("-h", "--help"):
            print(USAGE)
            return 0
        paths.append(a)
        i += 1

    if not paths:
        print(USAGE, file=sys.stderr)
        return 2

    trusted = pinned or None
    all_ok, checked = True, 0
    try:
        for path in paths:
            try:
                # A named pipe, device, or directory blocks forever on read: the tool waits
                # for a writer that never comes, and a CI gate wedges with no verdict, no
                # error and no timeout. A hang is worse than a crash — refuse anything that
                # is not a regular file before opening it.
                st = os.stat(path)
                if not stat.S_ISREG(st.st_mode):
                    raise Er1MalformedReceipt("not a regular file")
                # utf-8-sig: tolerate a BOM some producers add inadvertently. Invalid UTF-8 is
                # a load failure, not something to paper over — the two JS verifiers hashed a
                # replacement character and reported VERIFIED on bytes Python could not read.
                with open(path, encoding="utf-8-sig") as f:
                    text = f.read(MAX_BYTES + 1)
                if len(text) > MAX_BYTES:
                    raise Er1MalformedReceipt(
                        f"input exceeds {MAX_BYTES} bytes — a receipt is a constraint "
                        f"snapshot, not a payload")
                doc = load_document(text)
            except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError,
                    RecursionError) as exc:
                print(f"FAILED ✗  {path}  [could not load: {exc}]")
                all_ok = False
                continue
            for label, receipt in _receipts_from(doc, path):
                checked += 1
                if receipt is None:
                    print(f"FAILED ✗  {label}  [malformed bundle entry: no receipt object]")
                    all_ok = False
                    continue
                if receipt == "AMBIGUOUS":
                    print(f"FAILED ✗  {label}  [ambiguous document: carries both receipt "
                          f"fields and a `receipts` array]")
                    all_ok = False
                    continue
                try:
                    res = verify(receipt, trusted)
                except Er1MissingCrypto as exc:
                    print(f"error: {exc}", file=sys.stderr)
                    return 2
                d = receipt.get("decision") if isinstance(receipt.get("decision"), dict) else {}
                status = "VERIFIED ✓" if res["ok"] else "FAILED ✗"
                try:
                    short = receipt_hash(receipt)[:18] + "…"
                except (Er1MalformedReceipt, ValueError, TypeError, RecursionError):
                    short = "<uncanonicalizable>"
                signer = res.get("signer")
                # The signer is always shown: this verifier proves a receipt is internally
                # consistent and signed by the key it names — not that the key belongs to
                # anyone you trust. Pin with --pubkey.
                sig_note = (f"signer={signer[:12]}…" if isinstance(signer, str) and len(signer) > 12
                            else f"signer={signer}")
                if trusted is None and isinstance(signer, str):
                    sig_note += " (unpinned)"
                print(f"{status}  {label}  verdict={d.get('verdict')} "
                      f"(recomputed {res['recomputed_verdict']})  hash={short}  {sig_note}")
                for e in res["errors"]:
                    print(f"    ! {e}")
                all_ok = all_ok and res["ok"]
    except BrokenPipeError:
        # `er1-verify … | head` closes stdout early. Exiting 0 here would report success for
        # receipts that were never checked, so an interrupted run is always a failure.
        try:
            sys.stdout.close()
        except BrokenPipeError:
            pass
        return 1

    if checked == 0 and all_ok:
        # An empty bundle must never pass a CI gate by saying nothing.
        print("FAILED ✗  no receipts found in input", file=sys.stderr)
        return 1
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
