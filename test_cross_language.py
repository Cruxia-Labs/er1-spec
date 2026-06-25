"""Cross-language conformance — the JavaScript reference verifier (`er1_verify.mjs`) agrees with the
Python one byte-for-byte on the published golden vectors, and rejects tampering. Two independent
implementations re-deriving the same verdict from the same signed bytes is what makes ER1 a standard.

Skipped automatically if Node is not installed."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import er1_verify as ER1

HERE = Path(__file__).parent
NODE = shutil.which("node")
# Skipped when the node binary is not found (skipif condition True => skip).
pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([NODE, str(HERE / "er1_verify.mjs"), *args],
                          capture_output=True, text=True, cwd=HERE)


def test_js_verifies_every_golden_vector():
    r = _run("golden_vectors.json")
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.count("VERIFIED ✓") == 6
    assert "FAILED" not in r.stdout


def test_js_receipt_hashes_match_python_recorded_hashes():
    """The JS-computed canonical hash equals the hash recorded (by Python) in the vectors — i.e. the
    two canonicalizers produce identical bytes."""
    vectors = json.loads((HERE / "golden_vectors.json").read_text())
    r = _run("golden_vectors.json")
    for w in vectors["receipts"]:
        short = w["receipt_hash"][:18]
        assert f"hash={short}" in r.stdout, f"{w['name']}: JS hash != recorded {short}"


def test_js_rejects_a_tampered_receipt(tmp_path):
    vectors = json.loads((HERE / "golden_vectors.json").read_text())
    receipt = json.loads(json.dumps(vectors["receipts"][3]["receipt"]))  # a coherent ALLOW
    receipt["beliefs"].append({                                          # inject a banned-entity rule
        "belief_id": "lib:evil", "belief_class": "CERTIFIED", "entity": "lib:evil",
        "rule": "excludes", "source_kind": "deterministic", "status": "active", "value": "banned"})
    p = tmp_path / "tampered.json"
    p.write_text(json.dumps(receipt))
    r = _run(str(p))
    assert r.returncode == 1
    assert "FAILED ✗" in r.stdout                # signature no longer covers the mutated body


def test_prototype_named_entity_does_not_diverge(tmp_path):
    """An entity named like a JS built-in ('toString') must NOT create a phantom conflict in the JS
    verifier (a naive `in` check would see Object.prototype). Python and JS must both recompute ALLOW."""
    crafted = {
        "schema_version": "action-receipt/v0",
        "decision": {"verdict": "ALLOW", "reason_code": None, "conflicting_belief_id": None},
        "beliefs": [{"belief_id": "lib:toString", "belief_class": "CERTIFIED", "entity": "toString",
                     "rule": "excludes", "source_kind": "deterministic", "status": "active",
                     "value": "banned"}],
        "action": {"tool": "noop", "asserts": {}, "resource": ""},
        "action_binding": {"tool": "noop", "args_hash": "sha256:" + "0" * 64, "resource": ""},
        "pre_state_root": "sha256:" + "0" * 64,
        "signature": {"algorithm": "ed25519", "public_key": "AA", "signature": "AA"},
    }
    # Python: empty asserts -> the banned 'toString' is not used -> ALLOW.
    assert ER1.verify(crafted)["recomputed_verdict"] == "ALLOW"
    # JS: must agree. (Bogus signature -> the receipt FAILS overall, but a phantom HALT in the
    # recomputed verdict would mean prototype pollution diverged the two verifiers.)
    p = tmp_path / "proto.json"
    p.write_text(json.dumps(crafted))
    assert "recomputed ALLOW" in _run(str(p)).stdout


def test_unicode_canonicalization_is_byte_identical(tmp_path):
    """Non-ASCII strings must canonicalize identically in Python and JS (NFC + \\uXXXX escaping +
    surrogate pairs), so the receipt_hash matches across languages. Receipts are ASCII today; this
    proves the cross-language byte-equality claim holds for Unicode (incl. supplementary-plane) too."""
    text = "café — naïve — 日本語 — 𝟙𝟚 — 😀"
    crafted = {
        "schema_version": "action-receipt/v0",
        "decision": {"verdict": "ALLOW", "reason_code": None, "conflicting_belief_id": None},
        "beliefs": [{"belief_id": "ui.label", "belief_class": "BEST_EFFORT", "entity": "ui.label",
                     "rule": "equals", "source_kind": "nl_extracted", "status": "active", "value": text}],
        "action": {"tool": "set_label", "asserts": {"ui.label": text}, "resource": "ui/label"},
        "action_binding": {"tool": "set_label", "args_hash": "sha256:" + "0" * 64, "resource": "ui/label"},
        "pre_state_root": "sha256:" + "0" * 64,
        "signature": {"algorithm": "ed25519", "public_key": "AA", "signature": "AA"},
    }
    py_hash = ER1.receipt_hash(crafted)                       # Python canonical hash of the body
    p = tmp_path / "unicode.json"
    p.write_text(json.dumps(crafted, ensure_ascii=False), encoding="utf-8")
    out = _run(str(p)).stdout
    assert f"hash={py_hash[:18]}" in out, f"canon diverged on Unicode: py={py_hash[:18]} | js={out}"


def test_tilde_equals_is_compatible_release_not_exact(tmp_path):
    """`~=2.0` is PEP 440 compatible-release (>=2.0, <3.0), NOT exact match: 2.5 must be ALLOWED and
    3.0 HALTed. The old code treated ~= as == and wrongly HALTed 2.5. Python and JS must agree."""
    def doc(proposed):
        return {
            "schema_version": "action-receipt/v0",
            "decision": {"verdict": "ALLOW", "reason_code": None, "conflicting_belief_id": None},
            "beliefs": [{"belief_id": "dep:lib", "belief_class": "CERTIFIED", "entity": "dep:lib",
                         "rule": "satisfies", "source_kind": "deterministic", "status": "active", "value": "~=2.0"}],
            "action": {"tool": "pip_install", "asserts": {"dep:lib": proposed}, "resource": "requirements.txt"},
            "action_binding": {"tool": "pip_install", "args_hash": "sha256:" + "0" * 64, "resource": "requirements.txt"},
            "pre_state_root": "sha256:" + "0" * 64,
            "signature": {"algorithm": "ed25519", "public_key": "AA", "signature": "AA"},
        }
    assert ER1.verify(doc("2.5"))["recomputed_verdict"] == "ALLOW"   # 2.5 satisfies ~=2.0
    assert ER1.verify(doc("3.0"))["recomputed_verdict"] == "HALT"    # 3.0 does not
    p = tmp_path / "tilde.json"; p.write_text(json.dumps(doc("2.5")))
    assert "recomputed ALLOW" in _run(str(p)).stdout                 # JS agrees on the once-buggy case
