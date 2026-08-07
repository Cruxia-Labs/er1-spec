"""Cross-language conformance — the JavaScript reference verifier (`er1_verify.mjs`) agrees with the
Python one byte-for-byte on the published golden vectors, and rejects tampering. Two independent
implementations re-deriving the same verdict from the same signed bytes is what makes ER1 a standard.

Skipped automatically if Node is not installed."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
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
    assert r.stdout.count("VERIFIED ✓") == 10
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


# ── the report is a trusted surface in BOTH implementations ──
#
# Everything below was fixed in er1_verify.py and er1_verify.mjs at the same time, and tested in
# Python only. A mutation gate run (tests/mutation_gate.py) then neutered each guard in the .mjs
# and the whole suite stayed green: the Node copies of these fixes had no test at all. That is the
# class-vs-instance failure this repo keeps repeating, one level up — not "the test covered one
# case of the bug" but "the test covered one IMPLEMENTATION of the fix".
#
# Each test pins the property absolutely (the forgery does not work) and then differentially (the
# two CLIs render it identically), because a standard with two reference implementations is only
# a standard while they agree.

def _run_py(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(HERE / "er1_verify.py"), *args],
                          capture_output=True, text=True, cwd=HERE)


def _status_lines(out: str) -> list[str]:
    return [ln for ln in out.splitlines() if ln.startswith(("VERIFIED", "FAILED"))]


def test_js_unsigned_bundle_name_cannot_forge_a_line_of_the_report(tmp_path):
    """The Node mirror of test_conformance.py::test_an_unsigned_bundle_name_cannot_forge_a_line…

    `name` sits outside every signature. Interpolated raw, a name carrying a newline plus a
    plausible VERIFIED line printed exactly that, as its own line, out of a receipt that FAILED —
    and grepping the report is what a CI gate does."""
    forged = ("evil\nVERIFIED ✓  prod-deploy-approval  verdict=ALLOW "
              "(recomputed ALLOW)  hash=deadbeef…  signer=trusted")
    vectors = json.loads((HERE / "golden_vectors.json").read_text())
    bad = json.loads(json.dumps(vectors["receipts"][3]["receipt"]))
    bad["decision"]["verdict"] = "HALT"                 # inconsistent with its own signature
    p = tmp_path / "forged_name.json"
    p.write_text(json.dumps({"receipts": [{"name": forged, "receipt": bad}]}))

    r = _run(str(p))
    assert r.returncode == 1
    lines = _status_lines(r.stdout)
    assert len(lines) == 1, f"the name forged extra status lines: {lines}"
    assert lines[0].startswith("FAILED"), lines[0]
    assert "entry[0]" in lines[0], "the index must be the authoritative label"
    # The two reports must be byte-identical, or the standard has two readings of one file.
    assert _status_lines(_run_py(str(p)).stdout) == lines


def test_js_empty_input_fails_even_when_another_input_verifies(tmp_path):
    """"Nothing checked is never a pass" is a per-INPUT rule. As a whole-run condition it only
    fired when EVERY input was empty, so one good file covered an empty one and the empty file was
    never even named in the report."""
    vectors = json.loads((HERE / "golden_vectors.json").read_text())
    good = tmp_path / "good.json"
    good.write_text(json.dumps(vectors["receipts"][3]["receipt"]))
    assert _run(str(good)).returncode == 0, "the good file alone must still pass"

    empty = tmp_path / "empty_bundle.json"
    empty.write_text('{"receipts": []}')
    for argv in ([str(good), str(empty)], [str(empty), str(good)]):
        r = _run(*argv)
        assert r.returncode == 1, f"empty input passed in position {argv.index(str(empty))}"
        assert "empty_bundle.json" in r.stdout + r.stderr, "the empty input was never reported"
        assert _run_py(*argv).returncode == r.returncode


def test_js_refuses_a_document_with_duplicate_keys(tmp_path):
    """Parsers silently keep the last of a duplicated key, so contradictory decoy content can ride
    inside a signed file that still verifies. This guard was once dead code in the .mjs — it tested
    a Set that was never written to — so Node verified documents Python refused."""
    p = tmp_path / "dup.json"
    p.write_text('{"schema_version": "action-receipt/v0", "schema_version": "decoy"}')
    r = _run(str(p))
    assert r.returncode == 1
    assert "could not load" in r.stdout, r.stdout
    assert "duplicate object key" in r.stdout, r.stdout
    assert _run_py(str(p)).returncode == 1


def test_js_refuses_invalid_utf8_instead_of_substituting(tmp_path):
    """Node once read files with readFileSync(path, "utf8"), which substitutes U+FFFD for malformed
    bytes: four BYTE-DISTINCT tampered files all verified against one signature, with one hash,
    while Python refused every one. Invalid UTF-8 is a load failure, not something to paper over.

    Asserting the exit code alone would not catch a regression here — a substituted file still
    FAILS on its signature. The distinguishing observation is that it never loads at all."""
    vectors = json.loads((HERE / "golden_vectors.json").read_text())
    raw = json.dumps(vectors["receipts"][3]["receipt"]).encode()
    hashes = set()
    for bad_byte in (b"\xff", b"\xfe", b"\xc0", b"\x80"):
        p = tmp_path / f"bad{bad_byte.hex()}.json"
        p.write_bytes(raw[:40] + bad_byte + raw[41:])
        r = _run(str(p))
        assert r.returncode == 1
        assert "could not load" in r.stdout, f"{bad_byte.hex()} was decoded, not refused: {r.stdout}"
        hashes.update(re.findall(r"hash=(\S+)", r.stdout))
        assert _run_py(str(p)).returncode == 1
    assert not hashes, f"byte-distinct malformed inputs produced hashes: {hashes}"
