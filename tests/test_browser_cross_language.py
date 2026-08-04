"""THREE-way cross-language conformance — the BROWSER verifier (verify/er1_verify.browser.mjs,
WebCrypto-only, no Node built-ins) must byte-agree with BOTH reference verifiers on every golden
vector, every verdict-flip tamper, and the real tamper pairs in tests/fixtures/.

The Node runner (tests/test_browser_verifier.mjs) already asserts exact agreement between the
browser module and er1_verify.mjs (same errors strings, same hashes) while running the module
under Node's own globalThis.crypto.subtle with network globals trapped. This file shells out to
that runner with --json and closes the triangle against the PYTHON reference (er1_verify.py):
identical ok, identical recomputed verdict, identical receipt hash, identical error CLASSES.

(Error classes, not raw strings, because the two languages quote the recorded verdict differently:
Python repr() -> 'PASS', JS JSON.stringify -> "PASS". Everything before the quoting is identical.)

Skipped automatically if Node is not installed."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

import er1_verify as ER1

HERE = Path(__file__).parent
ROOT = HERE.parent
FIXDIR = HERE / "fixtures"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")


def _error_class(e: str) -> str:
    """'verdict: recomputed HALT vs recorded "PASS"' and Python's '...recorded \'PASS\'' both
    normalize to the same class token; non-verdict errors are identical strings already."""
    for cls in ("signature: invalid or missing", "action_binding: args_hash mismatch",
                "pre_state_root mismatch", "verdict: conflicting_belief_id mismatch",
                "verdict: reason_code mismatch"):
        if e == cls:
            return cls
    if e.startswith("verdict: recomputed "):
        return "verdict: recomputed-mismatch [" + e.split(" vs recorded ")[0].split()[-1] + "]"
    return e


def _browser_results() -> list[dict]:
    r = subprocess.run([NODE, str(HERE / "test_browser_verifier.mjs"), "--json"],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads(r.stdout)["results"]


def _python_cases() -> dict[tuple, dict]:
    """Rebuild the exact case set the Node runner covers, keyed by (kind, name)."""
    cases = {}
    golden = json.loads((ROOT / "golden_vectors.json").read_text())
    for w in golden["receipts"]:
        cases[("golden", w["name"])] = w["receipt"]
        forged = copy.deepcopy(w["receipt"])
        forged["decision"]["verdict"] = "ALLOW" if forged["decision"]["verdict"] == "HALT" else "HALT"
        cases[("golden_tampered", w["name"])] = forged
    for tf in sorted(FIXDIR.glob("*.er1.tampered.json")):
        clean = tf.with_name(tf.name.replace(".er1.tampered.json", ".er1.json"))
        cases[("fixture", clean.name)] = json.loads(clean.read_text())
        cases[("fixture_tampered", tf.name)] = json.loads(tf.read_text())
    return cases


def test_browser_runner_is_green():
    """The Node runner itself (static no-builtins scan, network traps, feature-detect path,
    byte-agreement with er1_verify.mjs) exits 0."""
    r = subprocess.run([NODE, str(HERE / "test_browser_verifier.mjs")],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "byte-agreement with er1_verify.mjs" in r.stdout


def test_browser_verdicts_agree_with_python_on_every_case():
    results = _browser_results()
    cases = _python_cases()
    assert len(results) == len(cases) >= 16  # 6 golden + 6 flips + >=2 fixture pairs
    for entry in results:
        key = (entry["kind"], entry["name"])
        assert key in cases, f"browser runner produced an unknown case {key}"
        py = ER1.verify(cases[key])
        label = ":".join(key)
        assert entry["ok"] == py["ok"], f"{label}: ok diverges (browser vs python)"
        assert entry["recomputedVerdict"] == py["recomputed_verdict"], f"{label}: verdict diverges"
        assert entry["receiptHash"] == ER1.receipt_hash(cases[key]), f"{label}: canonical hash diverges"
        assert sorted(map(_error_class, entry["errors"])) == \
               sorted(map(_error_class, py["errors"])), f"{label}: error classes diverge"


def test_fixture_pairs_cover_both_directions():
    """At least 2 real tamper pairs, and every untampered twin VERIFIES under Python while every
    tampered one FAILS on both the signature and the verdict recompute."""
    tampered = sorted(FIXDIR.glob("*.er1.tampered.json"))
    assert len(tampered) >= 2
    for tf in tampered:
        clean = tf.with_name(tf.name.replace(".er1.tampered.json", ".er1.json"))
        assert clean.exists(), f"missing untampered twin for {tf.name}"
        good = ER1.verify(json.loads(clean.read_text()))
        assert good["ok"], f"{clean.name}: {good['errors']}"
        bad = ER1.verify(json.loads(tf.read_text()))
        assert not bad["ok"]
        assert not bad["checks"]["signature"]  # tamper-evident
        # The tamper must ALSO be caught without the signature — either the recomputed verdict
        # disagrees with the recorded one, or the tampered document no longer satisfies the
        # structural rules. Both are recomputation catching the lie; asserting only the first
        # would make a stricter verifier look like a regression.
        assert bad["checks"].get("verdict") is False or any(
            e.startswith("malformed receipt:") for e in bad["errors"]
        ), bad["errors"]
