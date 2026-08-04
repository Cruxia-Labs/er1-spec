"""The adversarial corpus GATES CI — all three implementations, one set of expectations.

tests/conformance_cases.json is the anti-drift mechanism: every case is a receipt that had once
produced VERIFIED, a crash, or a cross-language disagreement. Both runners existed and were green,
but nothing executed them:

  * tests/run_conformance_cases.py defines test_every_conformance_case(), but pytest's default
    `python_files` pattern is test_*.py, so the file was never collected;
  * tests/run_conformance_cases.mjs was not invoked by .github/workflows/ci.yml at all;
  * the browser build ran the golden vectors and tamper pairs, never the corpus.

So a corpus case could not have failed a build, which is the whole reason the corpus exists. This
file closes that: the corpus runs against er1_verify.py in-process and against both JavaScript
builds by subprocess, and the three must agree case by case.

Skipped automatically if Node is not installed."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import er1_verify as ER1

HERE = Path(__file__).parent
ROOT = HERE.parent
CORPUS = json.loads((HERE / "conformance_cases.json").read_text())["cases"]
NODE = shutil.which("node")

# The two runtime-inherent renderings that are NOT drift. Everything else must match byte for
# byte, so a real divergence cannot hide behind a normalizer.
#   * an absent key reads as None in Python and undefined in JavaScript;
#   * JSON.parse rounds 2**53+1 to 2**53 before the verifier ever sees it — both reject, the
#     quoted literal differs by one.
def _error_class(e: str) -> str:
    return e.replace("got undefined", "got null").replace("9007199254740993", "9007199254740992")


def _classes(errors: list[str]) -> list[str]:
    return [_error_class(e) for e in errors]


def _js_results(*flags: str) -> dict[str, dict]:
    """Run the corpus through a JavaScript build and return {case name: result}."""
    # The runner exits 1 when a case fails; that is data, not an error. Read the results either
    # way so the assertions below report the specific divergence instead of "the runner failed".
    proc = subprocess.run([NODE, str(HERE / "run_conformance_cases.mjs"), "--json", *flags],
                          capture_output=True, text=True, cwd=ROOT)
    try:
        results = json.loads(proc.stdout)["results"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise AssertionError(
            f"JS corpus runner produced no results ({exc}):\n{proc.stdout}\n{proc.stderr}") from exc
    return {r["name"]: r for r in results}


def _python_results() -> dict[str, dict]:
    out = {}
    for c in CORPUS:
        try:
            res = ER1.verify(c["doc"])
        except Exception as exc:                       # a crash is always a failure
            res = {"ok": None, "errors": [f"THREW: {type(exc).__name__}: {exc}"]}
        out[c["name"]] = res
    return out


def test_the_corpus_is_not_empty_and_every_case_must_be_refused():
    """A corpus that silently emptied itself would make every gate below vacuous."""
    assert len(CORPUS) >= 36
    assert all(c["expect_ok"] is False for c in CORPUS)
    assert len({c["name"] for c in CORPUS}) == len(CORPUS), "duplicate case names"


def test_python_refuses_every_conformance_case():
    results = _python_results()
    failures = []
    for c in CORPUS:
        res = results[c["name"]]
        errs = " | ".join(res["errors"])
        if res["ok"] != c["expect_ok"]:
            failures.append(f"{c['name']}: ok={res['ok']} (expected {c['expect_ok']}) {errs}")
        elif c["error_contains"] and c["error_contains"] not in errs:
            failures.append(f"{c['name']}: missing {c['error_contains']!r} in {errs}")
    assert not failures, "\n".join(failures)


@pytest.mark.skipif(NODE is None, reason="node not installed")
@pytest.mark.parametrize("flags,label", [((), "er1_verify.mjs"), (("--browser",), "browser build")])
def test_javascript_builds_refuse_every_conformance_case(flags, label):
    results = _js_results(*flags)
    assert set(results) == {c["name"] for c in CORPUS}, f"{label} skipped cases"
    failures = []
    for c in CORPUS:
        res = results[c["name"]]
        if not res["pass"]:
            failures.append(f"{c['name']}: ok={res['ok']} errors={res['errors']}")
    assert not failures, f"{label}:\n" + "\n".join(failures)


@pytest.mark.skipif(NODE is None, reason="node not installed")
@pytest.mark.parametrize("flags,label", [((), "er1_verify.mjs"), (("--browser",), "browser build")])
def test_python_and_javascript_agree_case_by_case(flags, label):
    """The soundness property the corpus exists to protect: the same bytes, the same answer.

    `ok` must be identical — a CI gate on one verifier must not admit what the other refuses —
    and so must the error classes, so the two cannot reach the same verdict for different
    reasons."""
    py, js = _python_results(), _js_results(*flags)
    disagree = []
    for c in CORPUS:
        p, j = py[c["name"]], js[c["name"]]
        pe = " | ".join(_classes(p["errors"]))
        je = " | ".join(_classes(j["errors"].split(" | "))) if j["errors"] else ""
        if p["ok"] != j["ok"] or pe != je:
            disagree.append(f"{c['name']}:\n    py  ok={p['ok']} {pe}\n    {label} ok={j['ok']} {je}")
    assert not disagree, "cross-language divergence:\n" + "\n".join(disagree)


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_explicit_null_enum_fields_are_refused_by_every_implementation():
    """The 2026-08-04 divergence, pinned: `?? "active"` fires on an explicit null and
    dict.get(k, "active") does not, so `"status": null` verified under Node and failed under
    Python on the same file. The schema requires a string for all three enum fields, so every
    implementation must refuse all three — no implicit default in either language."""
    names = [f"{f}_explicit_null" for f in ("status", "source_kind", "belief_class")]
    by_name = {c["name"]: c for c in CORPUS}
    assert set(names) <= set(by_name), f"corpus lost a case: {set(names) - set(by_name)}"

    py, node, browser = _python_results(), _js_results(), _js_results("--browser")
    for name in names:
        field = name[: -len("_explicit_null")]
        assert by_name[name]["doc"]["beliefs"][0][field] is None, f"{name} stopped testing null"
        for label, errors in (("python", py[name]["errors"]),
                              ("node", node[name]["errors"]),
                              ("browser", browser[name]["errors"])):
            errs = " | ".join(errors) if isinstance(errors, list) else errors
            # ok=False is NOT enough: these fixtures are unsigned, so the signature error alone
            # would satisfy it while the enum field was quietly defaulted. Demand the field.
            assert f"beliefs[0].{field}" in errs, (
                f"{label} did not refuse {field}=null on its own account: {errs}")
