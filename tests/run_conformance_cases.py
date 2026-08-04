#!/usr/bin/env python3
"""Run the shared adversarial corpus against the Python reference verifier.

    python3 tests/run_conformance_cases.py

Also exposed as pytest cases so `pytest` covers it. The same corpus runs against Node
(tests/run_conformance_cases.mjs) and the browser build — three implementations, one set of
expectations.
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))

import er1_verify as ER1  # noqa: E402

CORPUS = json.loads((HERE / "conformance_cases.json").read_text())


def run_case(c: dict) -> tuple[bool, str]:
    try:
        res = ER1.verify(c["doc"])
    except Exception as exc:                      # a crash is always a failure
        return False, f"THREW: {type(exc).__name__}: {exc}"
    errs = " | ".join(res["errors"])
    if res["ok"] != c["expect_ok"]:
        return False, f"ok={res['ok']} (expected {c['expect_ok']}) errors={errs}"
    if c["error_contains"] and c["error_contains"] not in errs:
        return False, f"missing {c['error_contains']!r} in errors={errs}"
    return True, errs


def test_every_conformance_case():
    failures = []
    for c in CORPUS["cases"]:
        ok, detail = run_case(c)
        if not ok:
            failures.append(f"{c['name']}: {detail}")
    assert not failures, "\n".join(failures)


if __name__ == "__main__":
    bad = 0
    for case in CORPUS["cases"]:
        ok, detail = run_case(case)
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {case['name']}")
        if not ok:
            print(f"      {detail}")
    total = len(CORPUS["cases"])
    print(f"\n{total - bad}/{total} conformance cases pass")
    raise SystemExit(1 if bad else 0)
