#!/usr/bin/env python3
"""Cross-engine browser matrix for verify/er1_verify.browser.mjs — runs the golden vectors,
verdict-flip tampers, and the tests/fixtures/ tamper pairs inside REAL browser engines via
Playwright (Chromium / Firefox / WebKit), loading verify/index.html from a loopback-only static
server (the module itself still performs zero I/O; the server only delivers the page + module,
exactly as a user's static host would).

NOT collected by pytest (needs Playwright, which is not a dependency of this repo). Run with any
Python that has `playwright` and browsers installed:

    python tests/run_browser_matrix.py                # all engines that are installed
    python tests/run_browser_matrix.py chromium       # one engine

Engines whose browser build is not downloaded are reported PENDING and do not fail the run;
results are recorded in tests/BROWSER_MATRIX.md. Exit code: 0 iff every INSTALLED engine passes.
"""
from __future__ import annotations

import copy
import json
import os
import socketserver
import sys
import threading
from http.server import SimpleHTTPRequestHandler
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXDIR = HERE / "fixtures"

# The page-side driver: runs every case through window.__er1 (the module's exports) and returns
# plain data. Receives [cases] where each case = {kind, name, receipt, expect: {...}}.
PAGE_DRIVER = """
async (cases) => {
  const { verify, receiptHash, Er1UnsupportedCryptoError } = window.__er1;
  const out = [];
  for (const c of cases) {
    try {
      const res = await verify(c.receipt);
      out.push({ kind: c.kind, name: c.name, ok: res.ok, recomputedVerdict: res.recomputedVerdict,
                 receiptHash: await receiptHash(c.receipt), errors: res.errors,
                 checks: res.checks, threw: null });
    } catch (e) {
      out.push({ kind: c.kind, name: c.name, threw: (e instanceof Er1UnsupportedCryptoError)
                 ? "Er1UnsupportedCryptoError" : String(e) });
    }
  }
  return out;
}
"""


def build_cases() -> list[dict]:
    cases = []
    golden = json.loads((ROOT / "golden_vectors.json").read_text())
    for w in golden["receipts"]:
        cases.append({"kind": "golden", "name": w["name"], "receipt": w["receipt"],
                      "expect": {"ok": True, "verdict": w["verdict"], "hash": w["receipt_hash"]}})
        forged = copy.deepcopy(w["receipt"])
        forged["decision"]["verdict"] = "ALLOW" if forged["decision"]["verdict"] == "HALT" else "HALT"
        cases.append({"kind": "golden_tampered", "name": w["name"], "receipt": forged,
                      "expect": {"ok": False}})
    for tf in sorted(FIXDIR.glob("*.er1.tampered.json")):
        clean = tf.with_name(tf.name.replace(".er1.tampered.json", ".er1.json"))
        cases.append({"kind": "fixture", "name": clean.name,
                      "receipt": json.loads(clean.read_text()), "expect": {"ok": True}})
        cases.append({"kind": "fixture_tampered", "name": tf.name,
                      "receipt": json.loads(tf.read_text()), "expect": {"ok": False}})
    return cases


def check(engine: str, cases: list[dict], results: list[dict]) -> list[str]:
    problems = []
    by_key = {(c["kind"], c["name"]): c for c in cases}
    for r in results:
        c = by_key[(r["kind"], r["name"])]
        label = f"{engine}:{r['kind']}:{r['name']}"
        if r.get("threw"):
            problems.append(f"{label}: threw {r['threw']}")
            continue
        exp = c["expect"]
        if r["ok"] != exp["ok"]:
            problems.append(f"{label}: ok={r['ok']} expected {exp['ok']} errors={r.get('errors')}")
        if exp.get("verdict") and r["recomputedVerdict"] != exp["verdict"]:
            problems.append(f"{label}: verdict {r['recomputedVerdict']} != {exp['verdict']}")
        if exp.get("hash") and r["receiptHash"] != exp["hash"]:
            problems.append(f"{label}: hash diverged")
        if not exp["ok"]:
            if r["checks"]["signature"] or r["checks"]["verdict"]:
                problems.append(f"{label}: tamper must fail signature AND verdict recompute")
    return problems


def main(argv: list[str]) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("PENDING: playwright not importable under this Python — see tests/BROWSER_MATRIX.md")
        return 0

    engines = argv or ["chromium", "firefox", "webkit"]
    cases = build_cases()

    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *a):  # keep test output clean
            pass

    os.chdir(ROOT)  # serve the repo root so /verify/... resolves
    httpd = socketserver.TCPServer(("127.0.0.1", 0), Quiet)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    failed = False
    with sync_playwright() as p:
        for name in engines:
            bt = getattr(p, name)
            if not Path(bt.executable_path).exists():
                print(f"{name}: PENDING — browser build not downloaded "
                      f"(python -m playwright install {name})")
                continue
            browser = bt.launch(headless=True)
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{port}/verify/index.html")
            page.wait_for_function("() => !!window.__er1")
            results = page.evaluate(PAGE_DRIVER, cases)
            version = browser.version
            browser.close()
            problems = check(name, cases, results)
            n_ok = sum(1 for r in results if not r.get("threw") and r["ok"])
            n_fail = sum(1 for r in results if not r.get("threw") and not r["ok"])
            if problems:
                failed = True
                print(f"{name} ({version}): FAIL")
                for pr in problems:
                    print(f"    ! {pr}")
            else:
                print(f"{name} ({version}): PASS — {n_ok} cases VERIFIED, "
                      f"{n_fail} tamper cases FAILED as required ({len(results)} total)")
    httpd.shutdown()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
