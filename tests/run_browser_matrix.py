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
            # A tampered receipt must not pass either gate. Since the v1.1 rebuild, structural
            # validation runs BEFORE the predicate and returns early, so `checks` may legitimately
            # carry no `verdict` key at all — the receipt never reached the recompute. Treat an
            # absent check as "did not pass", which is what it means; indexing it blindly turned
            # a correct refusal into a KeyError crash the first time this matrix ran after the
            # rebuild. (It had not run since: playwright was not installed, so this guard sat
            # unexecuted while the code beneath it changed.)
            if r["checks"].get("signature") or r["checks"].get("verdict"):
                problems.append(f"{label}: tamper must fail signature AND verdict recompute")
    return problems



# The PAGE driver. PAGE_DRIVER above calls window.__er1 directly, which is the module; this one
# types into the textarea and clicks Verify like a user, then reads what the page rendered. That
# distinction is not academic: verify/index.html once parsed with bare JSON.parse and shipped its
# own loose bundle-splitter, so a forged document rendered green VERIFIED while both CLIs refused
# it — and the matrix stayed green the whole time, because it was testing the module underneath.
PAGE_UI_DRIVER = """
async (docs) => {
  const out = [];
  for (const d of docs) {
    document.getElementById('input').value = d.text;
    document.getElementById('out').innerHTML = '';
    document.getElementById('run').click();
    await new Promise(r => setTimeout(r, 800));
    const rendered = document.getElementById('out').innerText.trim();
    out.push({ name: d.name, verified: /VERIFIED/.test(rendered), rendered: rendered.slice(0, 200) });
  }
  return out;
}
"""


def ui_cases():
    """Documents the PAGE must refuse, plus one it must accept. Each attack is one the page
    actually rendered as VERIFIED before the load path was routed through loadDocument."""
    golden = json.loads((ROOT / "golden_vectors.json").read_text())
    genuine = golden["receipts"][3]["receipt"]
    forged = {
        "schema_version": "action-receipt/v0", "receipt_id": "prod-deploy-approval",
        "created_at": "2026-01-01T00:00:00Z",
        "chain": {"sequence_number": 0, "prev_receipt_hash": None},
        "pre_state_root": "sha256:" + "0" * 64, "post_state_root": "sha256:" + "0" * 64,
        "action": {"tool": "deploy", "asserts": {"env:DEPLOY_TARGET": "production"},
                   "resource": "k8s://prod"},
        "action_binding": {"tool": "deploy", "args_hash": "sha256:" + "0" * 64,
                           "resource": "k8s://prod"},
        "beliefs": [], "decision": {"verdict": "ALLOW"},
        "coverage": {"exclusions": []}, "operator_version": "forged/1",
        "signature": {"algorithm": "ed25519", "public_key": "A" * 43, "signature": "A" * 86},
        "receipts": [{"name": "prod-deploy-approval", "receipt": genuine}],
    }
    genuine_text = json.dumps(genuine)
    hostile_name = ("evil\nVERIFIED \u2713  prod-deploy-approval  verdict=ALLOW  "
                    "signer=trusted")
    # A document over the 8 MiB bound both CLIs enforce. Padding rides in a free-text value, so
    # the document stays structurally valid and the ONLY reason to refuse it is the size rule.
    oversize = copy.deepcopy(genuine)
    oversize["action"]["resource"] = "k8s://" + "A" * (8 * 1024 * 1024)
    return [
        {"name": "ambiguous_receipt_and_bundle", "text": json.dumps(forged), "expect_verified": False},
        {"name": "duplicate_decision_key",
         "text": '{"decision": {"verdict":"ALLOW","note":"decoy"}, ' + genuine_text[1:],
         "expect_verified": False},
        {"name": "unpaired_surrogate_in_name",
         "text": json.dumps({"receipts": [{"name": "prod\\ud800", "receipt": genuine}]})
                 .replace("\\\\ud800", "\\ud800"),
         "expect_verified": False},
        {"name": "genuine_receipt_still_accepted", "text": genuine_text, "expect_verified": True,
         # The page proves a receipt is signed by the key it NAMES, not that the key is trusted.
         # A green VERIFIED with no visible signer invites exactly the wrong conclusion.
         "expect_contains": ["signer=", "(unpinned)"]},
        {"name": "oversize_input_refused", "text": json.dumps(oversize), "expect_verified": False,
         "expect_contains": ["exceeds"]},
        {"name": "hostile_bundle_name_cannot_spoof_the_label",
         "text": json.dumps({"receipts": [{"name": hostile_name, "receipt": genuine}]}),
         # Genuine receipt, so it VERIFIES — the point is that the label is the index and the
         # unsigned name cannot occupy the place a reader looks for the verdict.
         "expect_verified": True, "expect_contains": ["entry[0]"]},
    ]


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
            ui = page.evaluate(PAGE_UI_DRIVER, ui_cases())
            version = browser.version
            browser.close()
            problems = check(name, cases, results)
            for got, want in zip(ui, ui_cases()):
                if got["verified"] != want["expect_verified"]:
                    problems.append(
                        f"PAGE UI {got['name']}: rendered "
                        f"{'VERIFIED' if got['verified'] else 'FAILED'}, expected "
                        f"{'VERIFIED' if want['expect_verified'] else 'FAILED'} "
                        f"-- {got['rendered'][:110]}")
                # A verdict-only assertion cannot see whether the page told the user WHO signed,
                # or refused for the right reason. Both were missing while the matrix was green.
                for needle in want.get("expect_contains", []):
                    if needle not in got["rendered"]:
                        problems.append(
                            f"PAGE UI {got['name']}: rendered output lacks {needle!r} "
                            f"-- {got['rendered'][:110]}")
            n_ok = sum(1 for r in results if not r.get("threw") and r["ok"])
            n_fail = sum(1 for r in results if not r.get("threw") and not r["ok"])
            if problems:
                failed = True
                print(f"{name} ({version}): FAIL")
                for pr in problems:
                    print(f"    ! {pr}")
            else:
                # Report the page-UI count explicitly. A guard you cannot see run is a guard
                # you will not notice stopping — the failure mode this whole suite keeps hitting.
                ui_refused = sum(1 for g in ui if not g["verified"])
                ui_accepted = sum(1 for g in ui if g["verified"])
                print(f"{name} ({version}): PASS — {n_ok} cases VERIFIED, "
                      f"{n_fail} tamper cases FAILED as required ({len(results)} total); "
                      f"page UI: {ui_refused} attacks refused, {ui_accepted} genuine accepted "
                      f"({len(ui)} total)")
    httpd.shutdown()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
