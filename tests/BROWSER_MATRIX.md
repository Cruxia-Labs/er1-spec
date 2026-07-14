# Browser engine matrix — verify/er1_verify.browser.mjs

The browser verifier's conformance surface is exercised at three levels:

1. **Node WebCrypto** (`node tests/test_browser_verifier.mjs`) — always runs (CI + local). The
   module executes under Node's own `globalThis.crypto.subtle` with network globals trapped and a
   static scan proving it references no Node built-ins, so a green run is evidence the module
   works on the WebCrypto surface alone.
2. **Python cross-check** (`tests/test_browser_cross_language.py`) — closes the three-way
   agreement triangle against `er1_verify.py` on every case.
3. **Real engines via Playwright** (`tests/run_browser_matrix.py`) — loads `verify/index.html`
   from a loopback static server and runs all 16 cases (6 golden vectors, 6 verdict-flip tampers,
   2 real tamper pairs + their untampered twins) inside the engine.

Playwright is NOT a dependency of this repo and is never auto-installed; the matrix below records
the last local run and what is pending.

## Status (last run: 2026-07-13, local)

| Engine   | Version            | Result | Notes |
|----------|--------------------|--------|-------|
| Chromium | 147.0.7727.15      | PASS   | 8 cases VERIFIED, 8 tamper cases FAILED as required (16/16) |
| Firefox  | —                  | PENDING | browser build not downloaded on this machine |
| WebKit   | —                  | PENDING | browser build not downloaded on this machine |

WebCrypto Ed25519 note: the module feature-detects Ed25519 (RFC 8032 test-vector probe key) and
throws the typed `Er1UnsupportedCryptoError("browser lacks WebCrypto Ed25519 …")` on engines
without it, rather than reporting a misleading FAILED. Chromium ships Ed25519 by default since
137; current Firefox and Safari/WebKit also ship it — the pending rows are about the *builds not
being downloaded here*, not about expected support.

## To complete the matrix later

```sh
# one-time browser download (heavyweight — needs an explicit deps decision):
python -m playwright install firefox webkit

# then, with any Python that has playwright:
python tests/run_browser_matrix.py                # all engines
python tests/run_browser_matrix.py firefox webkit # just the pending ones
```

Update the table above with the results.
