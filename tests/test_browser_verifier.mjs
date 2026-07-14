#!/usr/bin/env node
// Conformance runner for the BROWSER verifier (verify/er1_verify.browser.mjs).
//
// Runs the browser module under Node's OWN globalThis.crypto.subtle (Node >= 19 ships WebCrypto
// incl. Ed25519). Because the module is imported here with network globals trapped and is
// statically asserted to reference no Node built-ins, a green run proves it exercises identical
// crypto through the WebCrypto surface alone — the same surface a real browser provides.
//
// Checks, in order:
//   1. STATIC: the browser module's source contains no Node built-ins and no network primitives.
//   2. DYNAMIC: fetch / XMLHttpRequest / WebSocket / EventSource are replaced with throwing traps
//      BEFORE the module is imported; any use would fail the run.
//   3. Feature-detect path: with subtle.importKey stubbed to refuse Ed25519, verify() must throw
//      the typed Er1UnsupportedCryptoError ("browser lacks WebCrypto Ed25519").
//   4. All golden vectors VERIFY, with recomputed verdict + receipt hash matching the recorded
//      ones, and full agreement (ok / verdict / checks / error strings) with er1_verify.mjs.
//   5. A verdict-flip tamper of EVERY golden vector FAILS with signature+verdict error classes.
//   6. The real tamper pairs in tests/fixtures/ behave correctly: untampered VERIFIED, tampered
//      FAILED with the signature + verdict-recompute error classes — again byte-agreeing with
//      er1_verify.mjs.
//
//     node tests/test_browser_verifier.mjs           # human-readable, exit 0/1
//     node tests/test_browser_verifier.mjs --json    # machine-readable results on stdout
//                                                    # (consumed by tests/test_browser_cross_language.py)
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as path from "node:path";
import { strict as assert } from "node:assert";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const JSON_MODE = process.argv.includes("--json");
const log = (...a) => { if (!JSON_MODE) console.log(...a); };

// ── 1. static zero-network / zero-Node-builtin assertion on the module source ──
const MODULE_PATH = path.join(ROOT, "verify", "er1_verify.browser.mjs");
const src = readFileSync(MODULE_PATH, "utf8");
const FORBIDDEN = [
  "node:", "require(", "process.", "Buffer", "__dirname", "__filename", // Node built-ins
  "fetch", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon",  // network primitives
  "navigator.", "import(",                                              // dynamic escape hatches
];
for (const token of FORBIDDEN) {
  assert.ok(!src.includes(token), `browser module must not reference ${JSON.stringify(token)}`);
}
log(`static scan: ${FORBIDDEN.length} forbidden tokens absent from er1_verify.browser.mjs ✓`);

// ── 2. dynamic traps installed BEFORE the module is imported ──
const trapped = [];
for (const name of ["fetch", "XMLHttpRequest", "WebSocket", "EventSource"]) {
  Object.defineProperty(globalThis, name, {
    configurable: true,
    value: function networkTrap() { throw new Error(`network primitive ${name} was invoked`); },
  });
  trapped.push(name);
}
log(`network traps armed: ${trapped.join(", ")} ✓`);

const browser = await import(MODULE_PATH); // import AFTER the traps
const { verify: bVerify, verifyJson: bVerifyJson, receiptHash: bHash, Er1UnsupportedCryptoError } = browser;
const ref = await import(path.join(ROOT, "er1_verify.mjs"));

// ── 3. feature-detect path: an engine without Ed25519 must raise the typed error ──
{
  const realImportKey = crypto.subtle.importKey.bind(crypto.subtle);
  crypto.subtle.importKey = async () => {
    const e = new Error("Unrecognized algorithm name");
    e.name = "NotSupportedError";
    throw e;
  };
  let thrown = null;
  try { await bVerify({}); } catch (e) { thrown = e; }
  crypto.subtle.importKey = realImportKey;
  assert.ok(thrown instanceof Er1UnsupportedCryptoError,
            `expected Er1UnsupportedCryptoError, got ${thrown}`);
  assert.match(thrown.message, /browser lacks WebCrypto Ed25519/);
  assert.equal(thrown.code, "ER1_WEBCRYPTO_ED25519_UNSUPPORTED");
  log("feature-detect: stubbed-out Ed25519 raises Er1UnsupportedCryptoError ✓");
}

// ── helpers ──
const results = [];
async function agreeWithRef(name, receipt) {
  // Byte-agreement with the Node reference verifier: same ok, same recomputed verdict, same
  // checks, same error STRINGS, same receipt hash.
  const b = await bVerify(receipt);
  const r = ref.verify(receipt);
  assert.equal(b.ok, r.ok, `${name}: ok diverges (browser ${b.ok} vs ref ${r.ok})`);
  assert.equal(b.recomputedVerdict, r.recomputedVerdict, `${name}: recomputed verdict diverges`);
  assert.deepEqual(b.checks, r.checks, `${name}: checks diverge`);
  assert.deepEqual(b.errors, r.errors, `${name}: error strings diverge`);
  const bh = await bHash(receipt);
  assert.equal(bh, ref.receiptHash(receipt), `${name}: receipt hash diverges`);
  return { browser: b, hash: bh };
}

// ── 4. golden vectors ──
const golden = JSON.parse(readFileSync(path.join(ROOT, "golden_vectors.json"), "utf8"));
assert.ok(Array.isArray(golden.receipts) && golden.receipts.length >= 6, "expected >=6 golden vectors");
for (const w of golden.receipts) {
  const { browser: res, hash } = await agreeWithRef(`golden:${w.name}`, w.receipt);
  assert.ok(res.ok, `golden:${w.name} must VERIFY, errors=${JSON.stringify(res.errors)}`);
  assert.equal(res.recomputedVerdict, w.verdict, `golden:${w.name}: verdict != recorded`);
  assert.equal(hash, w.receipt_hash, `golden:${w.name}: hash != recorded`);
  // verifyJson round-trips to the identical result
  const viaJson = await bVerifyJson(JSON.stringify(w.receipt));
  assert.deepEqual(viaJson, res, `golden:${w.name}: verifyJson diverges from verify`);
  results.push({ kind: "golden", name: w.name, ok: res.ok,
                 recomputedVerdict: res.recomputedVerdict, receiptHash: hash, errors: res.errors });
  log(`VERIFIED ✓  golden:${w.name}  verdict=${w.verdict}  hash=${hash.slice(0, 18)}…`);
}

// ── 5. verdict-flip tamper of every golden vector must FAIL (signature + verdict classes) ──
for (const w of golden.receipts) {
  const forged = JSON.parse(JSON.stringify(w.receipt));
  forged.decision.verdict = forged.decision.verdict === "HALT" ? "ALLOW" : "HALT";
  const { browser: res, hash } = await agreeWithRef(`tamper:${w.name}`, forged);
  assert.ok(!res.ok, `tamper:${w.name} must FAIL`);
  assert.equal(res.checks.signature, false, `tamper:${w.name}: signature must fail`);
  assert.equal(res.checks.verdict, false, `tamper:${w.name}: verdict recompute must catch the flip`);
  results.push({ kind: "golden_tampered", name: w.name, ok: res.ok,
                 recomputedVerdict: res.recomputedVerdict, receiptHash: hash, errors: res.errors });
  log(`FAILED ✗ (as required)  tamper:${w.name}  [${res.errors.join(" | ")}]`);
}

// ── 6. real tamper pairs from tests/fixtures/ ──
const FIXDIR = path.join(HERE, "fixtures");
const tamperedFiles = readdirSync(FIXDIR).filter((f) => f.endsWith(".er1.tampered.json")).sort();
assert.ok(tamperedFiles.length >= 2, "need at least 2 real tamper pairs in tests/fixtures/");
for (const tf of tamperedFiles) {
  const cleanFile = tf.replace(".er1.tampered.json", ".er1.json");
  const clean = JSON.parse(readFileSync(path.join(FIXDIR, cleanFile), "utf8"));
  const tampered = JSON.parse(readFileSync(path.join(FIXDIR, tf), "utf8"));

  const { browser: okRes, hash: okHash } = await agreeWithRef(`fixture:${cleanFile}`, clean);
  assert.ok(okRes.ok, `fixture:${cleanFile} (untampered) must VERIFY, errors=${JSON.stringify(okRes.errors)}`);
  results.push({ kind: "fixture", name: cleanFile, ok: okRes.ok,
                 recomputedVerdict: okRes.recomputedVerdict, receiptHash: okHash, errors: okRes.errors });
  log(`VERIFIED ✓  fixture:${cleanFile}  verdict=${clean.decision.verdict}  hash=${okHash.slice(0, 18)}…`);

  const { browser: badRes, hash: badHash } = await agreeWithRef(`fixture:${tf}`, tampered);
  assert.ok(!badRes.ok, `fixture:${tf} must FAIL`);
  assert.equal(badRes.checks.signature, false, `fixture:${tf}: signature must fail`);
  assert.equal(badRes.checks.verdict, false, `fixture:${tf}: verdict recompute must catch the tamper`);
  assert.ok(badRes.errors.some((e) => e.startsWith("signature:")), `fixture:${tf}: signature error class`);
  assert.ok(badRes.errors.some((e) => e.startsWith("verdict:")), `fixture:${tf}: verdict error class`);
  results.push({ kind: "fixture_tampered", name: tf, ok: badRes.ok,
                 recomputedVerdict: badRes.recomputedVerdict, receiptHash: badHash, errors: badRes.errors });
  log(`FAILED ✗ (as required)  fixture:${tf}  [${badRes.errors.join(" | ")}]`);
}

// ── traps must never have fired (they throw on use, but belt-and-braces: still defined) ──
for (const name of trapped) {
  assert.equal(typeof globalThis[name], "function", `trap for ${name} was tampered with`);
}

const nGolden = results.filter((r) => r.kind === "golden").length;
const nFixtureOk = results.filter((r) => r.kind === "fixture").length;
const nTamper = results.filter((r) => r.kind.endsWith("tampered")).length;
if (JSON_MODE) {
  process.stdout.write(JSON.stringify({ module: "verify/er1_verify.browser.mjs", results }, null, 1) + "\n");
} else {
  log(`\nbrowser-verifier conformance: ${nGolden} golden vectors + ${nFixtureOk} real receipts VERIFIED, ` +
      `${nTamper} tamper cases FAILED as required, ` +
      `byte-agreement with er1_verify.mjs on all ${results.length} cases ✓`);
}
process.exit(0);
