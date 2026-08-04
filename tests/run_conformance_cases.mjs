// Run the shared adversarial corpus against a JavaScript verifier.
//
//     node tests/run_conformance_cases.mjs [--json] [--browser]
//
// Default target is the Node reference verifier (er1_verify.mjs); --browser runs the SAME corpus
// against the browser build (verify/er1_verify.browser.mjs) under Node's own WebCrypto. The
// corpus also runs against Python (tests/run_conformance_cases.py). Three implementations, one
// set of expectations — a defect fixed in one language cannot silently survive in another.
// tests/test_conformance_corpus.py is what makes all three gate CI.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const useBrowser = process.argv.includes("--browser");
const modulePath = useBrowser
  ? join(here, "..", "verify", "er1_verify.browser.mjs")
  : join(here, "..", "er1_verify.mjs");
const implementation = useBrowser ? "er1_verify.browser.mjs" : "er1_verify.mjs";
// The browser build's verify() is async (WebCrypto); awaiting a sync return is harmless.
const { verify } = await import(modulePath);
const corpus = JSON.parse(readFileSync(join(here, "conformance_cases.json"), "utf8"));

const asJson = process.argv.includes("--json");
const results = [];
let failed = 0;

for (const c of corpus.cases) {
  let res;
  try {
    res = await verify(c.doc);
  } catch (exc) {
    res = { ok: null, errors: [`THREW: ${exc.message}`] };   // a crash is always a failure
  }
  const errs = (res.errors ?? []).join(" | ");
  const okMatch = res.ok === c.expect_ok;
  const errMatch = !c.error_contains || errs.includes(c.error_contains);
  const pass = okMatch && errMatch;
  if (!pass) failed++;
  results.push({ name: c.name, pass, ok: res.ok, errors: errs });
  if (!asJson) {
    console.log(`${pass ? "ok  " : "FAIL"} ${c.name}`);
    if (!pass) {
      console.log(`      expected ok=${c.expect_ok} error~${JSON.stringify(c.error_contains)}`);
      console.log(`      got      ok=${res.ok} errors=${JSON.stringify(errs)}`);
    }
  }
}

if (asJson) {
  console.log(JSON.stringify({ implementation, failed, results }, null, 1));
} else {
  console.log(`\n${corpus.cases.length - failed}/${corpus.cases.length} conformance cases pass`);
}
process.exit(failed ? 1 : 0);
