// Run the shared adversarial corpus against the Node reference verifier.
//
//     node tests/run_conformance_cases.mjs [--json]
//
// The same corpus is run against Python (tests/run_conformance_cases.py) and the browser build
// (tests/test_browser_verifier.mjs). Three implementations, one set of expectations — a defect
// fixed in one language cannot silently survive in another.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const { verify } = await import(join(here, "..", "er1_verify.mjs"));
const corpus = JSON.parse(readFileSync(join(here, "conformance_cases.json"), "utf8"));

const asJson = process.argv.includes("--json");
const results = [];
let failed = 0;

for (const c of corpus.cases) {
  let res;
  try {
    res = verify(c.doc);
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
  console.log(JSON.stringify({ implementation: "er1_verify.mjs", failed, results }, null, 1));
} else {
  console.log(`\n${corpus.cases.length - failed}/${corpus.cases.length} conformance cases pass`);
}
process.exit(failed ? 1 : 0);
