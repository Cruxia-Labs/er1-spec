#!/usr/bin/env python3
"""Differential fuzzer: Python vs Node canonical JSON, byte for byte.

    python3 tests/differential_fuzz.py [--cases 2000] [--seed 0]

The cross-language claim is that two conformant verifiers compute the same canonical bytes for
the same parsed document — a disagreement about bytes is a disagreement about whether a receipt
was tampered with. Before the 2026-08-04 rebuild this failed on 750 of 2710 random documents,
all of them numbers. The corpus in conformance_cases.json pins the specific defects; this pins
the general property.

Both sides must either produce IDENTICAL bytes or BOTH refuse the input.
"""
import argparse
import json
import pathlib
import random
import string
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
import er1_verify as ER1  # noqa: E402

RUNNER = r"""
import { readFileSync } from "node:fs";
const { canonicalJsonForFuzz } = await import(process.argv[2]);
const docs = JSON.parse(readFileSync(process.argv[3], "utf8"));
const out = docs.map((d) => {
  try { return { ok: true, bytes: canonicalJsonForFuzz(d) }; }
  catch (e) { return { ok: false, error: String(e.message) }; }
});
process.stdout.write(JSON.stringify(out));
"""


def rand_value(rng: random.Random, depth: int = 0):
    """Weighted toward the shapes that used to diverge: numbers of every magnitude, unicode
    that normalizes, keys that collide, deep nesting."""
    choice = rng.random()
    if depth > 3 or choice < 0.30:
        n = rng.random()
        if n < 0.25:
            return rng.randint(-(2 ** 60), 2 ** 60)          # includes the unsafe range
        if n < 0.45:
            return rng.randint(-(2 ** 53) + 1, 2 ** 53 - 1)  # the safe range
        if n < 0.60:
            # 1e309 is written as a literal and parses to infinity on BOTH sides, which is the
            # realistic non-finite path; NaN has no JSON literal so it cannot reach a verifier.
            return rng.choice([0, -0.0, 1e16, 1e21, 1e-6, 1.5, 2.0, 1e308])
        if n < 0.80:
            alphabet = string.ascii_letters + "éécaféé́ \U0001F600\\\"\n\t"
            return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
        if n < 0.9:
            return rng.choice([True, False, None])
        return rng.choice(["", "1.0", "latest", "v2", "  spaced  "])
    if choice < 0.65:
        return [rand_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    keys = ["a", "b", "café", "café", "Z", "z", "é", "é", "0", "\U0001F600"]
    return {rng.choice(keys): rand_value(rng, depth + 1) for _ in range(rng.randint(0, 5))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    docs = [rand_value(rng) for _ in range(args.cases)]

    # Python side
    py = []
    for d in docs:
        try:
            py.append({"ok": True, "bytes": ER1.canonical_json(d).decode("utf-8")})
        except Exception as exc:                       # noqa: BLE001 — any refusal counts
            py.append({"ok": False, "error": str(exc)})

    # Node side (a tiny shim exposes the canonicalizer without changing the public API)
    tmp_docs = HERE / ".fuzz_docs.json"
    tmp_shim = HERE / ".fuzz_shim.mjs"
    tmp_run = HERE / ".fuzz_run.mjs"
    try:
        # Docs go through JSON so both sides parse identical text.
        tmp_docs.write_text(json.dumps(docs, allow_nan=False))
        tmp_shim.write_text(
            'export { canonicalJsonForFuzz } from "../er1_verify.mjs";\n')
        tmp_run.write_text(RUNNER)
        proc = subprocess.run(
            ["node", str(tmp_run), str(HERE.parent / "er1_verify.mjs"), str(tmp_docs)],
            capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            print(proc.stderr[-2000:], file=sys.stderr)
            return 2
        js = json.loads(proc.stdout)
    finally:
        for p in (tmp_docs, tmp_shim, tmp_run):
            p.unlink(missing_ok=True)

    divergences = []
    both_refused = 0
    both_agreed = 0
    for i, (p, j) in enumerate(zip(py, js)):
        if p["ok"] and j["ok"]:
            if p["bytes"] == j["bytes"]:
                both_agreed += 1
            else:
                divergences.append((i, p["bytes"][:80], j["bytes"][:80]))
        elif not p["ok"] and not j["ok"]:
            both_refused += 1
        else:
            divergences.append((i, f"py_ok={p['ok']}", f"js_ok={j['ok']}"))

    print(f"agreed on bytes : {both_agreed}")
    print(f"both refused    : {both_refused}")
    print(f"DIVERGENCES     : {len(divergences)}")
    for i, a, b in divergences[:10]:
        print(f"  [{i}] py={a!r}\n       js={b!r}")
    return 1 if divergences else 0


if __name__ == "__main__":
    raise SystemExit(main())
