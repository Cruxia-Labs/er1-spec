# Implementations

ER1 is a *format*, not a tool. It earns the word "standard" only when a party **other than us** can
recompute the same verdicts from the same frozen vectors. Until then it's an open format we publish
and verify ourselves — and **the single most valuable contribution is a verifier you write, in your
language, that we never touched.** This file is the conformance roster and the how-to.

## Conformant means one thing

An implementation is **conformant** iff it reproduces every entry in
[`golden_vectors.json`](golden_vectors.json) — byte-for-byte — and rejects a one-byte tamper. That
file is the contract; passing it *is* the bar. No sign-off, no style review, no CLA.

## Reference implementations (maintained here)

| Implementation | Language | Status | Notes |
|---|---|---|---|
| [`er1_verify.py`](er1_verify.py) | Python | ✅ conformant | stdlib + `cryptography`; zero project imports. |
| [`er1_verify.mjs`](er1_verify.mjs) | JavaScript (Node) | ✅ conformant | `node:crypto` only, no `npm install`; byte-identical to the Python verifier. |

Both are deliberately small (~200 lines) so a third is an afternoon, not a project. They agree with
each other — which proves the format is reproducible across *languages*, but not yet across
*parties*. That last step is the one we can't take ourselves.

## The whole task, at a glance

`golden_vectors.json` is **7 primitives + 6 signed receipts** under one fixed test key. A verifier:

1. Reads the canonical-JSON scheme (documented in [`CONFORMANCE.md`](CONFORMANCE.md) — RFC
   8785-inspired: sorted keys, NFC-normalized strings, non-ASCII `\uXXXX`-escaped, no insignificant
   whitespace; the one deliberate deviation from RFC 8785 is noted there).
2. Reproduces the **primitive hashes** (`state_root`, `args_hash`, `chain_root_from_seed`) as
   `sha256:` over that canonical JSON.
3. Implements the **~30-line conflict predicate** — three HALT codes (`BANNED_ENTITY`,
   `SUPERSEDED_VALUE`, `CONSTRAINT_VIOLATION`), else `ALLOW`; with the two fences (`nl_extracted` and
   `superseded` beliefs never gate).
4. Reproduces each **`receipt_hash`** (canonical hash of the body with `signature := null`) and
   verifies the **Ed25519 signature** against the pinned public key.
5. Asserts your output equals every vector **byte-for-byte**, and that flipping one byte yields
   `FAILED`.

The 6 receipt cases exercise all of it: `equals_mismatch_halt`, `banned_entity_halt`,
`constraint_violation_halt`, `coherent_allow`, `amber_belief_does_not_halt`,
`superseded_belief_skipped`.

## Add yours — four steps

1. **Claim it** (optional): open a [good-first-verifier issue](https://github.com/Cruxia-Labs/er1-spec/issues/new?template=add-a-verifier.md)
   so two people don't duplicate the work.
2. **Write it** against `golden_vectors.json`. Match the *vectors*, not our code line-for-line.
3. **Prove it**: every entry verifies, and a one-byte tamper fails. Keep that output.
4. **Open a PR** adding one row to the roster table above (link to your repo) — the PR checklist
   walks you through it.

We will not gatekeep beyond the vectors. If a vector is ambiguous or under-specified, **that is a bug
in our spec** — open an issue and we'll fix it with you.

## A good first language

Any language is welcome. If you want a suggestion: **Rust** (or **Rust→WASM**) or **Go**. Rust→WASM
is a nice fit — one small file, no runtime to install, easy to drop into a CI step or run in a
browser tab. The point is simple: the more *independent* hands that recompute the vectors, the closer
ER1 is to a real standard rather than just our word for it.
