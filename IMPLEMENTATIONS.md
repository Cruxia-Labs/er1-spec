# Implementations

ER1 is a *format*, not a tool. It earns the word "standard" only when more than one party can
recompute the same verdicts from the same frozen vectors. This file is the conformance roster.

An implementation is **conformant** if it reproduces every entry in
[`golden_vectors.json`](golden_vectors.json) — the canonical-JSON serialization (RFC 8785), the
primitive hashes, the conflict-predicate verdict, and the Ed25519 signatures. See
[`CONFORMANCE.md`](CONFORMANCE.md) for the exact procedure.

## Reference implementations

| Implementation | Language | Status | Notes |
|---|---|---|---|
| [`er1_verify.py`](er1_verify.py) | Python | ✅ conformant | stdlib + `cryptography`; zero project imports. |
| [`er1_verify.mjs`](er1_verify.mjs) | JavaScript (Node) | ✅ conformant | `node:crypto` only, no `npm install`; byte-identical hashes to the Python verifier. |

These two are maintained here. They are intentionally small (~200 lines each) so a third
implementation is an afternoon's work, not a project.

## Add yours

The single most valuable contribution to ER1 is an **independent verifier in another language**
(Rust, Go, TypeScript, WASM, …) written by someone who is *not* us. That is what turns "a format
two files agree on" into "a format anyone can recompute."

If your implementation passes the frozen vectors:

1. Run it against `golden_vectors.json` and confirm every entry verifies (and that a one-byte
   tamper fails).
2. Open a PR adding a row to the table above with a link to your repo.

We will not gatekeep the roster beyond the vectors: passing them *is* the bar. (And if you find a
vector that is ambiguous or under-specified, that is a bug in the spec — please open an issue.)
