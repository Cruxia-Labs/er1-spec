# ER1 — Epistemic Receipt v1

**A cryptographic standard for proving the constraint state an autonomous AI agent's action was produced under** — portable, offline-verifiable, and reproducible in any language.

<p align="center"><img src="media/verify_hero.gif" alt="Two independent verifiers re-deriving the same verdict from the frozen golden vectors, offline" width="760"></p>

Agents act. Today you can attest *who* an agent is, *whether* it was allowed to act, *where* it ran, and *what*
it did — but nothing attests the **constraint state** (the active, deterministic "context lineage") the action
was actually taken under. ER1 is that missing record: a signed, chained receipt that a stranger can recompute
**offline, in any language, with no network and no access to the producer**, and get the same verdict — or prove
the producer lied.

```
$ pip install cryptography                   # the only dependency
$ python er1_verify.py golden_vectors.json   # self-test the 6 frozen vectors, offline
VERIFIED ✓  golden_vectors.json:equals_mismatch_halt    verdict=HALT  (recomputed HALT)  hash=sha256:…
VERIFIED ✓  golden_vectors.json:coherent_allow          verdict=ALLOW (recomputed ALLOW) hash=sha256:…
… all 6 receipts VERIFIED ✓
```

Tamper a single byte and it says `FAILED ✗`. The same vectors verify identically in JavaScript with no
dependencies — `node er1_verify.mjs golden_vectors.json` — proving the format is a standard, not one tool's
output. (`pip install -e .` adds an `er1-verify` command for checking your own receipts; the Ed25519 key pinned
in the vectors is test-only — never sign a production receipt with it.)

## What's in this repo

| File | What it is |
|---|---|
| [`er1.schema.json`](er1.schema.json) | The receipt wire format (JSON Schema 2020-12). |
| [`er1_verify.py`](er1_verify.py) | The **reference verifier** — one self-contained file, stdlib + `cryptography`, zero project imports. |
| [`er1_verify.mjs`](er1_verify.mjs) | A **second, independent verifier** in JavaScript — `node:crypto` only, no npm install. Proves the format is reproducible across languages, not tied to one implementation. |
| [`golden_vectors.json`](golden_vectors.json) | Frozen cross-language conformance vectors (a fixed key + 6 fully-signed receipts). |
| [`CONFORMANCE.md`](CONFORMANCE.md) | How any implementation (Rust/WASM/Go/TS) proves itself conformant. |
| [`SCOPE_OF_CERTIFICATION.md`](SCOPE_OF_CERTIFICATION.md) | Plain-English statement of exactly what a receipt does and does **not** certify, and the breach definition. |
| [`test_conformance.py`](test_conformance.py) · [`test_cross_language.py`](test_cross_language.py) | The Python verifier accepts every golden receipt and catches tampering; the JS verifier computes byte-identical hashes and the same verdicts. |
| [`IMPLEMENTATIONS.md`](IMPLEMENTATIONS.md) | The conformance roster — the two reference verifiers, and an open invitation to add an independent one in your language. |

## The constraint set

A receipt records the **constraint set** an action was checked against — each entry a typed rule on an entity
(`equals` / `excludes` / `satisfies`), e.g. `env:DEPLOY_TARGET equals staging`, `lib:boto3 excludes`,
`dep:numpy satisfies >=2.0`. The conflict predicate (~30 lines, in `CONFORMANCE.md`) computes `ALLOW` or `HALT`
deterministically over that set. *Only active, deterministic constraints can gate a `HALT`; advisory (NL-extracted)
constraints are carried but never gate.*

> The on-wire array is named `beliefs[]` in the frozen v1 schema for signature compatibility; conceptually it is
> the constraint / context-lineage set. A future v1.1 may rename the field.

## What it certifies (and what it does not)

ER1 certifies **coherence with the recorded constraints** (the verdict follows from them by a fixed, public
predicate) and **integrity** (any tampering breaks the signature). It does **not** certify the empirical truth of
the constraints, anything outside the recorded set, or safety/correctness of the action. *Garbage in, certified
garbage out.* The verified claim is the **verdict + the chain hash**; `receipt_id` and `created_at` are opaque
signed metadata. See [`SCOPE_OF_CERTIFICATION.md`](SCOPE_OF_CERTIFICATION.md).

## Conformance

An implementation is conformant **iff it reproduces every entry in `golden_vectors.json`** from the same pinned
inputs — the canonical-JSON serialization (RFC 8785), the primitive hashes, the conflict-predicate verdict, and
the Ed25519 signatures. This repo ships **two** conformant implementations (Python and JavaScript) that produce
byte-identical hashes on the golden vectors; that mutual acceptance across languages is what makes ER1 a standard
rather than one vendor's log. See [`CONFORMANCE.md`](CONFORMANCE.md).

## Prior art

The closest related work is **Context Lineage Assurance for Non-Human Identities** (arXiv:2509.18415), which
describes signed, hash-chained context-state proofs verifiable without reading the full context history. ER1
differs by being a productized, formally-grounded, open format with a machine-checked decision procedure and a
frozen cross-language conformance suite.

## License

Released under the **Apache License 2.0** (see [`LICENSE`](LICENSE)) — chosen for its explicit
patent grant, the standard-grade license for an open format adopters can build on. © 2026 Cruxia.
