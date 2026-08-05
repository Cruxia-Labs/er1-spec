# ER1 — Epistemic Receipt v1

**An open, offline-verifiable format for proving the constraint state an autonomous AI agent's action was checked against** — portable, recomputable in any language. The verdict is recomputed, never trusted.

<p align="center"><img src="https://raw.githubusercontent.com/Cruxia-Labs/er1-spec/v1.0.0/media/verify_hero.gif" alt="Two independent verifiers re-deriving the same verdict from the frozen golden vectors, offline" width="760"></p>

Agents act. Today you can attest *who* an agent is, *whether* it was allowed to act, *where* it ran, and *what*
it did — but nothing attests the **constraint state** (the active, deterministic "context lineage") the action
was actually taken under. ER1 is that missing record: a signed, chained receipt that a stranger can recompute
**offline, in any language, with no network and no access to the producer** — and get the same verdict, or
catch the receipt in a lie. What that proves is coherence and integrity, not the empirical truth of the
recorded constraints; the boundary is stated precisely in
[`SCOPE_OF_CERTIFICATION.md`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/SCOPE_OF_CERTIFICATION.md).

```
$ pip install er1-verify
$ curl -sO https://raw.githubusercontent.com/Cruxia-Labs/er1-spec/v1.0.0/golden_vectors.json
$ er1-verify golden_vectors.json    # self-test the 6 frozen vectors, offline
VERIFIED ✓  golden_vectors.json:entry[0] name="equals_mismatch_halt"  verdict=HALT (recomputed HALT)  hash=sha256:3c2034ac1c3…  signer=A6EHv_POEL4d… (unpinned)
VERIFIED ✓  golden_vectors.json:entry[1] name="banned_entity_halt"  verdict=HALT (recomputed HALT)  hash=sha256:94196b8debc…  signer=A6EHv_POEL4d… (unpinned)
…and four more; the exit code is 0 only when every receipt verifies.
```

`(unpinned)` is the verifier being precise: without `--pubkey` it proves a receipt is internally consistent and
signed **by the key it names** — pin a key to also assert *whose* key that is. Tamper a single byte and it says
`FAILED ✗`. The same vectors verify identically in JavaScript
(`node er1_verify.mjs golden_vectors.json`, no dependencies) and in the browser with the network off
(`verify/er1_verify.browser.mjs`, WebCrypto only) — three implementations on disjoint stacks, showing the
format is reproducible, not one tool's output. The Ed25519 key pinned in the vectors is test-only — never sign
a production receipt with it.

The sdist is self-proving: `pip download er1-verify --no-binary :all:` unpacks to the verifier, the frozen
vectors, and a conformance suite that needs nothing else — `python -m pytest test_conformance.py`.

## What's in the spec repo

The format lives at [github.com/Cruxia-Labs/er1-spec](https://github.com/Cruxia-Labs/er1-spec); links below are
pinned to the `v1.0.0` release.

| File | What it is |
|---|---|
| [`er1.schema.json`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/er1.schema.json) | The receipt wire format (JSON Schema 2020-12). |
| [`er1_verify.py`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/er1_verify.py) | The **reference verifier** — one self-contained file, stdlib + `cryptography`, zero project imports. This package. |
| [`er1_verify.mjs`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/er1_verify.mjs) | A **second verifier** in JavaScript — `node:crypto` only, no npm install. A third runs in the browser: [`verify/er1_verify.browser.mjs`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/verify/er1_verify.browser.mjs) (WebCrypto only). |
| [`golden_vectors.json`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/golden_vectors.json) | Frozen cross-language conformance vectors (a fixed test key + 6 fully-signed receipts). Also ships in this package's sdist. |
| [`CONFORMANCE.md`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/CONFORMANCE.md) | How any implementation (Rust/WASM/Go/TS) proves itself conformant. |
| [`SCOPE_OF_CERTIFICATION.md`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/SCOPE_OF_CERTIFICATION.md) | Plain-English statement of exactly what a receipt does and does **not** certify, and the breach definition. |
| [`test_conformance.py`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/test_conformance.py) · [`test_cross_language.py`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/test_cross_language.py) | The Python verifier accepts every golden receipt and catches tampering; the JS verifier computes byte-identical hashes and the same verdicts. |
| [`IMPLEMENTATIONS.md`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/IMPLEMENTATIONS.md) | The conformance roster — three verifiers on disjoint stacks (Python, Node, browser WebCrypto), and an open invitation to add an independent one in your language. |
| [`KEYS.md`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/KEYS.md) | Announced signing keys and key tiers. A key adds continuity, never the integrity claim — that stays recomputation. |

## The constraint set

A receipt records the **constraint set** an action was checked against — each entry a typed rule on an entity
(`equals` / `excludes` / `satisfies`), e.g. `env:DEPLOY_TARGET equals staging`, `lib:boto3 excludes`,
`dep:numpy satisfies >=2.0`. The conflict predicate (~30 lines, in `CONFORMANCE.md`) computes `ALLOW` or `HALT`
deterministically over that set. *Only active, deterministic constraints can gate a `HALT`; advisory (NL-extracted)
constraints are carried but never gate.*

> The on-wire array is named `beliefs[]` in the frozen v1 schema for signature compatibility; conceptually it is
> the constraint / context-lineage set. A future schema revision may rename the field.

## What it certifies (and what it does not)

ER1 certifies **coherence with the recorded constraints** (the verdict follows from them by a fixed, public
predicate) and **integrity** (any tampering breaks the signature). It does **not** certify the empirical truth of
the constraints, anything outside the recorded set, or safety/correctness of the action. *Garbage in, certified
garbage out.* The verified claim is the **verdict + the chain hash**; `receipt_id` and `created_at` are opaque
signed metadata. See
[`SCOPE_OF_CERTIFICATION.md`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/SCOPE_OF_CERTIFICATION.md).

## Conformance

An implementation is conformant **iff it reproduces every entry in `golden_vectors.json`** from the same pinned
inputs — the canonical-JSON serialization (RFC 8785-inspired; see
[`CONFORMANCE.md`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/CONFORMANCE.md)), the primitive hashes,
the conflict-predicate verdict, and the Ed25519 signatures. The spec repo ships **three** conformant
implementations (Python, Node, browser WebCrypto) that produce byte-identical hashes on the golden vectors; that
mutual acceptance across disjoint stacks makes ER1 reproducible — not just one vendor's log. (We reserve the
word "standard" for when a party other than us recomputes these vectors; see
[`IMPLEMENTATIONS.md`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/IMPLEMENTATIONS.md).)

## Prior art

The closest related work is **Context Lineage Assurance for Non-Human Identities in Critical Multi-Agent
Systems** (arXiv:2509.18415), which describes signed, hash-chained provenance for agent context verifiable
without replaying the full history. ER1 differs by being a productized, open format with an explicit, public
decision procedure and a frozen cross-language conformance suite.

## License

Released under the **Apache License 2.0** (see
[`LICENSE`](https://github.com/Cruxia-Labs/er1-spec/blob/v1.0.0/LICENSE)) — chosen for its explicit
patent grant, the license an open format's adopters can build on. © 2026 Cruxia.


---

*ER1 is small on purpose: a way to prove the constraint state an action was checked against, recomputable by
someone who doesn't trust the producer's tooling.
[sagrada-linter](https://github.com/Cruxia-Labs/sagrada-linter) is the first tool that emits one — and we'd
rather the format outlive any one tool, including ours. → [Cruxia-Labs](https://github.com/Cruxia-Labs)*
