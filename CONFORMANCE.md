# Conformance — proving a verifier reproduces the format

The Action Receipt is an open format. An implementation in any language (Rust, WASM, Go, TS, …)
is **conformant** iff it reproduces every entry in [`golden_vectors.json`](golden_vectors.json)
from the same pinned inputs. That file — not this prose, and not the Python code — is the
contract. The Python implementation is simply the first conformant verifier.

## What the vectors pin

`golden_vectors.json` fixes a single Ed25519 private scalar
(`fixed_inputs.ed25519_private_seed_hex`), a `created_at`, and a chain seed. Because Ed25519
signing is deterministic (RFC 8032), pinning the key makes the **entire** receipt — signature
included — reproducible byte-for-byte. Production receipts randomize `receipt_id`/`created_at`;
those are opaque to verification (see `SCOPE_OF_CERTIFICATION.md` §"determinism scope"). The
vectors pin them only so serialization can be compared exactly.

## The two layers a conformant implementation must reproduce

1. **Primitives** (`primitives[]`) — the pure hash functions over canonical JSON:
   - `state_root` = `sha256:` of canonical-JSON of the ordered belief snapshot,
   - `args_hash` = `sha256:` of canonical-JSON of `{tool, asserts, resource}`,
   - `chain_root_from_seed` = `sha256:` of the chain seed.
   Canonical JSON is a pinned, RFC 8785-inspired serialization: keys sorted by UTF-16 code unit,
   NFC-normalized strings, non-ASCII escaped as `\uXXXX` (surrogate pairs for astral planes — a deliberate deviation from RFC 8785 §3.2.2.2, which emits raw UTF-8; we pin escaping so the two reference verifiers stay byte-identical, and `golden_vectors.json` fixes it exactly), no
   insignificant whitespace, UTF-8 bytes. `golden_vectors.json` is the byte-exact contract — get it
   identical and everything else follows. (Receipt values are ASCII strings/enums today; the two
   reference verifiers are cross-checked on Unicode too, so the contract holds beyond ASCII.)
   Numeric fields are small non-negative integers (`sequence_number`, counts) — no floats and
   nothing near 2⁵³ — so Python and JS number formatting agree on every in-schema value.

2. **Receipts** (`receipts[]`) — for each case, the implementation must, from the recorded
   `beliefs` + `action`:
   - recompute the **verdict** and `reason_code` via the conflict predicate (including the two
     fences: `nl_extracted` beliefs and `superseded` beliefs never gate),
   - reproduce the **`receipt_hash`** (canonical hash of the body with `signature := null`),
   - reproduce or verify the **`signature`** against `fixed_inputs.public_key_b64url`.

## The conflict predicate (the load-bearing core, ~30 lines)

For each belief in recorded order, skip it unless it is `status == active` **and**
`source_kind == deterministic`. Then:

- `excludes`: HALT `BANNED_ENTITY` if the belief's entity appears in `action.asserts`.
- `equals`: HALT `SUPERSEDED_VALUE` if the asserted value `!=` the belief value.
- `satisfies`: HALT `CONSTRAINT_VIOLATION` if the asserted version does not satisfy the
  constraint (`>=`, `>`, `<=`, `<`, `==`/`=`/`~=`, or a bare exact version; compare by
  dot-separated numeric components, missing components = 0).

Return the **first** conflict found; if none, ALLOW. The reference is the vendored `_conflict`
predicate in [`er1_verify.py`](er1_verify.py) (and its byte-identical port in
[`er1_verify.mjs`](er1_verify.mjs)) — a new implementation must match it on the vectors, not
necessarily line for line.

## Running the check

```
# the two reference verifiers against the frozen vectors (offline)
er1-verify golden_vectors.json            # Python (after: pip install -e .)
node er1_verify.mjs golden_vectors.json   # JavaScript (Node built-ins only, no install)

# the conformance checks — no extra dependency (runs its own asserts)
python test_conformance.py

# the full suites incl. cross-language (needs Node + `pip install pytest`)
python -m pytest test_conformance.py test_cross_language.py -q
```

The golden vectors in this repo are **frozen**: their fixed key makes every receipt — signature
included — reproducible byte-for-byte, so any conformant implementation reaches the identical
result. A new implementation supplies its own harness that loads `golden_vectors.json`, recomputes
each field, and asserts equality. When it passes, it is conformant — and a receipt it produces will
verify under both reference verifiers, and vice versa. That mutual acceptance across independent
implementations is what would make the format a standard rather than one vendor's log — until a second party does it, ER1 is an open format we publish and verify ourselves.
