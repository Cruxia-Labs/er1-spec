# Conformance — proving a verifier reproduces the format

The Action Receipt is an open format. An implementation in any language (Rust, WASM, Go, Swift, …)
is **conformant** iff it reproduces every entry in [`golden_vectors.json`](golden_vectors.json)
from the same pinned inputs **and refuses every case in
[`tests/conformance_cases.json`](tests/conformance_cases.json)**. Those two files — not this
prose, and not the Python code — are the contract. The Python implementation is simply the first
conformant verifier.

Two contracts, because they answer different questions. The vectors prove you compute the same
answer on well-formed input. The corpus proves you *refuse the same inputs*, which is the harder
half: every case in it is a receipt that once produced VERIFIED, a crash, or a disagreement
between two implementations that both believed they were conformant.

## Design rule: the spec must be small enough that two people cannot implement it differently

This is the lesson of the 2026-08-04 rebuild, and it explains every restriction below. The
format previously leaned on primitives that languages define differently, and each one became a
soundness bug rather than a cosmetic difference:

| Primitive | How they differ | What it cost |
|---|---|---|
| Unicode NFC | CPython 3.12 ships Unicode 15.0, Node 24 ships 16.0; 20 code points compose in one and not the other | The **signed bytes depended on which interpreter ran**. A banned entity spelled decomposed passed the gate in one verifier and halted in the other; one signed receipt had two hashes. |
| `str.strip()` vs `String.trim()` | different whitespace sets | Opposite verdicts from identical bytes |
| `dict.get(k, d)` vs `?? d` | disagree on an explicit `null` | One verifier read a constraint as active, the other rejected the receipt |
| base64 decoders | three different leniencies | The same file verified in one implementation, failed in another |
| number formatting | Python `repr` vs ECMAScript `ToString` share no grammar | A tampered body kept a colliding hash in one language |
| JSON duplicate keys | last-wins, silently | Contradictory decoy content rode inside a signed file |

So the format does not ask implementations to agree about hard things. It removes the hard
things. **If a rule below seems needlessly strict, that is the point** — it is strict exactly
where two good-faith implementers would otherwise diverge.

## What the vectors pin

`golden_vectors.json` fixes a single Ed25519 private scalar
(`fixed_inputs.ed25519_private_seed_hex`), a `created_at`, and a chain seed. Because Ed25519
signing is deterministic (RFC 8032), pinning the key makes the **entire** receipt — signature
included — reproducible byte-for-byte. Production receipts randomize `receipt_id`/`created_at`;
those are opaque to verification (see `SCOPE_OF_CERTIFICATION.md` §"determinism scope"). The
vectors pin them only so serialization can be compared exactly.

## 1. Loading a document (before anything is parsed into a receipt)

A document must have exactly **one reading**, or none. Reject at load time:

- **duplicate object keys anywhere in the text.** JSON parsers silently keep the last, so a file
  can carry contradictory content that verifies. Detect this by scanning the document text —
  a reviver cannot, because the parser has already collapsed the duplicate.
- **unpaired surrogates**, in string values *and in object keys*. They have no UTF-8 form, so
  they have no canonical byte form.
- **a top-level that is not an object.**
- **invalid UTF-8.** A leading BOM is tolerated and stripped; nothing else is repaired.

## 2. Canonical JSON

A pinned serialization. Keys sorted by **UTF-16 code unit**; no insignificant whitespace; UTF-8
bytes out.

- **No normalization.** Strings are serialized as parsed. Two spellings are two strings with two
  hashes, in every runtime, forever. (This also makes the string layer RFC 8785-conformant rather
  than deviating from it — the previous NFC pass was the deviation, and it was the bug.)
- **Non-ASCII is escaped as `\uXXXX`** (surrogate pairs for astral planes). A deliberate deviation
  from RFC 8785 §3.2.2.2, which emits raw UTF-8; escaping is pinned so implementations cannot
  differ on encoding details, and `golden_vectors.json` fixes it exactly.
- **Numbers: integers only, `|n| <= 2**53 - 1`.** Anything else — a float, a larger integer —
  is **refused, not serialized**. No number grammar exists that Python and ECMAScript emit
  identically, so the format declines to have one. A receipt whose body carries an
  un-canonicalizable number has no well-defined signed form and is rejected with that reason,
  not merely reported as a signature failure.
- **Depth is bounded** (100 levels), so adversarial nesting yields a verdict rather than a stack
  overflow in whichever language runs out first.

## 3. Structural validation — runs BEFORE the predicate, and fails closed

Anything unrecognized makes the receipt **unverifiable, not permissible**. Previously an
unrecognized value silently skipped the constraint and the receipt verified as ALLOW, so
`"ACTIVE"` for `"active"` disarmed a gate.

- Enums are exact and **have no implicit defaults**: `status` ∈ {`active`, `superseded`} must be
  present and explicit; `source_kind` ∈ {`deterministic`, `nl_extracted`}; `rule` ∈ {`equals`,
  `excludes`, `satisfies`}; `belief_class` ∈ {`CERTIFIED`, `BEST_EFFORT`}; `decision.verdict` ∈
  {`ALLOW`, `HALT`}.
- An **active deterministic** constraint must be fully specified: `belief_id`, `entity`, `rule`,
  and (unless `excludes`) `value`.
- `action`, `action.asserts`, `action_binding`, `decision` must be objects; `beliefs` an array of
  objects; assert values strings.
- **A receipt is not a bundle.** A document carrying both receipt fields and a `receipts` array is
  ambiguous and is rejected. Previously the unsigned top-level `receipts` array decided what got
  verified, so a forged receipt carrying one genuine receipt printed VERIFIED and exited 0 —
  and key pinning did not help.

### Identity fields are printable ASCII

The names used to **look a constraint up** — `belief.entity`, the keys of `action.asserts`,
`belief_id` — must be printable ASCII (U+0020–U+007E). Within that set, normalization is the
identity function in every Unicode version, `strip` and `trim` agree, and comparison is byte
equality, so two implementations cannot disagree about *which* constraint an action touches.

Free text — `value`, `tool`, `resource` — is **unrestricted** and compared with exact code-point
equality, which is well defined everywhere. Receipts carrying rule prose, paths, or non-Latin
content keep working; only the identifiers are constrained.

> Known cost, stated plainly: identifiers cannot be written in non-Latin scripts. The alternative
> was shipping a pinned Unicode composition table in every implementation, which would end the
> property that makes a new verifier cheap to write. If a real use case needs it, the additive
> fix is percent-encoding non-ASCII identifiers at the producer; choosing ASCII now does not
> foreclose that.

## 4. The conflict predicate (the load-bearing core)

For each belief in recorded order, skip it unless `status == active` **and**
`source_kind == deterministic`. Then:

- `excludes`: HALT `BANNED_ENTITY` if the belief's entity appears in `action.asserts`.
- `equals`: HALT `SUPERSEDED_VALUE` if the asserted value `!=` the belief value.
- `satisfies`: HALT `CONSTRAINT_VIOLATION` if the asserted version does not satisfy the constraint.

Return the **first** conflict found; if none, ALLOW.

**Version comparison is strict.** A version is a non-empty dot-separated sequence of ASCII-digit
components, each `<= 2**53 - 1`; missing components compare as 0. Nothing coerces: previously
`<2.0` was satisfied by `"latest"`, `"main"`, `"v3.0"` and `""`, because non-numeric components
parsed as 0. Operators: `>=`, `>`, `<=`, `<`, `==`/`=`, `!=`, `~=`, or a bare exact version.
`~=` is PEP 440 compatible-release and **requires at least two components** — `~=2` is rejected
rather than degenerating into an unbounded `>=`, and that arity is checked before the proposed
version is even looked at, so whenever the rule is examined its malformedness does not depend on
the action. (A defective rule whose entity is never asserted, or that sits after the first
conflict, is never examined — same evaluation scope as 1.0.0.)

**Whitespace (as of 1.0.1):** the version after an operator may be surrounded by U+0020 —
`>= 2.0` is how humans write pins — lexed by hand, because `strip()`/`trim()` remove different
whitespace sets in the two reference languages. ONLY U+0020; a tab is not a version character.
The operator itself must be flush-left, and the PROPOSED version is taken verbatim.

**The two failure modes are different facts (as of 1.0.1):**

- A **constraint** whose version does not parse (`>=abc`, `~=2`) is a defect in the RULE — no
  action can repair it, so when it is examined the receipt is **malformed**, and it is never
  declarable as a coverage gap.
- A **proposed** version that does not parse against a well-formed OPERATOR bound (an unpinned
  `pip install numpy` against `>=2.0`) is **not evaluable**. The receipt must DECLARE that gap
  in `coverage.unevaluated_constraints` (entries `{entity, constraint, reason?}`), and the
  declared set is part of the verified claim: the verifier recomputes it over every active
  deterministic `satisfies` belief whose entity is asserted — a full pass, independent of the
  first-conflict short-circuit. A declaration that recomputation cannot find ("phantom") is
  refused under both verdicts. An UNDECLARED gap is refused when the recomputed verdict is
  ALLOW — a silent skip is the gate bypass 1.0.0's refusal existed to prevent — and tolerated
  when it is HALT: an unevaluable constraint can never BE the conflict (it evaluates to
  no-violation), so nothing launders through a refusal, and 1.0.0 verified HALT receipts whose
  short-circuited conflict left trailing constraints unevaluated. A declared, recomputed gap
  does not violate the constraint, and conformant verifiers surface every recomputed gap
  (`~ not evaluated: …`) rather than printing a VERIFIED indistinguishable from a
  fully-checked one.
- The **bare pin is the strict spelling** and takes neither path: `satisfies dep:x 2.0` means
  "the action must pin exactly this version". Against an unparseable proposed version it
  evaluates by exact string equality — almost always a violation, exactly as 1.0.0 evaluated
  it — and it is never a declarable gap. `==2.0` is the gap-declarable spelling. (The first
  1.0.1 draft reclassified the bare cell; review showed that flipped a published protective
  refusal into a verifying ALLOW, so the boundary of "unevaluable" is operator-form only —
  precisely the cells where 1.0.0 raised and no verified receipt existed.)

## 5. Signature

Ed25519 over the **SHA-256 digest of the canonical body** with `signature := null` — plain
Ed25519 over that 32-byte message, not Ed25519ph. `golden_vectors.json` pins it.

- **base64url is strict**: fixed alphabet, unpadded, exact character count, exact decoded length
  (32 bytes for the key, 64 for the signature). Do not delegate to a runtime decoder; three of
  them accepted three different sets of malformed input.
- **Small-order points are rejected**, for both the public key and the signature's R component
  (libsodium's `has_small_order` blacklist). Otherwise one constant signature block verifies
  against *any* message — a signature nobody produced.

## 6. Cross-field rules the verifier must enforce

- `pre_state_root` = `sha256:` of canonical-JSON of the belief snapshot.
- `args_hash` = `sha256:` of canonical-JSON of `{tool, asserts, resource}`.
- `action_binding.tool` / `.resource` must **mirror** `action.tool` / `.resource`. The binding
  names the request it binds to; a mismatch is a self-contradicting receipt, and since the
  signature covers both objects it can only be a producer defect.
- `post_state_root` **equals `pre_state_root` on ALLOW and is `null` on HALT** (the action did not
  take effect).

## 7. What VERIFIED means, and what it does not

VERIFIED means: this receipt is internally consistent, its recorded verdict follows from its
recorded constraint state, and it is signed by **the key it names**. It does **not** mean the key
belongs to anyone you trust — the CLI prints the signer and marks it `(unpinned)` for exactly
this reason. Pass `--pubkey <key>` to pin the signers you accept; pinning compares decoded key
bytes, not the base64 spelling. Full breach definition: `SCOPE_OF_CERTIFICATION.md`.

## Running the check

```
# the reference verifiers against the frozen vectors (offline)
er1-verify golden_vectors.json                    # Python (after: pip install -e .)
node er1_verify.mjs golden_vectors.json           # JavaScript (Node built-ins only, no install)

# the adversarial corpus — every case must be REFUSED, in each implementation
python tests/run_conformance_cases.py
node tests/run_conformance_cases.mjs
node tests/run_conformance_cases.mjs --browser

# everything, including the three-way agreement gate
python -m pytest -q
```

A new implementation supplies its own harness that loads both `golden_vectors.json` and
`tests/conformance_cases.json`, recomputes each field, and asserts equality — and refusal. When it
passes both, it is conformant: a receipt it produces will verify under the reference verifiers,
and a receipt they refuse it will refuse too.

That mutual acceptance across independent implementations is what would make the format a
standard rather than one vendor's log — until a second party does it, ER1 is an open format we
publish and verify ourselves.
