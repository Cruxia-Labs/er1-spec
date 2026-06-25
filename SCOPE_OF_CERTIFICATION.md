# Scope of Certification — the Action Receipt

*Version: action-receipt/v0. This document defines, in plain English, exactly what an ER1
action receipt certifies and what it does not. It is the reference an auditor, a counterparty,
or a court can hold up as Exhibit A. If the prose here and the verifier disagree, the verifier
is authoritative — anyone can run it.*

## What a receipt is

A receipt is a signed, chained record that, at a moment in time, an agent proposed a specific
action and a deterministic operator decided **ALLOW** or **HALT** by checking that action
against a snapshot of the project's **typed beliefs**. The receipt carries that belief
snapshot, the action, the verdict, and an Ed25519 signature. Anyone can recompute the verdict
from the receipt's own contents, offline, with no network and no access to our systems.

## What the receipt CERTIFIES (the claim)

1. **Coherence with the recorded decisions.** The verdict follows, by a fixed and public
   predicate, from the typed beliefs recorded *in the receipt*. A HALT means the action
   contradicted a current, active, deterministic belief; an ALLOW means it did not.
2. **Integrity.** The recorded beliefs, action, and verdict have not changed since signing.
   Altering any byte invalidates the Ed25519 signature, and re-running the predicate exposes a
   verdict that no longer matches.
3. **Reproducibility of the decision.** An independent verifier, in any language, recomputes
   the **same verdict** and the **same chain hash** from the same recorded inputs. This is
   guaranteed by the golden vectors (`golden_vectors.json`), which freeze the canonical
   serialization across implementations.
4. **Chain position.** Each receipt names the hash of its predecessor in a signed, tamper-evident
   field, so a sequence cannot be silently reordered, dropped, or back-dated within a chain. The
   single-receipt reference verifier checks a receipt's *own* integrity (signature, binding,
   state-root, verdict); chain **continuity** — that each `prev_receipt_hash` equals the actual
   predecessor's hash — is checked when an ordered chain is verified, not from one receipt alone.

## What the receipt does NOT certify (the limits)

- **Not empirical truth.** We certify that the action is coherent with the beliefs *the project
  recorded*, not that those beliefs are correct about the world. If a recorded decision is
  wrong, an action coherent with it is still wrong. **Garbage in, certified garbage out.**
- **Not natural-language / advisory beliefs.** Only typed, deterministic beliefs
  (`source_kind = deterministic`, `belief_class = CERTIFIED`) can produce a HALT. Beliefs
  extracted from prose are `BEST_EFFORT`, advisory, and are listed under `coverage.exclusions`;
  they never gate. The verifier enforces this in its recompute, not merely the producer.
- **Not anything outside the recorded belief set.** Coverage is exactly the typed beliefs in
  the receipt and the entities the action asserts. A risk not expressed as a typed belief is
  out of scope and the receipt makes no claim about it.
- **Not safety, correctness of code, or absence of harm.** The receipt is a record of
  belief-coherence, not a guarantee about outcomes.

## Whose keys count (the trust boundary)

A receipt's signature proves **integrity** — the recorded content was not altered since signing.
It does **not** establish **authority** — that the *signer* is one you should trust. Anyone can
generate a keypair and sign a coherent receipt, and the math will check out. **Coherence, not
authority. Admissible, not accurate.**

Deciding *whose* keys count is therefore the **relying party's policy, not part of this format** —
and deliberately so. A receipt format that hard-coded a single issuer's trust root would be a
*centralized* standard: the thing an ecosystem routes around. ER1 stays neutral so it can be
adopted across vendors. Concretely:

- **If you only verify your own receipts** (the common case — a local tool checking its own
  repo), trust is not even a question: you signed them.
- **If you rely on someone else's receipt**, pin the public keys you accept. Every verifier
  exposes the receipt's signing public key for exactly this — a one-line allowlist is the whole
  mechanism.
- **When a stronger trust layer is needed** (organization keys, witnessed co-signatures, a
  third-party attestation tier), it slots into seams the signed schema already reserves —
  `key_tier`, `witnesses[]`, and `verification_tier` — so it can be added **without a format
  change**. The trust layer is deferred, not foreclosed.

## The determinism scope (read this before relying on byte-equality)

The **verified claim** is the **verdict plus the chain hash**, each a pure function of the
canonical recorded inputs. Two fields are signed *metadata* but are deliberately **excluded**
from the verified claim and treated as opaque by every verifier:

- `receipt_id` (a UUID), and
- `created_at` (a wall-clock timestamp).

In production these are non-deterministic. A verifier must not depend on them to recompute the
verdict. (The golden vectors pin them only so that serialization itself can be tested
byte-for-byte across languages; that is a test fixture, not a runtime guarantee.)

## Breach definition

A receipt is **breached** if, for the inputs it records, an independent verifier:

- recomputes a **different verdict** than the one stored, **or**
- finds the **Ed25519 signature invalid**, **or**
- finds the **chain hash** inconsistent with the named predecessor.

Absent a breach, the receipt is a faithful, reproducible record of the decision. A breach is an
integrity event (tampering or implementation divergence) — categorically different from a
*contradiction finding*, which means the recorded decisions and the repo's current state
disagree (a coherence signal for a human to resolve, not an integrity failure).

## How to check it yourself

```
pip install cryptography
python er1_verify.py golden_vectors.json   # the bundled offline verifier — no engine, no network
```

(`golden_vectors.json` pins a fixed Ed25519 test key so the vectors reproduce byte-for-byte; that
key is for conformance only and must never sign a production receipt.)

Conformance of any other implementation is established by reproducing every entry in
`golden_vectors.json`; see `CONFORMANCE.md`.
