#!/usr/bin/env python3
"""Generate tests/conformance_cases.json — the shared adversarial corpus.

Every case here is a receipt that a verifier must REFUSE, drawn from the 2026-08-04 adversarial
review in which each one had produced VERIFIED, a crash, or a cross-language disagreement. The
corpus is the anti-drift mechanism: all three reference implementations run it and must agree,
so a defect fixed in one language cannot silently survive in another.

    python3 tests/build_conformance_cases.py     # regenerate (deterministic)

Cases assert on a substring of the error list rather than a whole message, so wording can be
improved without churning the corpus. `expect_ok` is what actually matters.
"""
import json
import pathlib
import unicodedata

HERE = pathlib.Path(__file__).parent
SHA0 = "sha256:" + "0" * 64


def receipt(**over):
    """A structurally complete receipt. Unsigned, so every case also carries a signature error;
    each case asserts on the SPECIFIC defect it is about."""
    r = {
        "schema_version": "action-receipt/v0",
        "receipt_id": "case",
        "created_at": "2026-08-04T00:00:00Z",
        "chain": {"sequence_number": 0, "prev_receipt_hash": None},
        "pre_state_root": SHA0,
        "post_state_root": SHA0,
        "action": {"tool": "deploy", "asserts": {"env": "prod"}, "resource": "k8s://prod"},
        "action_binding": {"tool": "deploy", "args_hash": SHA0, "resource": "k8s://prod"},
        "beliefs": [],
        "decision": {"verdict": "ALLOW", "reason_code": None, "conflicting_belief_id": None},
        "coverage": {"exclusions": []},
        "operator_version": "corpus/1",
        "signature": {"algorithm": "ed25519", "public_key": "AAAA", "signature": "AAAA"},
    }
    r.update(over)
    return r


def belief(**over):
    b = {"belief_id": "b1", "belief_class": "CERTIFIED", "entity": "env", "rule": "excludes",
         "value": "*", "source_kind": "deterministic", "status": "active"}
    b.update(over)
    return b


CASES = []


def case(name, doc, expect_ok, error_contains, why):
    CASES.append({"name": name, "why": why, "doc": doc,
                  "expect_ok": expect_ok, "error_contains": error_contains})


# ── 1. document confusion: a receipt is not a bundle ──
case("bundle_smuggling",
     receipt(receipts=[{"name": "x", "receipt": receipt()}]),
     False, "ambiguous",
     "A forged receipt carrying one genuine receipt printed VERIFIED and exited 0; the unsigned "
     "top-level `receipts` array decided what got verified. Pinning did not help.")

# ── 2. identity: NFC/NFD must not split one signed byte-string into two identities ──
nfd_env = unicodedata.normalize("NFD", "café")
nfc_env = unicodedata.normalize("NFC", "café")
case("nfd_entity_evasion",
     receipt(action={"tool": "deploy", "asserts": {nfd_env: "prod"}, "resource": "k8s://prod"},
             beliefs=[belief(entity=nfc_env)]),
     False, "printable ASCII",
     "A banned entity spelled in NFD evaded the predicate while canonicalizing to byte-identical "
     "signed input — the signed bytes did not determine the verdict. Now refused earlier: "
     "identity names are ASCII, so no two spellings of one name exist.")

# ── 3. version constraints must not be satisfied by non-versions ──
for bad in ["latest", "main", "v3.0", ""]:
    case(f"version_bypass_{bad or 'empty'}",
         receipt(action={"tool": "pip", "asserts": {"dep:x": bad}, "resource": "req.txt"},
                 action_binding={"tool": "pip", "args_hash": SHA0, "resource": "req.txt"},
                 beliefs=[belief(entity="dep:x", rule="satisfies", value="<2.0")]),
         False, "malformed",
         f"`<2.0` was satisfied by {bad!r} because non-numeric components parsed as 0.")

# ── 4. enums fail CLOSED: one wrong character must not disarm a gate ──
for field, value in [("status", "ACTIVE"), ("rule", "EXCLUDES"), ("rule", "excludes "),
                     ("source_kind", "DETERMINISTIC"), ("belief_class", "certified")]:
    case(f"enum_fail_open_{field}_{value.strip() or 'blank'}".replace(" ", "_"),
         receipt(beliefs=[belief(**{field: value})]),
         False, "malformed",
         f"beliefs[0].{field}={value!r} silently disabled the constraint and verified as ALLOW.")

# ── 5. an active deterministic constraint must be fully specified ──
for missing in ["entity", "rule", "belief_id"]:
    b = belief()
    del b[missing]
    case(f"belief_missing_{missing}", receipt(beliefs=[b]), False, "malformed",
         f"An active deterministic constraint without {missing!r} was skipped (Python) or "
         f"crashed (JS) instead of failing.")
b = belief(rule="equals")
del b["value"]
case("belief_equals_missing_value", receipt(beliefs=[b]), False, "malformed",
     "An `equals` constraint without a value cannot be evaluated.")

# ── 6. type confusion must yield a verdict, never a crash or a pass ──
case("asserts_not_object",
     receipt(action={"tool": "deploy", "asserts": "abc", "resource": "k8s://prod"}),
     False, "malformed", "action.asserts as a string crashed the predicate.")
case("beliefs_not_list", receipt(beliefs="notalist"), False, "malformed",
     "beliefs as a string iterated characters and crashed.")
case("belief_not_object", receipt(beliefs=["x"]), False, "malformed",
     "A non-object belief entry crashed .get().")
case("signature_not_object", receipt(signature="nope"), False, "signature",
     "A string signature block crashed .get(); the correct answer is an invalid signature.")
case("action_not_object", receipt(action="nope"), False, "malformed",
     "A string action crashed the binding check.")
case("assert_value_not_string",
     receipt(action={"tool": "deploy", "asserts": {"env": 5}, "resource": "k8s://prod"}),
     False, "malformed",
     "Non-string assert values made Python recompute HALT and JS recompute ALLOW.")

# ── 7. number grammar: only exactly-representable integers ──
case("integer_above_2_53",
     receipt(chain={"sequence_number": 9007199254740993, "prev_receipt_hash": None}),
     False, "malformed",
     "Integers above 2**53 collapsed to a neighbour in JS, so a tampered body kept a colliding "
     "hash in one language and not the other.")
case("non_integral_number",
     receipt(chain={"sequence_number": 1.5, "prev_receipt_hash": None}),
     False, "malformed",
     "Python repr and ECMAScript ToString share no float grammar (1e21, 1e16, 1e-6 all differed).")

# ── 8. degenerate keys ──
# CORRECT ENCODINGS ONLY. The first version of these cases used 87- and 88-character
# signatures where 86 is required, so every one of them died at the base64 LENGTH gate and
# never reached the small-order check at all. Deleting the entire blacklist left the corpus
# green in all three languages while the universal forgery came straight back. The guard for
# the worst bug this project has had was itself unguarded, for exactly the reason the bug
# existed: a case that passes for the wrong reason tests nothing.
# pk = 43 chars (32 bytes), signature = 86 chars (64 bytes). Anything else is a length test.
IDENTITY_PK = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"   # 0100..0000
SIGN_BIT_PK = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA"   # 0100..0080, sign bit set
P_PLUS_1_PK = "7v________________________________________8"   # eeff..ffff
GOOD_PK     = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"   # the golden signer
# basepoint || S=1 — with A = identity this satisfies S*B == R for EVERY message.
UNIVERSAL_SIG = "WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
# NOTE ON THE R OPERAND. The check reads `_small_order(pub_raw) or _small_order(sig_raw[:32])`.
# The public-key operand is exercised by the three cases below (dropping it fails them). The R
# operand is NOT black-box testable: with a non-degenerate key, a small-order R only verifies if
# S*B == R + h*A actually holds, which needs the private key — so the Ed25519 math rejects it
# whether or not we check. Dropping that operand therefore survives this corpus, and a case
# pretending otherwise would pass for the wrong reason. It is guarded instead by the direct
# helper contract test in test_conformance.py, and kept because libsodium checks both.

for name, pk, sig, why in [
    ("small_order_key_identity", IDENTITY_PK, UNIVERSAL_SIG,
     "The canonical identity point. One constant signature block verified EVERY receipt in all "
     "three implementations until 534dfb6."),
    ("small_order_key_sign_bit", SIGN_BIT_PK, UNIVERSAL_SIG,
     "Ed25519 stores the x-coordinate's sign in the high bit of byte 31, so the identity point "
     "has a second spelling that OpenSSL and WebCrypto both accept. The blacklist compared all "
     "32 bytes and missed it; libsodium masks s[31] & 127 first."),
    ("small_order_key_p_plus_1", P_PLUS_1_PK, UNIVERSAL_SIG,
     "p+1 also decodes to the identity point."),
]:
    case(name,
         receipt(signature={"algorithm": "ed25519", "public_key": pk, "signature": sig}),
         False, "signature", why)

# ── 9. schema rules the verifier must enforce ──
case("post_state_root_null_on_allow", receipt(post_state_root=None), False, "post_state_root",
     "The schema requires post_state_root == pre_state_root on ALLOW.")
case("action_binding_tool_mismatch",
     receipt(action_binding={"tool": "other", "args_hash": SHA0, "resource": "k8s://prod"}),
     False, "does not mirror",
     "The binding named a different tool than the action it claims to bind.")

# ── 10. structural limits ──
deep = {"v": None}
node = deep
for _ in range(300):
    node["v"] = {"v": None}
    node = node["v"]
case("deep_nesting", receipt(coverage=deep), False, "malformed",
     "300 levels of nesting raised RecursionError in Python and returned a verdict in JS.")

case("duplicate_key_after_nfc",
     receipt(action={"tool": "deploy",
                     "asserts": {nfc_env: "a", nfd_env: "b"},
                     "resource": "k8s://prod"}),
     False, "malformed",
     "Two assert keys identical after NFC are ambiguous; canonical JSON would emit a duplicate.")

# ── 11. cross-language primitive divergence (the 2026-08-04 re-gate) ──
# Every case below is a place where Python and JavaScript builtins disagreed, so the same
# signed bytes produced different verdicts in two conformant verifiers.
case("identity_entity_non_ascii", receipt(beliefs=[belief(entity="caf\u00e9")]),
     False, "printable ASCII",
     "NFC is bound to the runtime's Unicode version (CPython 15.0 vs Node 16.0; 20 code points "
     "compose in one and not the other), so a decomposed spelling evaded the gate in one "
     "implementation and not the other. Identity names are ASCII.")
case("identity_assert_key_non_ascii",
     receipt(action={"tool": "deploy", "asserts": {"caf\u00e9": "prod"},
                     "resource": "k8s://prod"}),
     False, "printable ASCII", "Same class, on the assert side.")
# An explicit null is not an absent key. `.get(k, default)` fires only when the key is missing;
# `?? default` fires on null too — so a producer emitting `"status": null` was rejected by one
# verifier and read as "active" by the other. Every enum field on a belief carries this hazard,
# so all three are pinned, including the one that is optional and guarded by a presence test.
for field in ["status", "source_kind", "belief_class"]:
    case(f"{field}_explicit_null", receipt(beliefs=[belief(**{field: None})]), False, "malformed",
         f"beliefs[0].{field} = null: Python's dict.get(k, default) and JavaScript's "
         f"`?? default` disagree on an explicit null, so one verifier read the constraint as "
         f"present-and-valid and the other rejected the receipt. Schema requires a string.")
case("version_leading_whitespace",
     receipt(action={"tool": "pip", "asserts": {"dep:x": "\u180e1.0"}, "resource": "req.txt"},
             action_binding={"tool": "pip", "args_hash": SHA0, "resource": "req.txt"},
             beliefs=[belief(entity="dep:x", rule="satisfies", value="<2.0")]),
     False, "malformed",
     "Python's str.strip and ECMAScript's String.trim remove different whitespace sets, "
     "flipping ALLOW/HALT on the same bytes.")
case("base64_padded_junk",
     receipt(signature={"algorithm": "ed25519", "public_key": "AAAA=", "signature": "AAAA=="}),
     False, "signature",
     "Node, CPython and WebCrypto accepted three different sets of malformed base64.")

# ── 12. the third gauntlet (2026-08-04): parse-path and API-shape divergences ──
case("null_document", None, False, "malformed",
     "Both JS verifiers threw an uncaught TypeError on JSON null instead of returning a "
     "verdict; Python returned FAILED. A crash is not a verdict.")
case("compatible_release_single_component",
     receipt(action={"tool": "pip", "asserts": {"dep:x": "9.0"}, "resource": "req.txt"},
             action_binding={"tool": "pip", "args_hash": SHA0, "resource": "req.txt"},
             beliefs=[belief(entity="dep:x", rule="satisfies", value="~=2")]),
     False, "malformed",
     "`~=2` has no upper bound to enforce — it degenerated into >=2, so the pin never gated. "
     "PEP 440 requires at least two components.")

# ── 12b. belief_class must agree with the source it labels ──
# `belief_class` used to be validated only WHEN PRESENT and then never used, so er1.schema.json
# required it while the verifier did not, and nothing tied the label to the thing labelled. The
# whole class is pinned here, not one member: both contradictory pairs, plus absent, plus null.
case("certified_label_on_nl_extracted_belief",
     receipt(beliefs=[belief(source_kind="nl_extracted", belief_class="CERTIFIED",
                             rule="equals", value="prod")]),
     False, "contradicts source_kind",
     "A prose-extracted belief wearing the word CERTIFIED. It never gated (the recompute keys on "
     "source_kind) but the signed label read CERTIFIED to any human or dashboard — trust in the "
     "producer creeping back into a format whose claim is that you need not trust the producer.")

case("best_effort_label_on_deterministic_belief",
     receipt(beliefs=[belief(source_kind="deterministic", belief_class="BEST_EFFORT")]),
     False, "contradicts source_kind",
     "The mirror case: a belief that DOES gate while labelled advisory. Pinning only the other "
     "direction would have left this half of the class reachable.")

_absent = belief()
del _absent["belief_class"]
case("belief_class_absent",
     receipt(beliefs=[_absent]),
     False, "is not a known belief_class",
     "er1.schema.json lists belief_class in `required` for every constraint, but the verifier "
     "checked it only `if present` — looser than the schema it publishes.")

# (belief_class = explicit null is already pinned in section 12; ABSENCE was the missing case.)


# ── 13. the positive control: a well-formed receipt must still recompute ──
case("well_formed_halt_recomputes",
     receipt(beliefs=[belief()],
             decision={"verdict": "HALT", "reason_code": "BANNED_ENTITY",
                       "conflicting_belief_id": "b1"},
             post_state_root=None),
     False, "signature",
     "Control: unsigned, so it must fail on the SIGNATURE only — proving the corpus's other "
     "cases fail for their own stated reason and the predicate still works.")

out = {
    "_note": "Adversarial conformance corpus. Every case is a receipt a verifier must refuse. "
             "All reference implementations run this and must agree — see "
             "tests/run_conformance_cases.py and tests/run_conformance_cases.mjs.",
    "cases": CASES,
}
(HERE / "conformance_cases.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
print(f"wrote {len(CASES)} cases -> tests/conformance_cases.json")
