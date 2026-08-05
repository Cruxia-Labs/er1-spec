"""ER1 conformance test — the reference verifier must accept every golden receipt and reject
tampering. Run: `python -m pytest test_conformance.py -q` (or `python test_conformance.py`).
"""
import copy
import json
import pathlib

import er1_verify as ER1

HERE = pathlib.Path(__file__).parent
GOLDEN = json.loads((HERE / "golden_vectors.json").read_text())


def test_every_golden_receipt_verifies():
    for vec in GOLDEN["receipts"]:
        rec = vec["receipt"]
        res = ER1.verify(rec)
        assert res["ok"], f"{vec['name']}: {res['errors']}"
        assert res["recomputed_verdict"] == vec["verdict"]
        assert ER1.receipt_hash(rec) == vec["receipt_hash"]


def test_signatures_use_the_pinned_key():
    pub = GOLDEN["fixed_inputs"]["public_key_b64url"]
    for vec in GOLDEN["receipts"]:
        assert vec["receipt"]["signature"]["public_key"] == pub
        assert ER1.verify_signature(vec["receipt"])


def test_tamper_is_caught_by_both_signature_and_recompute():
    # flip a HALT receipt's verdict to ALLOW -> signature fails AND recompute disagrees
    halt = next(v for v in GOLDEN["receipts"] if v["verdict"] == "HALT")
    forged = copy.deepcopy(halt["receipt"])
    forged["decision"]["verdict"] = "ALLOW"
    res = ER1.verify(forged)
    assert not res["ok"]
    assert not res["checks"]["signature"]   # tamper-evident
    assert not res["checks"]["verdict"]      # recompute catches the lie too


def test_amber_and_superseded_resolve_to_allow_in_the_recompute():
    by = {v["name"]: v for v in GOLDEN["receipts"]}
    for name in ("amber_belief_does_not_halt", "superseded_belief_skipped"):
        assert ER1.verify(by[name]["receipt"])["recomputed_verdict"] == "ALLOW"


def test_cli_verifies_the_golden_bundle():
    # the documented `er1-verify golden_vectors.json` path — the CLI must unwrap the bundle (not
    # treat it as a single receipt) and verify all six. This guards the bundle-handling regression.
    assert ER1.main([str(HERE / "golden_vectors.json")]) == 0


def test_tilde_equals_is_compatible_release():
    # `~=2.0` is PEP 440 compatible-release (>=2.0, <3.0), NOT exact match. (Runs without Node.)
    def doc(proposed):
        return {"decision": {"verdict": "ALLOW", "reason_code": None, "conflicting_belief_id": None},
                "beliefs": [{"belief_id": "dep:x", "belief_class": "CERTIFIED", "entity": "dep:x",
                             "rule": "satisfies", "source_kind": "deterministic", "status": "active", "value": "~=2.0"}],
                "action": {"tool": "pip_install", "asserts": {"dep:x": proposed}, "resource": "req.txt"},
                "action_binding": {"args_hash": "sha256:" + "0" * 64}, "pre_state_root": "sha256:" + "0" * 64,
                "signature": {"algorithm": "ed25519", "public_key": "AA", "signature": "AA"}}
    assert ER1.verify(doc("2.5"))["recomputed_verdict"] == "ALLOW"   # 2.5 satisfies ~=2.0
    assert ER1.verify(doc("3.0"))["recomputed_verdict"] == "HALT"    # 3.0 does not


def test_canonical_json_does_not_normalize():
    # The canonical form deliberately does NOT normalize: NFC is bound to the runtime's Unicode
    # version (CPython 3.12 ships 15.0, Node 24 ships 16.0, and 20 code points compose in one
    # and not the other), so normalizing made the signed bytes depend on the interpreter.
    # RFC 8785 does not normalize either. Two spellings are two strings, with two hashes.
    composed = "\u00e9clair"
    decomposed = "e\u0301clair"
    assert ER1.canonical_json({composed: 1}) != ER1.canonical_json({decomposed: 1})


def test_identity_fields_are_ascii_only():
    # Identity is the one place where "two spellings of one name" is a gate bypass, so the
    # names used to look a constraint up are restricted to printable ASCII. Free text (values,
    # tool, resource) is unrestricted and compared with exact code-point equality.
    r = copy.deepcopy(GOLDEN["receipts"][0]["receipt"])
    r["beliefs"][0]["entity"] = "caf\u00e9"
    res = ER1.verify(r)
    assert res["ok"] is False and any("printable ASCII" in e for e in res["errors"])

    r2 = copy.deepcopy(GOLDEN["receipts"][0]["receipt"])
    r2["action"]["asserts"] = {"caf\u00e9": "x"}
    res2 = ER1.verify(r2)
    assert res2["ok"] is False and any("printable ASCII" in e for e in res2["errors"])


def test_document_text_must_have_one_reading():
    import pytest
    # Duplicate keys let contradictory decoy content ride inside a signed file that verified.
    with pytest.raises(ValueError):
        ER1.load_document('{"a": 1, "a": 2}')
    with pytest.raises(ValueError):
        ER1.load_document("[]")                        # top level must be an object
    with pytest.raises(ValueError):
        ER1.load_document('{"a": "\\ud800"}')          # unpaired surrogate has no UTF-8 form


def test_adversarial_input_fails_and_never_crashes():
    # Every one of these was a crash before the 2026-08-03 external review.
    bad = [
        {"signature": "not-an-object"},                                  # type confusion
        {"signature": {"algorithm": "ed25519", "public_key": 12345, "signature": "x"}},
        {"signature": {"algorithm": "ed25519", "public_key": "!!bad!!", "signature": "!!"}},
        {"beliefs": "not-a-list"},
        {"beliefs": [{"status": "active", "source_kind": "deterministic"}]},  # missing predicate
        {"action": {"asserts": None}},
        [],                                                              # not even an object
    ]
    # Unhashable enum values are NOT tested here: a stub this small dies on `action must be an
    # object` first, so it would never reach the membership test that used to crash. That case
    # needs a whole valid receipt — see the test below.
    for doc in bad:
        res = ER1.verify(doc)
        assert res["ok"] is False, doc


def test_empty_bundle_cannot_pass_a_ci_gate(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text('{"receipts": []}')
    assert ER1.main([str(p)]) == 1        # silence must not read as success


def test_unreadable_input_is_failed_not_a_traceback(tmp_path):
    assert ER1.main([str(tmp_path / "missing.json")]) == 1
    junk = tmp_path / "junk.json"
    junk.write_text("{not json")
    assert ER1.main([str(junk)]) == 1


def test_malformed_enum_values_print_a_verdict_instead_of_a_traceback(tmp_path, capsys):
    """A crash is not a verdict. These four inputs exited 1 with an uncaught TypeError, and a
    sweep that only reads exit codes cannot tell that apart from a clean FAILED — the assertion
    has to be on what was PRINTED."""
    good = copy.deepcopy(GOLDEN["receipts"][0]["receipt"])
    cases = [
        ("decision.verdict", lambda r: r["decision"].update(verdict=[])),
        ("beliefs[0].status", lambda r: r["beliefs"][0].update(status=[])),
        ("beliefs[0].source_kind", lambda r: r["beliefs"][0].update(source_kind={})),
        ("beliefs[0].belief_class", lambda r: r["beliefs"][0].update(belief_class=[])),
    ]
    for field, mutate in cases:
        rec = copy.deepcopy(good)
        mutate(rec)
        p = tmp_path / "bad.json"
        p.write_text(json.dumps(rec))
        assert ER1.main([str(p)]) == 1, field
        out = capsys.readouterr().out
        assert out.startswith("FAILED ✗"), f"{field}: no verdict line, got {out!r}"
        assert f"malformed receipt: {field} " in out, f"{field}: not reported as malformed"


def test_quoted_values_in_errors_render_the_javascript_way(tmp_path):
    """The malformed-receipt strings are compared literally against er1_verify.mjs, so a value
    quoted into one must match JSON.stringify: no space after a comma, and no trailing `.0`."""
    assert ER1._q([1, 2]) == "[1,2]"
    assert ER1._q({"a": 1, "b": [2, 3]}) == '{"a":1,"b":[2,3]}'
    assert ER1._q(1.0) == "1"
    assert ER1._q("active") == '"active"'
    assert ER1._q(None) == "null"
    assert ER1._q(True) == "true"


def test_pubkey_pinning_rejects_a_self_signed_receipt():
    # The verifier accepts the key a receipt carries (documented scope). Pinning
    # is how a relying party gets a trust anchor.
    bundle = json.loads((HERE / "golden_vectors.json").read_text())
    receipt = bundle["receipts"][0]["receipt"]
    assert ER1.verify(receipt)["ok"] is True                       # unpinned: verifies
    assert ER1.verify(receipt, {"some-other-key"})["ok"] is False  # pinned elsewhere: rejected
    real = receipt["signature"]["public_key"]
    assert ER1.verify(receipt, {real})["ok"] is True               # pinned correctly: verifies


def test_small_order_helper_covers_every_spelling():
    """The blacklist guards the worst bug this project has had — one constant signature block
    that verified every receipt. Its corpus cases were dead for a week: they carried 87- and
    88-character signatures where 86 is required, so they died at the base64 length gate and
    never reached the check. Deleting the entire blacklist left the suite green.

    This tests the helper's contract directly, so the masking logic cannot be quietly dropped."""
    small = {
        "00" * 32,                                                     # zero
        "01" + "00" * 31,                                              # identity, canonical
        "01" + "00" * 30 + "80",                                       # identity, sign bit set
        "ee" + "ff" * 31,                                              # p+1
        "ec" + "ff" * 30 + "7f",                                       # p-1
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    }
    for h in small:
        assert ER1._small_order(bytes.fromhex(h)), f"{h} must be rejected as degenerate"
        # every one of these also has a sign-bit twin that decodes to the same point
        raw = bytearray(bytes.fromhex(h))
        raw[31] ^= 0x80
        assert ER1._small_order(bytes(raw)), f"sign-bit twin of {h} must be rejected"
    # the real base point must NOT be rejected, or every genuine receipt breaks
    assert not ER1._small_order(bytes.fromhex("58" + "66" * 31))


def test_universal_forgery_is_refused_end_to_end():
    """The actual attack, correctly encoded: public key = identity point, signature =
    basepoint || S=1. With A = identity the verification equation collapses to S*B == R, which
    this satisfies for EVERY message. Both operands correctly sized, so it reaches the check."""
    import base64
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    forged = copy.deepcopy(GOLDEN["receipts"][3]["receipt"])
    forged["signature"] = {
        "algorithm": "ed25519",
        "public_key": b64(bytes.fromhex("01" + "00" * 31)),
        "signature": b64(bytes.fromhex("58" + "66" * 31) + bytes.fromhex("01" + "00" * 31)),
    }
    assert len(forged["signature"]["public_key"]) == 43
    assert len(forged["signature"]["signature"]) == 86
    assert ER1.verify_signature(forged) is False
    assert ER1.verify(forged)["ok"] is False


def test_post_state_root_rule_is_enforced():
    # er1.schema.json states it; before 2026-08-03 nothing checked it, so an
    # ALLOW receipt could record no resulting state and still verify.
    allow = copy.deepcopy(
        [w for w in GOLDEN["receipts"] if w["receipt"]["decision"]["verdict"] == "ALLOW"][0]["receipt"])
    allow["post_state_root"] = None
    res = ER1.verify(allow)
    assert res["ok"] is False and any("post_state_root" in e for e in res["errors"])

    halt = copy.deepcopy(
        [w for w in GOLDEN["receipts"] if w["receipt"]["decision"]["verdict"] == "HALT"][0]["receipt"])
    halt["post_state_root"] = halt["pre_state_root"]      # HALT must not record a resulting state
    res = ER1.verify(halt)
    assert res["ok"] is False and any("post_state_root" in e for e in res["errors"])


def test_action_binding_must_mirror_the_action():
    r = copy.deepcopy(GOLDEN["receipts"][0]["receipt"])
    r["action_binding"]["tool"] = "some_other_tool"
    res = ER1.verify(r)
    assert res["ok"] is False and any("does not mirror" in e for e in res["errors"])


def test_bom_prefixed_input_is_tolerated(tmp_path):
    p = tmp_path / "bom.json"
    p.write_text("﻿" + json.dumps(GOLDEN), encoding="utf-8")
    assert ER1.main([str(p)]) == 0


if __name__ == "__main__":
    test_every_golden_receipt_verifies()
    test_signatures_use_the_pinned_key()
    test_tamper_is_caught_by_both_signature_and_recompute()
    test_amber_and_superseded_resolve_to_allow_in_the_recompute()
    test_cli_verifies_the_golden_bundle()
    test_tilde_equals_is_compatible_release()
    print("ER1 conformance: all checks passed ✓")
