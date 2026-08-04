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


def test_keys_are_nfc_normalized_before_ordering():
    # An independent port that normalizes-then-sorts (the natural reading of
    # CONFORMANCE.md) must land on our exact bytes. Sorting raw and normalizing
    # at emit time mis-orders keys whose normalized form sorts differently.
    composed = "éclair"            # é
    decomposed = "éclair"         # e + combining acute
    assert ER1.canonical_json({composed: 1}) == ER1.canonical_json({decomposed: 1})
    # …and two keys that collide under NFC are ambiguous, never silently duplicated
    try:
        ER1.canonical_json({composed: 1, decomposed: 2})
    except ValueError as exc:
        assert "NFC" in str(exc)
    else:
        raise AssertionError("colliding keys must raise, not emit a duplicate")


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


def test_pubkey_pinning_rejects_a_self_signed_receipt():
    # The verifier accepts the key a receipt carries (documented scope). Pinning
    # is how a relying party gets a trust anchor.
    bundle = json.loads((HERE / "golden_vectors.json").read_text())
    receipt = bundle["receipts"][0]["receipt"]
    assert ER1.verify(receipt)["ok"] is True                       # unpinned: verifies
    assert ER1.verify(receipt, {"some-other-key"})["ok"] is False  # pinned elsewhere: rejected
    real = receipt["signature"]["public_key"]
    assert ER1.verify(receipt, {real})["ok"] is True               # pinned correctly: verifies


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
