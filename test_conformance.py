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


if __name__ == "__main__":
    test_every_golden_receipt_verifies()
    test_signatures_use_the_pinned_key()
    test_tamper_is_caught_by_both_signature_and_recompute()
    test_amber_and_superseded_resolve_to_allow_in_the_recompute()
    test_cli_verifies_the_golden_bundle()
    test_tilde_equals_is_compatible_release()
    print("ER1 conformance: all checks passed ✓")
