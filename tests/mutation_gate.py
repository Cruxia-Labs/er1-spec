#!/usr/bin/env python3
"""Mutation gate for the ER1 reference verifiers: prove the suite guards what it claims to guard.

A verifier's tests are unusual: almost all of them assert that something is REFUSED. That makes
them uniquely easy to get wrong, because a test that expects failure still passes when the code
fails for a completely different reason — or when the check it was written for has been deleted and
something else refuses the input first. Every serious defect this repo has had was a guard that was
not guarding, and a green suite was never evidence to the contrary:

  - the duplicate-key guard was dead code: it tested a Set that was never written to
  - the browser build had no parse gate at all, while the module it wrapped had every rule
  - the verify PAGE shipped its own loose bundle-splitter, so the matrix tested the module beneath it
  - one constant signature block verified every receipt in all three implementations
  - the universal-forgery guard that fixed it was itself unreached by its own tests
  - an unsigned bundle-entry `name` was printed verbatim, forging VERIFIED lines out of a FAILED run
  - "nothing checked is never a pass" was a whole-RUN condition, so one good file covered an empty one

This script inverts the question. Instead of asking "do the tests pass?", it neuters one
load-bearing check at a time and asks "does the suite NOTICE?". A mutation nothing catches is a
guard with no test, and is reported as a failure.

    python tests/mutation_gate.py               # every mutation
    python tests/mutation_gate.py --list        # names only
    python tests/mutation_gate.py --only NAME   # one mutation
    python tests/mutation_gate.py --fast        # skip the browser matrix (~3 browsers x N mutations)

Three rules, each learned by getting it wrong:

1. **A mutation that fails to apply is indistinguishable from a guard that catches nothing.** The
   first hand-run of these mutations reported a false survivor because the pattern silently matched
   nothing. Every mutation asserts the text actually changed, and a stale pattern is a hard FAILURE,
   not a skip — otherwise this file rots into a no-op as the code moves.

2. **Never score against a red baseline.** "The mutation was caught" means nothing if the suite was
   already failing. The baseline runs first and the gate refuses to proceed unless it is green.

3. **A mutation the scoring run cannot possibly catch must be skipped loudly, never scored.** Under
   --fast the browser matrix does not run, so page-only guards are unscoreable — reporting them as
   SURVIVED would be a lie in the safe direction, which is the worst kind.

Scoring is by failing-test NAME, not by count, so a mutation "caught" by an unrelated flake is
visible rather than silently credited.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "__pycache__", "node_modules", "dist", ".pytest_cache", "er1_verify.egg-info"}


@dataclass
class Mutation:
    """One neutered check. `find` must appear EXACTLY ONCE in `file`."""

    name: str
    file: str
    find: str
    replace: str
    guards: str  # what an attacker gets back in the real world if this check is gone
    # True when only the browser matrix can catch it. --fast cannot score these, and a run that
    # cannot catch a mutation must not report it as surviving.
    needs_browser: bool = False
    # Set ONLY when the guard is redundant given the others, so its removal is not black-box
    # observable and no honest test can catch it. The value explains why and is printed. Such a
    # mutation surviving is EXPECTED and does not fail the build. Never set this to silence a
    # survivor you have not actually measured — writing a test that passes for the wrong reason is
    # the exact failure this whole file exists to prevent.
    unobservable: str = ""
    expect: list[str] = field(default_factory=list)  # informational


MUTATIONS = [
    # ── the report is a trusted surface ──
    # CI greps this output. The exit code was always right; the REPORT was forgeable.
    Mutation(
        "py_name_printed_raw",
        "er1_verify.py",
        '    esc = json.dumps(name)[1:-1]     # drop json\'s own quotes, keep its escaping\n'
        '    if len(esc) > 60:\n'
        '        esc = esc[:57] + "..."\n'
        '    return f\' name="{esc}"\'',
        '    return f\' name="{name}"\'',
        "an unsigned, unvalidated bundle-entry name carrying a newline prints its own "
        "'VERIFIED  prod-deploy-approval  verdict=ALLOW' line out of a receipt that FAILED.",
    ),
    Mutation(
        "py_name_uncapped",
        "er1_verify.py",
        '    if len(esc) > 60:\n        esc = esc[:57] + "..."\n',
        "",
        "the length cap. Without it a name can push the real verdict off a terminal line or bury "
        "it under padding, which is the same forgery with more bytes.",
    ),
    Mutation(
        "mjs_name_printed_raw",
        "er1_verify.mjs",
        '  let esc = JSON.stringify(name).slice(1, -1)\n'
        '    .replace(/[\\u007f-\\uffff]/g, (c) => `\\\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);\n'
        '  if (esc.length > 60) esc = esc.slice(0, 57) + "...";\n'
        '  return ` name="${esc}"`;',
        '  return ` name="${name}"`;',
        "the same report forgery in the Node CLI. The two implementations must render hostile "
        "names byte-identically or the reports disagree about what was verified.",
    ),
    # ── nothing checked is never a pass ──
    Mutation(
        "py_empty_input_not_per_input",
        "er1_verify.py",
        "            entries = _receipts_from(doc, path)\n            if not entries:",
        "            entries = _receipts_from(doc, path)\n            if False:",
        "`er1-verify good.json empty-bundle.json` exits 0 and never prints empty-bundle.json. A CI "
        "gate globbing a directory sees success for a file that verified nothing.",
    ),
    Mutation(
        "mjs_empty_input_not_per_input",
        "er1_verify.mjs",
        "    if (entries.length === 0) {",
        "    if (false) {",
        "the same silent pass in the Node CLI.",
    ),
    # ── one reading or none ──
    # This cross-check compares the keys the document TEXT contains against the keys the parser
    # produced, so "one reading or none" is checked rather than assumed of whatever parser is
    # underneath. See the note on both mutations below for what it is and is not evidence of.
    Mutation(
        "mjs_trusts_the_parser",
        "er1_verify.mjs",
        "  if (seen.length !== want.length || seen.some((k, idx) => k !== want[idx])) {",
        "  if (false) {",
        "the only thing standing between a signature computed over a parser's misreading and a "
        "VERIFIED line, if a JSON parser under this code is ever wrong about its own keys.",
        unobservable=(
            "MEASURED, not assumed, and it corrects an earlier claim of ours. Commit 5c94d09 "
            "introduced this guard citing a specific reproducible V8 defect — Node 24's JSON.parse "
            "misreading an escaped object key after a priming parse in the same process. That does "
            "NOT reproduce: 200,000 parses across four escaped-key shapes with interleaved priming "
            "parses, on the very version named (v24.11.1), produced zero misparses. Nor is the "
            "guard reachable by construction: twelve documents built specifically to split a hand "
            "scanner from a real parser (__proto__, astral escapes, NUL, braces and commas inside "
            "string values, nested arrays, empty keys) produced zero disagreements — duplicate keys "
            "throw in the scanner before this comparison, and every other shape reads identically "
            "both ways. So absent an actual parser defect, text and parse always agree and no "
            "honest test can catch this guard's removal. KEPT anyway: it is nearly free (the scan "
            "already runs for duplicate detection), and 'one reading or none' is a promise this "
            "format makes, so checking it rather than trusting a parser is right even when no "
            "parser is known to be wrong. What is NOT justified is citing a V8 bug as its reason."
        ),
    ),
    Mutation(
        "browser_trusts_the_parser",
        "verify/er1_verify.browser.mjs",
        "  if (seen.length !== want.length || seen.some((k, idx) => k !== want[idx])) {",
        "  if (false) {",
        "the same check in the browser build, which is the copy a stranger actually runs.",
        needs_browser=True,
        unobservable="Same measurement as mjs_trusts_the_parser; the browser build shares the code.",
    ),
    Mutation(
        "py_duplicate_keys",
        "er1_verify.py",
        "        if k in seen:",
        "        if False:",
        "245 bytes of contradictory decoy content riding inside a signed file that still verifies, "
        "because parsers keep the last of a duplicated key.",
    ),
    Mutation(
        "mjs_duplicate_keys",
        "er1_verify.mjs",
        "        if (top && top.seen.has(str)) {",
        "        if (false) {",
        "the same decoy content in Node. This guard was once dead code — it tested a Set that was "
        "never written to — so Node verified documents Python refused.",
    ),
    Mutation(
        "py_lone_surrogates",
        "er1_verify.py",
        "            if 0xD800 <= ord(ch) <= 0xDFFF:",
        "            if False:",
        "a string with no UTF-8 form, hence no canonical byte form: Python raised on it while "
        "JavaScript hashed a replacement character and reported VERIFIED.",
    ),
    Mutation(
        "mjs_utf8_not_fatal",
        "er1_verify.mjs",
        'new TextDecoder("utf-8", { fatal: true })',
        'new TextDecoder("utf-8")',
        "four byte-distinct tampered files all verifying against one signature with one hash, "
        "because U+FFFD substitution collapses them.",
    ),
    # ── forgery ──
    Mutation(
        "py_small_order_public_key",
        "er1_verify.py",
        "        if _small_order(pub_raw) or _small_order(sig_raw[:32]):",
        "        if _small_order(sig_raw[:32]):",
        "universal forgery: one constant signature block verifies EVERY receipt. Small-order public "
        "keys are the whole attack, and sign-bit spellings of the identity point are why the check "
        "masks byte 31 instead of comparing exact encodings.",
    ),
    Mutation(
        "py_small_order_R",
        "er1_verify.py",
        "        if _small_order(pub_raw) or _small_order(sig_raw[:32]):",
        "        if _small_order(pub_raw):",
        "libsodium's has_small_order is applied to R as well as the key, and this mirrors it.",
        unobservable=(
            "MEASURED, not assumed: with the R operand dropped, no case in the conformance corpus "
            "changes verdict, and none can be constructed that does. A small-order R makes the "
            "verification equation fail on its own for any key an attacker does not control, so the "
            "key operand above already refuses everything this one would. Kept because it mirrors "
            "libsodium exactly and is insurance if the key check is ever narrowed — but no honest "
            "test can catch its removal today."
        ),
    ),
    # ── the document says what it is ──
    Mutation(
        "py_ambiguous_bundle",
        "er1_verify.py",
        '        if any(k in doc for k in ("decision", "signature", "action", "beliefs")):',
        "        if False:",
        "an unsigned top-level `receipts` array deciding what got verified: a forged receipt that "
        "also carries one genuine receipt prints VERIFIED and exits 0.",
    ),
    Mutation(
        "py_belief_class_binding",
        "er1_verify.py",
        "        if BELIEF_CLASS_OF_SOURCE[source_kind] != belief_class:",
        "        if False:",
        "a producer shipping {source_kind: nl_extracted, belief_class: CERTIFIED} — a prose-extracted "
        "guess wearing the word CERTIFIED in a signed field. In a format whose claim is that you need "
        "not trust the producer, a label the verifier never checks is that trust creeping back in.",
    ),
    # ── denial of service and resource bounds ──
    Mutation(
        "py_max_bytes",
        "er1_verify.py",
        "                if len(raw) > MAX_BYTES:",
        "                if False:",
        "the size bound. It is measured in BYTES on purpose: reading through a text handle and "
        "taking len() counted CHARACTERS, so one 10 MB file of two-byte characters passed here and "
        "was refused in Node — one signed receipt, two verdicts.",
    ),
    Mutation(
        "py_regular_file_only",
        "er1_verify.py",
        "                if not stat.S_ISREG(st.st_mode):",
        "                if False:",
        "a named pipe or device blocking forever: the CI gate wedges with no verdict, no error and "
        "no timeout. A hang is worse than a crash.",
    ),
    # ── what the page shows is what the page certifies ──
    Mutation(
        "page_no_size_bound",
        "verify/index.html",
        "    if (nbytes > MAX_BYTES) {",
        "    if (false) {",
        "the browser build's only size bound. MAX_BYTES lived in Python and Node alone until this "
        "was wired; it is now exported from the module so there is one constant, not three.",
        needs_browser=True,
    ),
    Mutation(
        "page_hides_signer",
        "verify/index.html",
        "          (typeof res.signer === \"string\"\n"
        "            ? ` &nbsp;signer=${esc(res.signer.slice(0, 12))}… <b>(unpinned)</b>`\n"
        "            : ` &nbsp;signer=${esc(String(res.signer))}`) +",
        '          "" +',
        "the signer. This page certifies that a receipt is signed by the key it NAMES, not that the "
        "key belongs to anyone you trust — a green VERIFIED with no visible signer invites exactly "
        "the opposite conclusion.",
        needs_browser=True,
    ),
]


def _copy_repo(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for item in REPO.iterdir():
        if item.name in SKIP_DIRS:
            continue
        target = dest / item.name
        if item.is_dir():
            shutil.copytree(item, target, ignore=shutil.ignore_patterns(*SKIP_DIRS))
        else:
            shutil.copy2(item, target)


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=1800)


def _pytest_failures(proc: subprocess.CompletedProcess) -> list[str]:
    return re.findall(r"^FAILED (\S+)", proc.stdout, re.M)


def _browser_failures(proc: subprocess.CompletedProcess) -> list[str]:
    out = proc.stdout + proc.stderr
    return [ln.strip() for ln in out.splitlines() if "FAIL" in ln]


def score(cwd: Path, with_browser: bool) -> tuple[list[str], str]:
    """Return (failing test names, raw tail) for the scoring run."""
    proc = _run([sys.executable, "-m", "pytest", "-q", "--tb=no", "-rf"], cwd)
    failures = _pytest_failures(proc)
    tail = proc.stdout.strip().splitlines()[-1:] or [""]
    if failures or not with_browser:
        return failures, tail[0]
    bproc = _run([sys.executable, "tests/run_browser_matrix.py"], cwd)
    if bproc.returncode != 0:
        return _browser_failures(bproc) or ["browser-matrix"], "browser matrix red"
    return [], tail[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only")
    ap.add_argument("--fast", action="store_true", help="skip the browser matrix")
    args = ap.parse_args()

    if args.list:
        for m in MUTATIONS:
            flag = " [browser]" if m.needs_browser else ""
            flag += " [redundant-by-design]" if m.unobservable else ""
            print(f"{m.name}{flag}")
        return 0

    todo = [m for m in MUTATIONS if not args.only or m.name == args.only]
    if args.only and not todo:
        print(f"no mutation named {args.only!r}", file=sys.stderr)
        return 2

    with_browser = not args.fast
    tmp = Path(subprocess.run(["mktemp", "-d"], capture_output=True, text=True,
                              check=True).stdout.strip())
    pristine = tmp / "pristine"
    _copy_repo(pristine)

    print("baseline (a mutation is only meaningful against a green suite) ...", flush=True)
    base_failures, base_tail = score(pristine, with_browser)
    if base_failures:
        print(f"REFUSING TO SCORE: the baseline suite is already red: {base_failures[:5]}")
        return 1
    print(f"  baseline green: {base_tail}\n")

    caught, survived, skipped, redundant = [], [], [], []
    for m in todo:
        if m.needs_browser and not with_browser:
            skipped.append(m)
            print(f"SKIP     {m.name}  (needs the browser matrix; --fast cannot score it)")
            continue

        work = tmp / f"work-{m.name}"
        shutil.rmtree(work, ignore_errors=True)
        _copy_repo(work)
        target = work / m.file
        text = target.read_text()

        occurrences = text.count(m.find)
        if occurrences != 1:
            print(f"FAIL     {m.name}: pattern occurs {occurrences}x in {m.file}, expected exactly 1.")
            print("         A stale pattern is a hard failure, not a skip: a mutation that does not")
            print("         apply is indistinguishable from a guard that catches nothing.")
            return 1
        target.write_text(text.replace(m.find, m.replace))

        failures, _ = score(work, with_browser)
        if failures:
            caught.append(m)
            print(f"caught   {m.name}  <- {failures[0]}"
                  + (f" (+{len(failures) - 1} more)" if len(failures) > 1 else ""))
        elif m.unobservable:
            redundant.append(m)
            print(f"REDUNDANT {m.name}  (expected: not black-box observable)")
        else:
            survived.append(m)
            print(f"SURVIVED {m.name}  -- NOTHING CAUGHT THIS. Guards: {m.guards}")

    print(f"\n{len(caught)} caught, {len(survived)} survived, {len(skipped)} skipped, "
          f"{len(redundant)} redundant-by-design, of {len(todo)}")
    if skipped:
        print("  skipped mutations are NOT evidence of anything — run without --fast before "
              "trusting a green result.")
    for m in redundant:
        print(f"\nREDUNDANT GUARD (kept, not independently testable): {m.name}\n  {m.unobservable}")
    if survived:
        print("\nEach SURVIVED line is a check with no test. Write the test, or record why the")
        print("guard is not observable — do not delete the entry.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
