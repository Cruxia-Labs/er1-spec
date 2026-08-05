# Contributing to ER1

The most valuable contribution is an **independent verifier in a new language** — see
[IMPLEMENTATIONS.md](IMPLEMENTATIONS.md) for the four-step path and [CONFORMANCE.md](CONFORMANCE.md)
for the exact procedure. Passing the frozen `golden_vectors.json` *is* the bar; we don't gatekeep
beyond that.

Also welcome:

- **Spec ambiguities** — if a golden vector is under-specified or two readings are possible, open an
  issue. That's our bug, not yours.
- **Docs** — clarifications to `CONFORMANCE.md` / `SCOPE_OF_CERTIFICATION.md` that help an implementer.

## Running the tests

```bash
pip install cryptography pytest
python -m pytest -q                      # Python, Node and browser-build suites
python tests/differential_fuzz.py        # the two CLIs must agree byte-for-byte
python tests/mutation_gate.py            # every guard is actually guarded (add --fast to skip Playwright)
```

The mutation gate exists because of how this codebase fails. Nearly every test here asserts that
something is **refused**, and a refusal test keeps passing when the check it was written for has been
deleted and something else rejects the input first. That has happened repeatedly: a duplicate-key
guard that tested a `Set` nothing wrote to, a universal-forgery guard its own tests never reached, a
browser build with no parse gate while the module it wrapped had every rule, and a size-bound test
that passed either way because an oversize file fails verification anyway.

So the gate deletes one guard at a time and requires the suite to notice. **If you add a check, add a
mutation for it.** Two rules it enforces, both learned by getting them wrong: a mutation whose pattern
no longer matches is a hard failure rather than a skip (a mutation that does not apply looks exactly
like a guard that catches nothing), and nothing is ever scored against an already-red baseline.

A handful of guards are marked `unobservable` — kept deliberately, but provably not catchable by any
honest test, with the measurement that established this recorded in the entry. Do not "fix" one by
writing a test for it; writing a test that passes for the wrong reason is the failure the gate exists
to prevent.

By contributing you agree your contribution is licensed under this repo's Apache-2.0 license. No CLA.
