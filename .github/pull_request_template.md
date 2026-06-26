<!-- Adding a verifier? Use the checklist below. For other changes, just describe what and why. -->

## Adding a conformant verifier

- **Language / runtime:**
- **Repo:**

Checklist:

- [ ] Reproduces every entry in `golden_vectors.json` (7 primitives + 6 receipts) byte-for-byte
- [ ] A one-byte tamper yields `FAILED`
- [ ] Does not import or vendor our reference code (an independent implementation)
- [ ] Added one row to the roster table in `IMPLEMENTATIONS.md` linking the repo

**Conformance output:**

```
<paste: all entries VERIFIED, and the one-byte-tamper case FAILED>
```

<!-- If a vector was ambiguous, note it — spec ambiguity is our bug, not yours. -->
