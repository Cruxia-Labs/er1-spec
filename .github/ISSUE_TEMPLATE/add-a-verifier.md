---
name: Add a verifier (good first verifier)
about: Claim or propose an independent ER1 verifier in a new language.
title: 'Verifier: <language>'
labels: ['good first verifier', 'conformance']
---

Thanks for adding an independent verifier — it's the single most valuable contribution to ER1, and
the thing that turns "a format two files agree on" into "a format anyone can recompute."

**Language / runtime:**
<!-- e.g. Rust, Rust→WASM, Go, TypeScript, Swift … -->

**Repo (if you have one yet):**
<!-- link, or leave blank and add it on the PR -->

The task (full detail in [IMPLEMENTATIONS.md](https://github.com/Cruxia-Labs/er1-spec/blob/main/IMPLEMENTATIONS.md) +
[CONFORMANCE.md](https://github.com/Cruxia-Labs/er1-spec/blob/main/CONFORMANCE.md)):

- [ ] Reproduce all **7 primitives + 6 receipts** in `golden_vectors.json`, byte-for-byte
- [ ] A one-byte tamper yields `FAILED`
- [ ] Independent of our code (a re-implementation, not a wrapper)

**Conformance output** (paste when ready):

```
<your verifier> golden_vectors.json
…
```

Found a vector that's ambiguous or under-specified? That's a bug in our spec — say so here and we'll
fix it with you.
