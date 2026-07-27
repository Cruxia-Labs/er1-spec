# Signing keys

ER1 receipts carry an Ed25519 signature whose public key rides inside the
receipt (`signature.public_key`, raw 32 bytes, base64url unpadded). The
integrity claim is always recomputation — the verifiers re-derive the
verdict and hashes from the receipt body with the key ignored entirely.
What a key adds is **continuity**: the same key signing a run of receipts
lets you check that one operator produced them.

## Key tiers

| `key_tier` | Meaning |
|---|---|
| `ephemeral` | Minted for the run (or derived from a public phrase). Proves tamper-evidence and replayability, never authorship. |
| `org` | A persistent operator key, announced here. Proves week-to-week continuity of one operator. Not an identity system. |
| `witnessed` | Reserved: an `org` key countersigned by third parties. |

## Announced keys

| Fingerprint | Public key (base64url) | Tier | Signs | Effective |
|---|---|---|---|---|
| `86cdb7ce03de6630` | `qFfr7mvoHYBdezzygPk6YN39vCWUDD0rJvsFDXvb93Q` | `org` | the weekly sweep bank (`sweep-bank-<week>` receipts) | 2026-W31 |

The fingerprint is `sha256(raw_public_bytes)`, first 16 hex characters.

Checking a bank receipt against this table:

```
python3 -c "import json,hashlib,base64; \
  r=json.load(open('receipt.er1.json')); \
  pk=r['signature']['public_key']; \
  raw=base64.urlsafe_b64decode(pk+'='*(-len(pk)%4)); \
  print(hashlib.sha256(raw).hexdigest()[:16])"
```

A key rotation or loss is announced by adding a successor row with its
effective week. Earlier receipts still verify and recompute; only the
continuity chain restarts.
