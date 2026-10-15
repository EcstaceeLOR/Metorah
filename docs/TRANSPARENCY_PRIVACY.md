# Public migration transparency and evidence privacy — Issue #33

## What works

The offline `tools/transparency/index.py` library generates a canonical, deterministic public index and content-addressed objects using SHA-256. A verifier with **only** a pinned, externally distributed index digest and a downloaded evidence directory can rehash each exact object, detect missing or altered bytes, reject duplicate/noncanonical records and recognize explicit fail-closed source-authentication flags. It requires no Metorah dashboard or operator API.

**This is E1 byte integrity, NOT consensus, source authenticity, guaranteed availability, signed publication authority, or proof of a real Portaldot migration.** The index always has `can_activate=false` and `can_claim=false`. Published report signatures must also be checked independently using `tools/attestations/cli.py` and an out-of-band pinned signing identity; an object hash alone does not prove who published it.

## Publishing rule

A public index may contain only pre-reviewed, already-redacted documents in allowlisted categories: `signed_report_redacted`, `public_verifier_build`, `public_challenge_status`, and `public_methodology`. The caller must provide an explicit privacy-review approval object before generating an index. This object is merely an offline API gate; it is **not cryptographically authenticated** and is not a replacement for production role checks or lawful informed consent.

This first-pass scanner refuses common sensitive JSON field names (wallet/address mappings, balance/allocations, PII and secret keys) and obvious private-key headers. **It is NOT a complete PII detector**: free text, indirectly identifying fields, commitment correlation, quasi-identifiers, nested encodings and metadata may still leak. All publication candidates require trained human review and a data-protection impact assessment. Private artifacts must never be passed as public entries.

## Privacy lifecycle and retention requirements

- Default to nonpublication. Require explicit informed consent where legally required, a defined lawful basis, purpose limitation, documented retention period and access controls for nonpublic evidence. Consent withdrawal cannot guarantee erasure of material already mirrored publicly.
- Publish only a minimal redacted verification report, status, public build fingerprint, and challenge status without litigant identities. Raw holder lists, balances, source/destination wallet bindings, contact data, chain addresses tied to individual holders, signed registration messages and unredacted objections remain restricted.
- Keep private documents encrypted at rest and in transit, with tenant isolation, authorized downloads, per-object audit trail, retention schedule and a legally reviewed deletion process; off-chain private deletion cannot erase on-chain immutable facts.
- Public material should be mirrored to at least two organizationally independent stores, with availability probes, downloadable verifier source/binary digest, published log-root checkpoints and signed append-only sequence/history across revisions. An operator-controlled mirror without independent witnessing cannot prevent equivocation, reordering, tail truncation or suppression.
- If an operator disappears, an external auditor should obtain the pinned index digest, public object directory, expected signer key and verifier build digest independently, then reproduce each integrity check and independently validate all underlying cryptographic source and finality proofs. Publishing a URL alone does not establish continued availability.
- If a public artifact is discovered to contain personal data, immediately suspend new publication, restrict first-party mirrors where lawful and feasible, notify the affected owner and apply the incident/notification policy. Public mirrors and blockchain copies may be impossible to erase. Publish a signed revocation/redaction notice without silently rewriting historic commitments.

## Independent check

```python
from pathlib import Path
from tools.transparency.index import verify
# The index SHA256 MUST arrive from an independently trusted channel.
result = verify(Path("downloaded-public-evidence"), "<64 lowercase hex pinned index digest>")
assert result["status"] == "PUBLIC_BYTES_INTEGRITY_VERIFIED"
assert result["can_activate"] is False
```

Tests: `python -m unittest discover -s test -p 'test_transparency_index.py' -v`.

## Outstanding production acceptance gates (keep issue open)

1. Build persistent, replicated object storage with atomic signed append-only publication, externally witnessed heads, anti-equivocation auditing, public independent endpoints and availability monitoring (#47).
2. Authenticate consent, reviewers and publishers with durable RBAC and tamper-resistant approval records (#49); enforce legally reviewed regional privacy and deletion/retention policies.
3. Wire cryptographically verified V3 source header/finality, storage and completeness evidence (#18, #27–#31); integrate dispute disposition (#32). Publishing E1 evidence must not imply E3 or E4.
4. Independently restore/download evidence after simulated operator outage and malicious history rollback; fuzz privacy filters, review metadata leak channels and commission security/privacy audit.

No chain transaction, fund movement, customer data publication, or production claim is enabled by this PR.
