# Signed and independently reproducible verification reports — Issue #31

**Assurance class: E1 only.** Metorah can create a cryptographically signed operator attestation that an **untrusted published evidence package** is byte-for-byte self-consistent. This does NOT prove Portaldot V3 chain identity, finalized consensus, trie membership, source entitlement completeness, or destination funding. A successful verification report can NEVER activate migrations or customer claims.

## Independent report format

A verification evidence directory must include **all four files**:

| File | Purpose | Independently verified here |
| --- | --- | --- |
| `manifest.json` | Canonical V1 SHA-256 migration header, complete proposed leaves, positional root, manifest digest | Exact V1 encoding and digest reproduction; NOT real holder completeness |
| `header-observation.json` | #27 RPC-observed genesis, source block hash/number and state root | Consistency with manifest only; NOT trusted finality |
| `trie-proof-bundle.json` | #28 source storage-proof nodes and values | Block and state-root reference consistency only; **NOT cryptographic trie verification** |
| `holder-reconciliation.json` | #29 complete-relative-to-supplied-data supply and holder reconciliation | Reported allocation totals, root and digest consistency only; NOT actual authentic source completeness |

The new `tools/attestations/report.py` enforces the exact file set, bounded UTF-8 JSON without duplicate fields or nonfinite numbers, canonical V1 manifest hash/leaf rules, pinned chain identity and cross-report conservation fields. It computes byte-level SHA-256 commitments for every original file, not normalized or pretty-printed equivalents.

The signer does not choose a result. The evaluator produces **`E1_CHECKS_PASS`** or **`E1_CHECKS_FAIL`** and a deterministic sorted list of findings from the published files. PASS means *only these E1 checks* passed; FAIL may be signed and independently reproduced as a valid negative result. A self-proclaimed finality or claim-activation flag in published auxiliary evidence is treated as a finding, not automatically trusted.

### Cryptographic receipt

`tools/attestations/report.py` builds a strict `metorah-verification-payload-v1` containing:

- Exact **migration ID** and source **genesis, contract, code hash, finalized block hash, block number, state root**.
- Exact **destination chain ID and contract**, plus canonical manifest/header-derived SHA-256 Merkle root and manifest digest.
- Four artifact byte digests and byte lengths, computed verdict and findings, UTC timestamp, fresh 256-bit run nonce.
- **Exact trusted verifier build SHA-256**, 40-character Git revision and version label. An external reviewer must independently decide which verifier build digest/revision to trust; signer assertions alone do not establish software provenance.
- `verification_scope=E1_OFFLINE_EVIDENCE_CONSISTENCY_ONLY`, `signer_scope=OPERATOR_ATTESTATION_ONLY_NOT_FINALITY_PROOF`, `source_chain_authenticated=false`, `consensus_finality_verified=false`, `storage_trie_verified=false`, `can_activate=false`, `can_claim=false`.

The reproducible digest is SHA-256 over domain-separated, lexicographically keyed, compact ASCII JSON:

```text
report_digest = sha256("METORAH_VERIFICATION_REPORT_HASH_V1\0" || canonical_payload_json)
signature_ed25519 = Ed25519Sign(operator_secret,
    "METORAH_ED25519_VERIFICATION_REPORT_V1\0" || 32-byte report_digest)
```

The report embeds the Ed25519 public key, but **the verifier REQUIRES a separately pinned `--trusted-public-key`** (raw 32 bytes as 0x-prefixed lowercase hex). A signature made by any other key is rejected even if internally valid. The verifier also requires an independently pinned `--expected-tool-build-sha256`, verifies Ed25519, recalculates all four byte commitments, repeats the full local evaluation, checks the entire typed payload (including destination chain and migration domain) and rejects differences.

**A report signature binds the operator's report to bytes. It is NOT a Substrate consensus signature or a permission to mint.**

## Offline command sequence

Requires the existing **pinned** `cryptography==46.0.4` dependency in `local_model/requirements.lock`.

Use a proper protected key management service for production signers. For an isolated local test only, generate a new raw Ed25519 seed and its public key. Never commit the key/seed to Git:

```sh
python - <<'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os
k = Ed25519PrivateKey.generate()
p = "local-signing-key.bin"
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(k.private_bytes(serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw, serialization.NoEncryption()))
print("Trusted offline test public key: 0x" +
    k.public_key().public_bytes(serialization.Encoding.Raw,
        serialization.PublicFormat.Raw).hex())
PY
```

The signing CLI refuses private-key files with group/other POSIX permissions and never logs the private bytes. `--tool-build-sha256` must come from independently measured/reviewed verifier bytes; the placeholder below is NOT a trusted build hash. Artifacts must be generated by the preceding source acquisition steps and inspected before signing.

```sh
python tools/attestations/cli.py sign \
  --evidence-dir path/to/complete-evidence \
  --signing-key-file local-signing-key.bin \
  --tool-revision EXACT_40_HEX_COMMIT \
  --tool-version metorah-report-v1 \
  --tool-build-sha256 0xINDEPENDENTLY_REVIEWED_64_HEX_SHA256 \
  --report path/to/new-only-report.json \
  --history path/to/local-attestation-history.json

python tools/attestations/cli.py verify \
  --evidence-dir path/to/complete-evidence \
  --report path/to/new-only-report.json \
  --trusted-public-key 0xEXTERNALLY_APPROVED_SIGNER_32_BYTES \
  --expected-tool-build-sha256 0xINDEPENDENTLY_REVIEWED_64_HEX_SHA256

python tools/attestations/cli.py history-check \
  --history path/to/local-attestation-history.json \
  --trusted-public-key 0xEXTERNALLY_APPROVED_SIGNER_32_BYTES \
  --expected-head 0xLAST_HEAD_DIGEST_SAVED_IN_INDEPENDENT_WITNESS
```

`verify` exits 0 if a properly signed **E1_CHECKS_PASS** result reproduces, 1 if a properly signed **E1_CHECKS_FAIL** reproduces, and 2 on bad signature, untrusted key/build, changed file, inconsistent payload or malformed evidence. A negative result may still be a valid signed record; do not interpret exit 0 as live migration approval.

## Tamper-evident local history and replay defense

The `tools/attestations/history.py` journal uses a single-writer OS lock and atomic replacement of a bounded JSON sequence. Each entry commits to:

- Contiguous index, preceding entry SHA-256 hash (initially zero), signed report digest, Ed25519 signature and signer public key, migration ID and fresh run nonce.
- An independent domain-separated SHA-256 of the entry fields.

Appending verifies the complete report again, the entire prior sequence of signatures, contiguity and hashes, and refuses reuse of a signed report hash or a run nonce for the same migration. The tool can compare an **externally witnessed last-head digest** to detect suffix truncation or rollback.

**Limitations:** Hash chaining without publishing the last head to a genuinely independent witness cannot detect a malicious deletion of the complete journal tail or entire file. A local operator can replace history and its lock; no external anchor service or distributed audit log is implemented in #31. The history is an integrity mechanism, not a permanent immutable ledger. Never describe it as independently witnessed, externally anchored or on-chain unless verifiable witness receipts exist. Signatures attest the operator key and can be replayed to independent verifier clients; the nonce/chain logic prevents repeat append within one validated journal, not a globally enforced once-only migration claim.

## Regression and known release blockers

```sh
python -m pip install -r local_model/requirements.lock
python -m unittest discover -s test -p test_verification_reports.py -v
```

All synthetic tests construct their own keys at runtime; no developer/customer key or live token is touched. Tests include signing/verifying PASS and FAIL, swapped source root, wrong destination chain, signer substitution, report hash tampering, forged E3 flags, changed verifier build, duplicate JSON evidence fields, nonce replays, multiple history entries, deletion/reordering, and external-head rollback detection.

The verifier **does not implement** actual `sp-trie` proof verification, GRANDPA/BEEFY finality, contract storage decoding, source-history completeness, signer registry governance or solvent EVM token settlement; those remain blocked in #18/#27–#30/#34–#42. Even a signed report with a valid public key must not trigger the existing legacy claim ledger or enable production transfers.

**Release: NO-GO for real assets.** Mergeable E1 engineering code does not close the underlying authenticated source-proof acceptance criteria. Full issue #31 acceptance also needs externally retained head receipts, exact reviewed build provenance and an independently reproducible official V3 E3 proof bundle.
