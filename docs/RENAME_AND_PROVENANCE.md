# StateLift → Metorah: source provenance and crypto compatibility

On 2026-10-15, the **StateLift starter** was renamed to **Metorah** for the product repository. This is a branding/repository import, **not** an audited protocol-version change.

## Source provenance

- Source archive: user-provided `StateLift_Starter_2026-10-15 (1).zip`.
- Additional material: `StateLift_Reviewed_Baseline_2026-10-15.zip` from the previous engineering review, adding Foundry tests, GitHub validation workflow, and the engineering audit. Tests are **unverified** unless a live Foundry runner proves them.
- Historical artifact JSON is retained as produced by the **offline Python simulation**, including prior `StateLift` protocol labels and simulated block/hash values.
- Prior audit `docs/ENGINEERING_BASELINE.md` remains historical; prior link references to an uncreated `EcstaceeLOR/StateLift` repo and legacy name are not current instructions. The canonical work tracker is `EcstaceeLOR/Metorah`.

## Intentional compatibility constraints

1. Python `local_model/metorah.py` retains `statelift/poc-v1/*` hashing domain prefixes and its on-disk manifests keep `statelift-poc-v1`. Changing them would change commitments and break existing evidence.
2. Solidity `src/MetorahClaimLedger.sol` retains `STATELIFT_LEAF_V1` under `leafHash`, even though the contract/file was renamed. The contract name is **not** part of the leaf preimage; destination address *is*, so previous deployed ledger commitments would not transfer automatically.
3. The Python and Solidity formats are not interoperable. Do not assert the model's 16 tests validate on-chain Solidity proofs.
4. No actual WASM contract, authenticated storage proof, chain freeze receipt, or token settlement is included.
5. Introducing a Metorah-branded cryptographic scheme requires a **new versioned manifest and cross-language golden vectors** (issue #25 and #26), not a search-and-replace.

## Validation policy

Unit tests must be run against the specific git commit. Do not mark Foundry or Portaldot results passing before runner logs and actual chain evidence are available. Never fund demo keys.
