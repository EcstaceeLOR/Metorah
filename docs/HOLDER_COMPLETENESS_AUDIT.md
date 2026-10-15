# Independent source-entitlement completeness audit — Issue #29

**Status:** Event-replay + complete historical-registry/manifest comparison, for offline engineering review. **Not source-chain authentication or a verified migration.** The algorithm cannot rule out jointly forged storage, history and freeze receipts from a compromised source provider.

## Why valid individual Merkle proofs are insufficient

A proof for Account A confirms only that *A is in the particular tree the operator published*. It does not establish that Account B was also included. Metorah must refuse activation unless the complete actual source holder registry, supply, bindings and cutover event stream are independently authenticated and compared against the candidate migration manifest.

### Contract source-of-truth inputs

The source ink! ledger (#20–#24) exposes an append-only historical holder array indexed from zero, current balance for each account, retained zero-balance tombstones, cap/supply counters, source-caller-authorized beneficiary registrations with nonces, a freeze marker and source-reported \`SourceFrozen\` event.

The reference module at \`tools/reconciliation/audit.py\` replays a **complete supplied event sequence starting from the actual zero-issuance genesis state** and reconstructs:

- Every account's first-funded slot index, irrespective of later burns or transfers back to zero.
- Issued units, burned units, all transfers and current balances, with uint128 checked arithmetic and issuance never exceeding the configured cap.
- Each account's registration history, initial zero destination, previous-beneficiary continuity, nonce starting at 1 and increasing exactly by 1, and immutable destination contract/migration/chain domain.
- Exactly one terminal freeze event, with freeze actor, source contract/asset/domain, block number, total supply, historical and active holder counts, and **zero unbound funded holders**.

Then it compares every supplied historical slot **0 through holder_count-1** to the replayed first-funded holder order and final amount/beneficiary/nonce, including **every zero-balance tombstone**. It rejects gaps, removed or duplicated holders, altered balances, inconsistent supply, missing registrations, stale destination wallets, missing issuance/transfer/burn events, wrong cutoff or domain and any event after freeze.

Finally it calls the canonical V1 SHA-256 manifest generator (#25), independently builds all positive entitlements in ascending historical-slot order, and compares the generated **whole manifest object** with the operator's submission. A mathematically valid Merkle tree built by deliberately omitting a funded account is rejected as \`OPERATOR_MANIFEST_DISAGREEMENT\` against the supplied complete source registry.

**Critical assumption:** This detects omission only **relative to the supplied records**. If a malicious indexer erases both a funded user and all underlying authentic source records and forges matching counters, replay alone cannot detect the fraud. Signed consensus finality, verified storage key derivation and trie proofs, authenticity/completeness of actual event history and an independently constrained full holder-count enumeration remain mandatory (#18, #27–#30).

## Input schema

A source snapshot JSON is exactly:

- \`schema_version: "metorah-source-replay-v1"\`;
- \`header\`: the canonical 15-field \`metorah-canonical-v1\` header, including source genesis, exact cutoff block hash/number/state root, WASM source contract/code hash, asset, migration, destination chain/contract, decimals, historical and active holder counts, and total supply;
- \`owner\`: source controller AccountId32; \`max_supply\`: a positive canonical decimal-string uint128;
- \`frozen: true\`; \`freeze_block_number\`: positive canonical decimal-string uint64, equal to the header cutoff number;
- \`unbound_active_holders: 0\`;
- \`slots\`: **exactly** historical-holder-count entries with \`index\` 0..N-1, \`source_account\` AccountId32, \`units\` canonical decimal-string uint128 (zero allowed), \`beneficiary\` H160 or null, and \`binding_nonce\` canonical decimal-string uint64 (zero only if no binding);
- \`events\`: bounded array with a unique, consecutive integer \`event_index\` 0..M-1 and an explicit \`kind\`. Allowed kinds reflect the real ink! event structs \`Issued\`, \`Transferred\`, \`Burned\`, \`BeneficiaryRegistered\`, \`SourceFrozen\`; only their typed, exact event fields are accepted.

Event identities, first-funded order and historical zero-balance entries are replayed and checked. Example fixture construction lives in \`test/test_entitlement_reconciliation.py\` and uses six synthetic holders, three of whom finish with zero balances. The source uses fixed-width **32-byte AccountId**, not truncated EVM addresses; authorized beneficiaries use exact 20-byte H160.

The independent candidate \`--manifest\` file must pass \`canonical.verify_manifest\` and be **exactly equal** to the auditor's reconstructed manifest; the candidate cannot assert \`can_claim=true\`, add hidden fields, alter the destination or omit a holder and still pass.

The audit uses a pure standard-library implementation plus the existing canonical manifest Python module. Its event stream is a **normalized, untrusted event representation**, not independently decoded SCALE or an authentic chain receipt. The integer \`event_index\` is an ingestion sequence check, **not** a cryptographically proven Substrate block/extrinsic/event locator.

## Reproduction

Run with synthetic fixtures or with independently collected evidence after the source runtime is verified:

\`\`\`sh
python -m unittest discover -s test -p test_entitlement_reconciliation.py -v

python tools/reconciliation/check.py \
  --snapshot path/to/untrusted-frozen-snapshot.json \
  --manifest path/to/operator-candidate-manifest.json \
  --output local_model/artifacts/holder-audit.json
\`\`\`

The CLI accepts strict UTF-8 JSON, rejects duplicate keys/non-finite numbers and oversized inputs, performs **zero network or wallet calls**, and atomically writes an offline diagnostic report only after all checks pass. On any failure, it exits nonzero without overwriting or creating a success report. It never upgrades source assurance. Passing output is \`COMPLETE_RELATIVE_TO_SUPPLIED_DATA_UNAUTHENTICATED\` and contains \`can_activate=false\`, \`can_claim=false\`, \`registry_storage_proofs_verified=false\`, and \`complete_event_history_cryptographically_verified=false\`.

## Additional real-chain acceptance evidence still required

1. Independently authenticated V3 finalized genesis/header hash/state root and runtime code identity (#18/#27), with trust-anchor rotation and consensus signatures.
2. Authenticated Contracts pallet and WASM storage key derivation, including the correct nested child trie membership proofs relative to the top-level finalized state root (#28).
3. Full authenticated registry count and **one proof for every historical slot** 0..N-1, with source account, balance and binding proofs, not just a filtered list of positive accounts; prove record deletion/absence according to the exact deployed runtime.
4. Event history from the real deployed contract's genesis to cutoff, authenticated and gap-free across blocks/indices, including actual signed extrinsics, code upgrades and historical deletions. RPC-reported contiguous synthetic indexes cannot establish this.
5. Reconciliation of total supply, caps, minted and burned units, active/unbound counts, tombstones, destination wallet nonces and metadata at **one same finalized checkpoint**.
6. External security review and destination issuance/solvency assurance (#34–#41). **No root activation, claim or asset mint** may be triggered by an E1 offline report alone.

**Exit:** Keep issue #29 open until those authentic-chain proofs have been independently reproduced and audited. Tests alone are not a verified WASM-to-EVM migration.
