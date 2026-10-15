# Source enumeration and reconciliation — Issue #21

**Status: implementation under CI review, not an authenticated Portaldot migration.** This first-stage registry and scanner are real implementation work, but source identity, finality proofs and deployment remain blocked by #18–#20 and #27–#29.

## Contract-side inventory interface

The ink! source ledger in contracts/wasm/source-ledger/lib.rs provides:

- registry_snapshot(): seven fields (frozen, asset_id, decimals, max_supply, total_supply, holder_count, active_holder_count) in one read.
- holder_page_indexed(start, limit): indexed AccountId32/u128 rows, no more than 64 slots per call. Zero balances are included rather than filtered, making skipped indices visible.
- holder_at(index), index_of(account), balance_of(account): read-only cross-checks against an indexed page.
- holder_count is the dense historical set of every account ever funded. A zero balance retains its tombstone index, and reactivation does not add a second holder. active_holder_count is the number of currently positive balances.

The source freezes mint/transfer/burn in its ABI after the authorized freeze, but chain-level upgrades and code authenticity require separate verification.

## Independent scanning and reconciliation

tools/enumeration/scan.py implements a strict scanner through a pluggable PinnedLedgerReader. All interface calls take the **same exact block hash**, which a real RPC adapter must enforce at the source runtime layer.

The reader must implement:
- registry_snapshot(at_block) returning the seven named fields.
- holder_page_indexed(start, limit, at_block) returning (index, AccountId32 as 0x-prefixed 64 hex, unsigned balance) for each historical slot.
- holder_at(index, at_block), index_of(account, at_block), balance_of(account, at_block).

The reader must transform ink! SCALE values faithfully; this repo does not pretend a mocked RPC is a live chain. Neither providing a block hash nor reading contract getters authenticates that block.

Scan stages:

1. Require a frozen source and strict valid metadata, page size and bounded source population.
2. Enumerate **every historical index** exactly once in batches of 1–64. Any missing, duplicate, reordered, malformed or extra record fails closed.
3. Independently compare each page row with direct holder_at, index_of and balance_of reads at the same pinned block. Reject mismatches and u128 overflows.
4. Retain zero-balance tombstones for coverage checks but exclude them from positive entitlement candidates.
5. Recompute the exact sum and positive-holder count and compare with the reported source supply and active count; re-read the same registry summary to detect drift.
6. Emit deterministic diagnostic SHA-256 of the candidate inventory. **It is not the canonical cross-VM Merkle commitment, storage proof or authenticated state root.** Proof encoding is specified separately in #25–#26.

Amounts in the resulting JSON are decimal strings to avoid JavaScript number rounding. The scan retains historical source indices; it does not yet assign destination beneficiaries or authorize payments.

## Critical trust boundary

This scanner checks **internal consistency of data returned by the selected source reader**. An RPC or indexer that forges the claimed holder count, balances, total supply and all individual getter results consistently could still omit a rightful user.

Only trusted finalized chain metadata together with independently verified storage proof paths covering the entire on-chain enumerable registry can elevate this to chain-authenticated completeness. That remains #23 and #27–#29. For this reason, even successful scans always report:

- status: RECONCILED_UNAUTHENTICATED
- source_chain_authenticated: false
- holder_set_cryptographically_complete: false
- freeze_finality_verified: false
- destination_bindings_verified: false
- can_activate: false and can_claim: false

Do not let operator-provided flags override this assessment. **Customer migration is still NO-GO.**

## Reproducible validation

Execute from the repository root:

    python -m unittest discover -s test -p test_enumeration.py -v
    cargo test --manifest-path contracts/wasm/source-ledger/Cargo.toml --locked
    cargo check --manifest-path contracts/wasm/source-ledger/Cargo.toml --locked

The Python adversarial suite checks thousands of historical holders and zero-balance tombstones, while the ink! integration-style test exercises 130 actual contract balances crossing the 64-record pagination boundary. These prove local behavior only.

Future work must implement the real chain RPC adapter and independently verifiable header/storage proof bundle, as well as beneficiary mapping and destination settlement (#22–#29, #36–#39).
