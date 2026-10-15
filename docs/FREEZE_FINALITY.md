# Irreversible source freeze and finalized cutoff evidence — Issue #23

**Status: local freeze marker + event and untrusted read-only cutoff observation implemented. NOT verified Portaldot V3 finality or storage proofs. NO activation or real funds.**

## Required security property

Destination claims must remain impossible until an independently authenticated finalized checkpoint shows the actual source rights are retired, source holder inventory and beneficiary mappings are complete, and source state cannot be mutated by the contract or privileged runtime actions. An event and RPC's self-declared "finalized" head are insufficient.

## Source WASM changes

The ink! contract in contracts/wasm/source-ledger/lib.rs stores a one-time freeze_block: Option<BlockNumber>. A successful authorized freeze records the source runtime's observed block number, emits SourceFrozen and locks balance and beneficiary mutations. The event includes the source contract AccountId32, acting owner, asset and migration IDs, destination EVM chain/contract, total supply, holder counts and zero unbound-funded-holder count.

freeze_marker() returns (observed_block_number, total_supply, historical_holder_count, active_holder_count, unbound_active_holder_count) only after a successful freeze. A failed freeze never sets the marker or emits SourceFrozen. Repeated freeze, minting, transfers, burning and destination registration are rejected once frozen; no unfreeze exists in the message ABI.

**An observed runtime block number is NOT a finalized block hash, consensus signature or proof of source storage membership.** A privileged runtime upgrade or chain-level state rewrite is beyond the contract's local enforcement.

## Freeze evidence observer

tools/freeze/observe.py accepts a caller-pinned genesis hash, source contract AccountId32, source code hash, freeze transaction hash and freeze block hash. It checks an untrusted read-only provider's receipt, owner, event, exact block/header and state root, reported finalized-head height, canonical block identity, contract code identity, frozen snapshot, cutoff marker, unbound funded-holder count, destination domain and second-read consistency.

The observer rejects wrong chain/contract, failed or mismatched receipt, missing/duplicated freeze event, incorrect signer, mismatched asset/migration/domain, nonfinal cutoff height, orphaned/reorged source block, inconsistent supply/counters and changed state during the scan. Every contract-state getter must use the same pinned cutoff block hash.

A self-consistent malicious RPC can still lie about all of these. Therefore the only successful output is **FREEZE_OBSERVED_UNAUTHENTICATED** with chain-genesis authenticity, cryptographic finality, finalized ancestry, trie membership, signed extrinsic authentication, irreversible runtime freeze and activation all explicitly FALSE.

In particular, checking that an RPC's finalized head number exceeds the freeze height does NOT prove the freeze block is a verified ancestor of that head, nor that the header hash matches signed finality or the returned storage root. This needs a trusted genesis, verified consensus/finality proof, header encoding and independent state trie verifier (#18, #27–#29).

## Real cutover procedure — required future work

1. Independently authenticate Portaldot V3 genesis, supported contract runtime, source account and deployed code hash.
2. Reconcile all funded holders and source-authorized destination bindings at the same authenticated state, and ensure zero unbound active rights.
3. Submit freeze with an authorized actual source transaction. Record the real transaction hash, inclusion block, dispatch result and fully decoded source event.
4. Cryptographically validate finalized headers and ancestry, exact storage root, freeze marker, contract code and all relevant source mappings against trusted state-trie proofs.
5. In a safe test-asset environment, confirm post-freeze mint/transfer/burn/beneficiary writes cannot mutate state. Review privileged upgrade and governance bypasses independently.
6. Only then may an independent verifier assess a canonical migration snapshot and destination solvency. Any mismatch, nonfinality or reorg is a **NO-GO / DISPUTED** event, not a root-approval exception.

Source freeze that succeeded but destination migration did not complete must leave activation paused; it is not a license to unfreeze or reimburse from an admin script. Once final destination settlements occur, application rollback cannot reverse on-chain transfers.

## Reproducibility

Run these commands at repository root:

    cargo test --manifest-path contracts/wasm/source-ledger/Cargo.toml --locked
    cargo check --manifest-path contracts/wasm/source-ledger/Cargo.toml --locked
    python -m unittest discover -s test -p test_freeze_evidence.py -v

The supplied evidence-reader fixtures and block identifiers are **synthetic**. Do not store them as real source transaction proofs. Issue #23 remains OPEN until real network receipts and independently authenticated finality/storage evidence can be saved and reviewed.
