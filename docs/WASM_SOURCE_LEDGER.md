# Metorah WASM source ledger — implementation note (#20)

**Status: development-only. NOT certified Portaldot V3-compatible, not deployed, not audited.** Actual runtime approval and finalized storage evidence remain blocked by #18–#19 and #23–#29.

## What the contract actually does

The ink! 5.1.1 contract in \`contracts/wasm/source-ledger/\` implements the first supported fungible-entitlement *source accounting* class: immutable asset ID, decimals and supply cap; issuer-only minting; holder-authorized transfers and burning; total-supply conservation; persistent historical holder registry; bounded read-only holder pagination; and a one-way owner-authorized freeze that makes mint, transfer and burn return errors. Unit tests exercise privilege bypasses, overflow, zero-value operations, cap breaches, duplicate/zero holders, one-time freeze and reconciliation after multiple operations.

**Deliberate limitations:** The issuer owner remains capable of minting before freeze. Draft PR #103 adds source-caller-restricted destination beneficiary registration, immutable destination chain/contract/migration domains, strict nonces, registration events and a no-unbound-funded-holders freeze guard (#22), but this is NOT yet verified on a trusted chain. It still lacks cryptographic proof of finalized freeze (issue #23), audited chain storage trie verification (#28), independent finality proof, canonical Merkle snapshot (#25), or destination settlement. The on-chain registry is exhaustive *if the implementation is correct and the chain state is authentic*; a \`holder_page\` RPC response by itself proves neither.

### Storage schema for future audited source adapter

- \`balances: Mapping<AccountId,u128>\` keyed by source AccountId32, zero default.
- \`holders: Mapping<u32, AccountId>\` zero-based, dense historical allocation of unique funded holders. Never delete a slot or reuse its index.
- \`slots_plus_one: Mapping<AccountId,u32>\`: source account's index+1; zero means absent.
- \`holder_count\` (historical slots), \`active_holder_count\` (positive balances now), \`total_supply\`.
- \`asset_id:[u8;32]\`, \`decimals:u8\`, immutable positive \`max_supply:u128\`, owner and frozen flag.

A holder whose balance becomes zero remains in the historical registry; source completeness scanning must ignore zero balances *but verify* index history, active holder count and total supply. Mutation writes are preflighted before storage updates so \`Err\` returns cannot silently partially issue or transfer value. The contract intentionally rejects zero-value operations and self-transfers to avoid registry ambiguities. Maximum page size is 64 and read-only view calls must still be externally authenticated at a finalized header.

### Reproduce tests (after chain toolchain #19 is buildable)

\`\`\`sh
cargo test --manifest-path contracts/wasm/source-ledger/Cargo.toml
cargo contract build --release --manifest-path contracts/wasm/source-ledger/Cargo.toml
\`\`\`

Successful off-chain ink! tests only verify code behavior under the ink! test environment. Successful \`cargo contract build\` produces a bundle for **the pinned development compiler**, not a statement that official Portaldot V3 accepts it. Do not download arbitrary node binaries or deploy with actual funds.

## Issue exit requirements still unmet

1. Finish #18 and #19: independently authenticate V3 network identity/finality, confirm contracts runtime/cargo-contract version and compile cleanly from a **committed, reviewed Cargo.lock**.
2. Check the finalized source contract code hash, deployed address and transaction/block hashes from actual supported chain tests; review event ABI and storage keys for independent proof verification.
3. Perform deeper property/adversarial tests and independent review (issues #21–#23 and #71), and only then enable verified snapshot/activation later in the protocol.

**No end-user wallet will be allowed to claim assets from this ledger until the independent provenance, mapping and destination settlement work is completed.**


## Issue #21: Indexed source inventory and reconciliation

See [SOURCE_ENUMERATION.md](SOURCE_ENUMERATION.md) for the indexed registry reader, separate off-chain scanner, tombstone policy, fail-closed reconciliation, and why chain-finalized storage proofs remain required.


## Issue #22: Source-signed destination beneficiary binding

See [DESTINATION_BINDINGS.md](DESTINATION_BINDINGS.md). Holder mappings require their own pre-freeze source transaction; destination H160 is not derivable from AccountId32. The source ledger records each change and refuses to freeze while any funded holder is unbound. Chain-authenticated extrinsic origins and event/storage histories remain future verifier responsibilities.
