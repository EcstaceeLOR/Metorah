# Source-authorized EVM beneficiary registration — Issue #22

**Status:** Development implementation and offline evidence auditor. **No source chain identity/finality, storage proof, V3 deployment or EVM claim authorization has been verified.** Required prior issues #18–#21 remain under review. The independently authenticated migration proof and destination contract gating are separate #23, #25–#29, #36–#39.

## Security goal

The source account is a **32-byte Substrate AccountId**. The EVM beneficiary is **a 20-byte H160**. They are not interchangeable and may not be inferred or converted just by truncating or reinterpreting bytes. The *source account itself* must approve the exact destination before irreversible freeze, and that approval must be anchored to a specific migration and destination contract.

### Immutable destination domain at deployment

The source ledger constructor is now:

\`new(asset_id: [u8;32], decimals: u8, max_supply: u128, destination_chain_id: u64, destination_contract: [u8;20], migration_id: [u8;32])\`.

The EVM chain ID, actual claim/settlement H160 contract, and nonzero migration ID **cannot change** after deployment. Both the source chain genesis and source contract address must be attached by the independently trusted chain verifier; a source-chain extrinsic's signing payload and genesis/finality check are the chain runtime's responsibility, not a user-supplied JSON flag.

`destination_domain()` exposes the exact destination scope. Constructor rejects zero chain/contract/migration. An operator cannot pick a new beneficiary, new chain or migration domain after a holder has signed.

### Authorization and update flow

- A currently positive-balance source holder calls \`register_beneficiary(beneficiary_h160, expected_nonce)\` as a **normal signed source-chain extrinsic**. The contract uses **only** \`env().caller()\` as source account, not a supplied source_owner parameter. This ensures admin, relayer or random claimant cannot register another account inside this ABI.
- The very first registration must pass nonce **1**. Every subsequent pre-freeze modification supplies exactly the previous nonce + 1. Stale/duplicate or skipped update requests are rejected, and nonce wrap is rejected. Empty/zero beneficiary is rejected.
- The contract emits \`BeneficiaryRegistered\` with source owner, **source contract account ID**, immutable destination chain/contract/migration, previous and new H160 recipients, and monotonically increasing nonce. The latest \`binding_of(source_account)\` and \`binding_at(index)\` snapshot exposes final beneficiary and nonce. A trusted verification pipeline must validate the actual finalized event sequence and state.
- Registry-wide \`unbound_active_holders\` counts all positive-balance accounts without a mapping. Mint, transfers, burns, first registrations and zero-balance reactivation maintain this counter via checked arithmetic. A zero-balance tombstone needs no beneficiary unless it becomes funded again.
- \`freeze()\` is **blocked** if even one positive entitlement lacks a binding. This avoids silently confiscating balances on a migration cutoff. After freeze, no holder can change or register a destination. There is **no administrator override** to redirect unbound balances.

### Lost keys, disputes, and support

If a holder loses *only the destination wallet* but still controls their source wallet, they can register a different H160 address before freeze with the next nonce. If the source key is lost, the admin **cannot authorize a substitute wallet**: the source migration must remain blocked/enter dispute and follow an audited external recovery policy or formally abandon the unsafe cutover. Post-freeze reassignment is not available. Genuine case handling, source authorized recovery, customer communication and cutoff rules are tracked by #23, #32, #60, #82.

### What is verified today vs still missing

- **Implemented in ink! code:** source-caller-restricted mapping, domain immutability, monotonic nonce, event history, final mapping view, no freeze with unbound funded accounts, post-freeze mutation prohibition.
- **Locally tested:** source-caller simulation via ink! test environment, replay/nonce protections, mapping visibility, accountant counter conservation under mint/transfer/burn, rejection of zero recipients, tests spanning many holders.
- **Not yet verified:** normal signed extrinsics on actual Portaldot V3, an independently authenticated source header and storage proof, proof of exactly all prior registration events from deployment to cutoff, final beneficiary inclusion in the canonical Merkle tree, destination claim enforcement for that beneficiary, or withdrawal/asset settlement.

The read-only \`tools/bindings/inspect.py\` checks each positive inventory entry against final \`binding_at\` and \`binding_of\` getters and sequential event data under a pinned block, including migration-domain and nonce continuity, but **the entire reader and event stream are still untrusted**. Success always returns \`BINDINGS_RECONCILED_UNAUTHENTICATED\`, \`source_chain_authenticated=false\`, \`can_activate=false\` and \`can_claim=false\`.

### Development testing

\`\`\`sh
cargo test --manifest-path contracts/wasm/source-ledger/Cargo.toml --locked
cargo check --manifest-path contracts/wasm/source-ledger/Cargo.toml --locked
python -m unittest discover -s test -p test_bindings.py -v
\`\`\`

The supplied offline test data is synthetic. A real runtime adapter must pin every call to an authentically finalized block and independently verify the source contract's code and storage state; an indexer cannot self-certify beneficiary authority. Do not send real tokens to this contract.
