# Source WASM deployment fixture and integration harness — Issue #24

**Engineering state: deterministic local fixture implementation, not an approved Portaldot V3 fresh-node deployment.** This work is stacked on draft PR #104 and depends on open issues #18–#23.

## Included executable scenarios

The real ink! source-ledger contract contains dedicated `fixture_` tests:

1. Create six distinct AccountId32 source holders (not fewer than five), fund them with known allocations, register six distinct destination H160 beneficiaries via each wallet's simulated source caller, and confirm complete holder indexing and supply accounting.
2. Exercise a holder-signed transfer and burn; replace a destination beneficiary before freeze; reject replayed nonce, zero beneficiary and another account's unauthorized update.
3. Enumerate all six historical slots and independently sum balances; freeze only when every positive holder is bound; check frozen marker and accounting at cutoff.
4. Attempt transfer, burn and registration as **every holder** after freeze, plus issuer mint/repeated freeze; confirm full state and balances remain unchanged.
5. Reject freeze with a missing funded-holder binding; check zero-balance holder cannot redirect another holder.

A synthetic test environment is not a network transaction. The fixtures may use mocked `env().caller()` and runtime block height, but **must never be included in a mainnet/testnet transaction evidence bundle.** No synthetic addresses or block hashes are presented as genuine RPC results.

## Reproduce local tests and safe evidence

Run from a clean clone with verified pinned Rust 1.90.0, ink! 5.1.1 and checked-in Cargo.lock:

```sh
python tools/fixtures/run_local.py --output local_model/artifacts/source-fixture-local.json
python -m unittest discover -s test -p test_source_fixture_runner.py -v

# Optional full Rust and WASM checks with vetted compiler:
cargo test --manifest-path contracts/wasm/source-ledger/Cargo.toml --locked
cargo contract build --release --manifest-path contracts/wasm/source-ledger/Cargo.toml
```

The Python runner executes actual `cargo test --locked ... fixture_` and `cargo check --locked` as child processes with fixed command arrays; it does **not** silently run an RPC or sign any transaction. The structured output includes command argv, actual exit codes, bounded test logs and source/dependency fingerprints. It sets all on-chain identity, receipts, finality, storage proofs, deployment and activation flags **false**.

GitHub Actions runs the harness after the ink! source ledger unit tests. The report is a local reproducibility artifact only, **not a release approval**.

## Mandatory future fresh-node integration (NOT accomplished)

A genuine testnet-local fresh-node fixture requires the official Portaldot V3 WASM contracts environment and verified binary/build provenance (#18), runtime-compatible deployable WASM+metadata/ink! pallet semantics (#19), real signed test-asset transactions (#20–#23) and valid finalized state verification (#27–#29). Then implement and document a secure opt-in driver that:

- Starts a vetted ephemeral node with isolated genesis and faucet accounts, never production secrets; records compiler, genesis and chain spec;
- Compiles and actually deploys the source contract, funds at least five holders, has each holder sign pre-freeze registration and transfer/burn calls, executes freeze and rejected post-freeze mutations;
- Records **real** contract address/code hash, inclusion transaction hashes, block headers/state root, explorer/RPC receipts and independent finalized storage evidence, in a versioned manifest with no fabricated values;
- Cleans up the ephemeral environment and refuses live-network signing/funding unless the operator explicitly selects an approved test-only environment and sees the safety warnings.

No official V3 RPC/genesis/runtime trust anchors or compatible safe dev-node binaries have been independently validated yet, so this branch does not pretend to provide a live deployment fixture or declare #24 complete. The test-only runner cannot activate or claim any migrated assets.
