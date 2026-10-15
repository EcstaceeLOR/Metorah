# Destination ledger safety baseline — Issue #34

The inherited `MetorahClaimLedger.sol` records **accounting credits only**. It does not transfer, custody, redeem, mint or back any actual asset. Solidity 0.8.24 performs checked integer arithmetic, and an overflow reverts. A successful Merkle inclusion proves only that the leaf matches the administrator's committed root, **not** that the root reflects an authenticated Portaldot finalized state.

## Reproducible validation

```sh
forge --version
forge build
forge test -vvv
```

CI uses pinned `foundry-rs/foundry-toolchain@v1` version `v1.3.6` and runs both commands in the `solidity` job. Inspect the linked successful GitHub Actions run and commit SHA before claiming this execution passed.

`test/MetorahClaimLedger.t.sol` covers normal claims, root commitment authorization, invalid proofs, immutable root, duplicate claims and two-leaf reconciliation. `test/MetorahClaimLedgerAdversarial.t.sol` adds malicious administrator source root (demonstrating the trust defect), cap overflow with valid leaves, zero allocation, incorrect indices, account/amount tampering, cross-chain and cross-migration replay, arithmetic boundary, double claims and no real ETH transfers.

## Risks blocking all fund-bearing use

1. **Privileged fabricated root:** an administrator can commit an arbitrary opaque Merkle root without verifying chain headers, source storage, complete holders, authorized source-to-destination bindings or the freeze evidence hash. There is no independent evidence-root verification and no on-chain fraud challenge window. Track the root/activation controls in #36 and authenticated source pipeline #18/#27–#33.
2. **No backing or settlement:** credits are inert mapping entries. There is no escrow solvency proof, token transfer, redemption, asset adapter, or economically meaningful claim. Track separately in E3 settlement work and security audit gates.
3. **No operational freeze or clawback:** after the one-time root commit, claims cannot be paused, refunded or reversed by this contract. A malicious root may permanently allocate ledger credits, even if no funds leave.
4. **Privacy and availability:** public leaf values with account IDs and beneficiaries may correlate wallets; publish only privacy-reviewed evidence and avoid storing raw identity registries in public reports.
5. **Replay domain:** the hash includes chain ID, contract address and migration ID, but correctness relies on deployment chain semantics; forks with reused chain ID and identical address remain a separate operational review risk.
6. **Gas griefing:** user-supplied Merkle proofs are not length-bounded. Extremely large proofs can be expensive; EVM gas limits still apply but no application-level limit is enforced.

## Boundaries

These tests provide an **E1 Foundry/CI ledger baseline only**. They do not prove live V3 deployment, Substrate finality, source entitlement completeness, cryptographic wallet mapping, app-level activation controls, funded EVM settlement, or production readiness. Do not deploy this standalone contract for customer assets.

Production migration enablement stays **NO-GO** until all source proof, identity, authorization, settlement, monitoring and audit dependencies are proven. Issue #34 can close on verified Foundry acceptance as an *accounting-only baseline*, not as approval for customer funds.
