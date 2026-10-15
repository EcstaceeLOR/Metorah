# E3 accounting, receipts, and solvency snapshot

## On-chain source of truth

The claim ledger and settlement adapter expose accounting without depending on a backend:

- `VerifiedTokenClaimLedger.migrationStatus()`: migration/freeze/root/manifest state, allocation, claim totals, activation and pause state, funded and settled totals, actual escrow token balance, funded liability, unfunded authorization, and available backing.
- `VerifiedTokenClaimLedger.claimReceipts(index)`: source account, beneficiary, amount, deterministic claim ID, and settlement timestamp for a successful claim.
- `BackedTokenSettlement.accountingSnapshot()`: authorized allocation cap, cumulative deposits, cumulative payouts, live ERC-20 balance, remaining authorization, funded liability, unfunded authorization, available backing, and surplus token balance.
- Direct getters `remainingAuthorizedAllocation()`, `remainingFundedLiability()`, `unfundedAuthorizedAllocation()`, and `escrowTokenBalance()` support lightweight clients.

## Definitions

- **Authorized allocation**: immutable cap configured for this migration. It is not money deposited.
- **Total funded**: cumulative amount successfully transferred into escrow, verified by exact balance delta.
- **Total settled**: cumulative amount paid to beneficiaries after exact sender/recipient balance-delta checks.
- **Remaining funded liability**: `totalFunded - totalSettled`; funded amounts not yet paid.
- **Unfunded authorized allocation**: `allocationCap - totalFunded`; authorized capacity not yet deposited.
- **Available backing**: the lesser of actual escrow balance and remaining funded liability.
- **Surplus token balance**: actual escrow balance above remaining funded liability; donations or unusual token behavior must not be counted as authorized deposits.

All values are in the token's smallest units. The adapter rejects fee-on-transfer behavior and does not support rebasing tokens.

## Events and reconciliation

- `Funded(funder, amount, totalFunded)` and `SettlementAccountingUpdated(...)` describe each successful deposit and its post-state.
- `Settled(claimId, beneficiary, amount, totalSettled)` and `SettlementAccountingUpdated(...)` describe each successful payout and its post-state.
- `TokenClaimSettled(index, sourceAccountId, beneficiary, amount, claimId)` and `ClaimReceiptRecorded(...)` provide the user-facing receipt and cumulative totals. Failed claims revert all writes and emit no successful receipt events.

An indexer should key settlements by `claimId`, claims by `(ledger address, index)`, replay logs in block/log order, and compare reconstructed totals against the public storage getters and snapshots. Store chain ID, contract address, block number, block hash, and transaction/log index; handle reorgs by removing logs from orphaned blocks and replaying canonical history. The contract snapshot remains available if the indexer or API is down.

## Assurance boundary

The tests validate local accounting transitions, claim receipt storage, and consistency between status snapshots and contract storage. They do not demonstrate that a deployed production indexer has been run against live chain logs, nor do they establish Portaldot finality or production deployment. A real dashboard must label the chain, contract address, block freshness, token, and whether values are from live chain or a local fixture.
