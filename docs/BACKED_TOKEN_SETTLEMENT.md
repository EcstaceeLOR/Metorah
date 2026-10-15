# Issue #38 — backed token settlement adapter

`BackedTokenSettlement` is an isolated escrow adapter for a single supported ERC-20 asset and migration allocation. It accepts funding only from the configured funder, caps funding at the allocation, and allows only the configured settlement controller to release funds. Each claim ID can settle once. Funding and payouts enforce exact balance deltas and reject fee-on-transfer behavior; rebasing tokens are unsupported and should not be configured.

## Critical integration boundary

This adapter does not authenticate claims, verify source evidence, or enforce beneficiary bindings by itself. The controller must be a trusted, integrated claim ledger that checks activation, verified entitlement, and source-authorized beneficiary binding before calling `settle`. Do not use an EOA as controller in production. There is no arbitrary withdrawal path; accidental funding, token upgradeability, token blacklisting, and compromised controller keys remain asset-specific risks.

Run `forge build` and `forge test -vvv` with the repository's pinned toolchain. Issue #38 remains open until the adapter is integrated with the verified claim flow and tests demonstrate real test-token transfers, allocation conservation, fee-token rejection, and backing at all times.