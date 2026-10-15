# Issue #37 — source-authorized beneficiary bindings

`SourceAuthorizedBindings` stores a one-time source-account-to-beneficiary binding for a single migration. A quorum of allowlisted attesters signs an EIP-712 digest scoped to migration ID, source account ID, beneficiary, destination chain, registry contract and expiry. Duplicate bindings, expired signatures, unauthorized signers and non-canonical signer ordering are rejected.

## Security boundary

This is an authorization registry component, not a complete claim-path integration. The attesters must independently verify frozen source registration or an approved source-signature proof; the registry does not independently verify Substrate finality. The claim ledger/application must call `verifyBinding` before any claim can be considered source-authorized. Existing legacy claim paths must be disabled or gated before production use. Smart-contract wallets and alternative source-account signature schemes require an explicit policy and implementation.

Run `forge build` and `forge test -vvv` with the repository's pinned Foundry toolchain. Issue #37 must remain open until this registry is wired into the claim path and end-to-end tests prove a beneficiary cannot be substituted or front-run.