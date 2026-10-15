# Issue #39 — claim hardening

The integrated fungible claim path applies effects before the external settlement call, rejects repeated indices, and uses a settlement adapter that separately rejects reused settlement IDs. This change adds independent reentrancy locks to the claim ledger and escrow settlement adapter, caps Merkle proofs at 64 siblings to bound caller-controlled verification work, and provides an administrator-controlled emergency pause for claims. The pause is a single-administrator stopgap; multisig/timelock governance is tracked separately.

The settlement adapter marks a settlement before transferring and relies on EVM transaction atomicity: if the token call fails or its balance deltas do not match exactly, the whole transaction reverts, including the claim ledger's `claimed` flag and `totalClaimed` accounting. The regression test forces a token transfer failure, verifies that no claim or settlement remains recorded, then retries successfully.

## Test coverage

- duplicate claim index rejected;
- wrong beneficiary rejected;
- failed token payout rolls back claim and settlement accounting, then allows retry;
- overlong Merkle proofs rejected before hashing;
- administrator pause blocks claims without consuming the claim index, and unpause restores claim execution;
- Foundry fuzz property checks arbitrary positive allocation amounts up to the cap while verifying claimed/settled equality and backing conservation;
- Foundry stateful invariants assert claims never exceed the authorized allocation, settlement never exceeds funded backing, and ledger totals remain aligned with escrow totals.
- successful retry pays the exact amount and preserves remaining backing.

## Limits

This is targeted adversarial regression coverage plus a bounded Foundry fuzz property, not a formal proof or exhaustive stateful invariant campaign. Only standard exact-transfer ERC-20 behavior is supported; rebasing and callback/non-standard tokens require a separately reviewed adapter. The 64-sibling cap supports trees with up to 2^64 leaves and must remain consistent with the manifest/tree builder. No live Portaldot proof or production audit is implied.
