# Issue #36 — quorum-attested evidence activation

`VerifiedEvidenceLedger` is an isolated E3 implementation of an attested evidence proposal, a mandatory review delay, and activation-gated accounting claims.

## Activation protocol

1. Deploy with a fixed signer allowlist, quorum threshold, nonzero migration/freeze commitments, allocation cap, and nonzero review delay.
2. Independent authorized signers sign the EIP-712 digest binding migration ID, root, manifest hash, freeze-evidence hash, allocation, chain ID, this ledger address, and activation timestamp.
3. Submit signatures in strictly ascending signer-address order. Duplicate, unauthorized, malformed, or insufficient signatures revert.
4. Evidence cannot be replaced after a proposal; activation cannot occur before the committed timestamp.
5. Claims revert until activation and then must prove inclusion in the committed root, with the allocation cap and duplicate-claim checks applied.

## Security boundary — not a production bridge

This component enforces the on-chain quorum and timelock policy, but **does not independently verify Portaldot/Substrate finality or completeness**. Signers must independently inspect authenticated source proofs and the manifest; quorum signatures prove only that the configured keys attested to the bound digest. Key compromise, signer collusion, incorrect signer selection, and dishonest off-chain verification remain trust risks.

It is a separate contract and does not retrofit the legacy `MetorahClaimLedger`. Deployment integration and migration routing must explicitly choose this gated ledger rather than the legacy administrator-root ledger before claims can be considered guarded. Credits remain accounting entries only; no assets are held, minted, transferred, redeemed, or proven solvent.

## Reproducible checks

Run with Foundry 1.3.6:

```sh
forge build
forge test -vvv
```

The tests cover quorum signatures, unauthorized signer rejection, early activation rejection, and claim gating. Do not close issue #36 as fully complete until CI passes and the application/registry cannot route claims through the legacy unverified-root ledger. Live source-chain proof verification and deployment remain separate prerequisites.
