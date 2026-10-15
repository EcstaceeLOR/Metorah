# Migration governance, incident controls, and recovery policy

## Roles

The optional `MigrationGovernance` controller separates duties for one migration ledger:

- **DEFAULT_ADMIN_ROLE**: grants/revokes roles and controls the governance configuration. In production this should be a multisig, not a single hot key.
- **PROPOSER_ROLE**: schedules ledger-admin calldata for delayed execution.
- **EXECUTOR_ROLE**: executes a scheduled action only after the configured minimum delay.
- **GUARDIAN_ROLE**: can pause claims immediately and cancel queued actions, but cannot unpause or rewrite an activated root without the timelock.

The governance contract must be explicitly installed as the ledger administrator using the ledger's two-step handover: current admin nominates it, then the governance admin calls `acceptLedgerAdministrator()`. Before handover, the original administrator still controls the ledger. Role changes should be managed by a multisig and logged/reviewed under the operational policy.

## Timelocked actions and evidence correction

All normal ledger-admin calls should be encoded and scheduled through `MigrationGovernance.schedule(salt, data)`, then executed through `execute(salt, data)` after `minDelay`. Guardians/admins can cancel queued actions. The contract emits schedule, cancellation, execution, role-change, and emergency-pause events.

Evidence may be cancelled only while proposed and before activation. Cancellation clears the root, manifest, and activation time, and the next proposal must again pass quorum attestation and the review delay. Once activated, evidence cannot be cancelled or replaced; the holder entitlement encoded by that root is immutable for this ledger.

## Emergency pause and surplus recovery

A guardian can stop claim execution immediately. Resumption is an ordinary ledger-admin action and therefore must be timelocked when governance is installed. Pause does not alter claim balances or transfer tokens.

Recovery is restricted to unsolicited escrow token surplus above the full remaining funded liability. The adapter checks the live escrow balance against `totalFunded - totalSettled` and verifies exact sender/recipient balance deltas. It cannot withdraw funded holder liability; failed or excessive recovery reverts. Fee-on-transfer and rebasing tokens remain unsupported.

## Upgrade policy

The E3 contracts are deployed as non-proxy contracts with immutable migration parameters. Do not upgrade bytecode in place or claim that a proxy upgrade is available. If a critical defect requires a new implementation, create a new migration/ledger with a new deployment address and explicit migration identifier, publish source and deployment hashes, pause the affected old ledger if appropriate, and obtain a documented governance/security sign-off. Existing activated claims and liabilities must not be silently rewritten or redirected.

## Incident runbook

1. Guardian pauses claims and records the transaction, block hash, alert, and suspected impact.
2. Operators compare the on-chain root/manifest, funding snapshot, claim receipts, and token balance; do not trust the dashboard alone.
3. Security reviewers determine whether the incident concerns evidence, signer compromise, token behavior, or infrastructure.
4. Any root cancellation, recovery, role change, or unpause is reviewed and queued through the timelock; guardians may cancel unsafe queued actions.
5. Resume only after a documented decision and revalidation of backing and entitlement state.

## Assurance boundary

Foundry tests cover role separation, delayed execution, preactivation cancellation, emergency pause, and recovery limits. These tests are local fixtures. They do not establish an audited deployment, production multisig configuration, or live Portaldot finality. Production launch requires independent contract review and a real multisig/timelock operational drill.
