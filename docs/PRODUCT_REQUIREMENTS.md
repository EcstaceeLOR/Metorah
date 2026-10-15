# Metorah — Product Requirements Document (PRD)

**Version:** 0.1, product specification — 2026-10-15  
**Status:** proposed requirements, NOT shipped functionality.  
**Product:** Metorah — *Migrate Contracts. Preserve Everything.*  
**First supported use case:** cooperative, enumerable, freezeable **fungible entitlement ledger** on a validated WASM source environment, settling a verified allocation into a backed/authorized EVM fungible destination contract. This is a target architecture, not a claim that Portaldot V3 is already verified.

## 1. Problem and positioning

Application teams cannot easily migrate contract-managed entitlements without custom off-chain scripts, trusted opaque snapshots, complex wallet mapping, accounting errors and dangerous cutover windows. Users need evidence that they remain entitled to the correct assets and cannot be cheated by arbitrary administrator edits or accidental omissions.

Metorah is intended to be **migration infrastructure with independently reviewable evidence and explicit trust assumptions**. It is not a generic bridge and does not guarantee all arbitrary blockchain state can be migrated. A Merkle inclusion proof proves inclusion in a committed root, **not** that the root matches a genuine and complete source ledger. Our strongest mode therefore requires independent finalized-source verification and a completeness check; any governed attestation alternative must be marked as lower assurance throughout the product.

### Initial customer hypothesis, not verified market demand

- **Ideal first buyer:** a token-based application's engineering lead / protocol operations team preparing an approved contract upgrade, who controls an enumerable source ledger and can perform an authorized irreversible freeze.
- **Trigger:** a confirmed need to migrate balances to a newer contract or supported WASM→EVM execution environment.
- **Economic buyer / decision makers:** protocol leadership, technical lead, security lead and treasury/governance signatories.
- **First sellable result:** a documented migration report, verified completeness, audited claim contract and claimant support path with evidence suitable for independent review.
- **Validation requirement:** conduct actual discovery interviews before treating the hypothesis, pricing or customer appetite as established (issue #85).

## 2. User roles and jobs to be done

| Role | Jobs and success definition | Sensitive authority |
|---|---|---|
| Protocol owner / migration operator | Check eligibility, model fees, configure migration, coordinate freeze and review immutable final evidence | Draft and operate; never silently bypass verifier/approval |
| Developer / integrator | Integrate the supported source adapter, inspect contract ABI and chain capabilities, automate reproducible migration tasks | Scoped API/SDK credentials; no custodial signing by default |
| Security reviewer / approver | Independently check chain finality, holder completeness, wallet bindings, allocation, funding and activation prerequisites | Approve/challenge according to configured, recorded governance |
| Wallet holder / claimant | Confirm authentic migration, inspect accurate entitlement, authorize beneficiary, claim funds safely and obtain verifiable receipt | Source signs beneficiary before cutoff; destination wallet signs claim |
| Platform support / operator | Investigate eligibility issues, slow finality, wrong network, stuck transactions or disputes without changing immutable claims | Read-only by default; emergency privileges with audit + separation |

All roles require organization isolation, auditability and least privilege. High-value signers should be controlled by external wallet hardware, multisig or reviewed KMS rather than application servers.

## 3. Initial scope and compatibility gates

**Required first capability (no silent fallback):** source contract supports (a) enumeration of the complete eligible holder set, (b) verifiable per-holder balances and total supply, (c) source-authenticated registration of the destination wallet for each migrated entitlement, (d) irreversible freeze that blocks all value mutations, and (e) a finalized block/storage verification path supported by an approved chain runtime. Destination must demonstrably distribute a solvent, authorized asset representation, not bookkeeping credits.

**Deferred until explicit adapter certification:** NFTs/ERC721/1155, governance votes and delegation, contract roles/allowances, vesting/staking/yield, rebasing and fee-on-transfer tokens, privacy-preserving private balances, unenumerable mappings, arbitrary legacy storage or unauthorizable immutable contracts. These must display an *unsupported* explanation rather than a misleading green success state. See #13, #62 and #42.

**Non-goals for first commercial pilot:** atomic arbitrary-chain bridging, reversing already-settled irreversible transfers, recovering lost source private keys, magically restoring unprovable balances, custody of unrestricted customer funds, promising trustlessness when the root is administrator-attested, or automatically upgrading third-party immutable contracts.

## 4. Canonical end-to-end operator workflow (planned)

1. **Onboard an organization.** Authenticate by verified wallet challenge; assign separate operator, reviewer and approver roles. Do not infer economic ownership solely from a web login.
2. **Create migration draft.** Choose approved source and destination networks, source contract, asset semantics, data disclosure and governing actors. Store a versioned draft.
3. **Run automated preflight.** Probe actual chain genesis, runtime/toolchain, source metadata, enumeration/freeze support, current supply and costs. Fail closed on unsupported source. Never substitute a generic EVM/Dev node for an unverified Portaldot V3 environment.
4. **Configure destination bindings.** Source holders register and can update their own EVM beneficiary while permitted; include chain ID, destination contract and migration domain. Cutoff is explicit. No account is silently redirected by an indexer.
5. **Preview and approve cutover.** Present required authorizations, expected downtime, source retirement semantics, holder participation, fees and user notifications. The irreversible freeze requires governance authorization and explicit confirmation.
6. **Freeze and finalize.** Execute a real source transaction. Wait for chain-specific finalized evidence. From this checkpoint, no value mutation on source is permitted.
7. **Verify and reconstruct.** Fetch storage proofs pinned to a single finalized root; enumerate every eligible entitlement; independently reconcile counts/total; generate immutable manifest and proof bundle. Inability to prove a full set is an activation blocker.
8. **Independent security review and challenge.** Allow reviewers to reproduce the report and challenge omission or invalid mapping before a root can activate. Define the finality/attestation class prominently.
9. **Fund and activate destination.** Verify settlement asset support, authorization/escrow sufficiency, commitment, backing, governance policy and destination chain. Activation binds exact immutable migration parameters.
10. **Enable holders to claim.** Display on-chain eligibility; reconstruct proof; confirm wallet/asset/recipient and gas; submit claimant-signed transaction; show success only after the required chain confirmation and event reconciliation.
11. **Reconcile and close.** Publicly expose allocation/claim totals, liabilities, residual/unclaimed policies and verified receipts. Allow users/support to inspect disputes without confiscation or secret entitlement rewrites.

## 5. Lifecycle and invariants

**States (proposed):** DRAFT → PREFLIGHT_OK → PREPARED → FROZEN_PENDING_FINALITY → FROZEN_FINAL → VERIFIED → REVIEW → ACTIVATION_READY → ACTIVE → CLAIMING → COMPLETED. Orthogonal `PAUSED`, `DISPUTED`, `CANCELLED` and `FAILED` branches need guard conditions; cancellation/rollback may be impossible after settlement. Detailed state machine belongs to #15.

- **Safety:** no activation without verified source checkpoint, complete enumeration, approved destination mappings, accepted commitment and actual asset backing.
- **Conservation:** total successfully settled claims must never exceed the independently verified allocated source amount or backing; decimal conversions/fees have explicit deterministic accounting rules.
- **Once-only:** no entitlement index can settle twice, even on replay, concurrent submission or reentrant execution.
- **Authenticity:** every accepted source record is proven at one finalized root; a set of valid individual proofs alone cannot establish completeness.
- **Authority:** source wallet chooses beneficiary before frozen cutoff; an operator may not change it after freeze.
- **Domain separation:** proofs and approvals include version, source genesis/contract, destination chain/contract, migration ID, entitlement type, index, original owner, beneficiary and amount.
- **Evidence:** every irreversible transition has a transaction ID/block/root and a reproducible signed report; no simulated identifier is presented as chain evidence.

## 6. Prioritized functional requirements

| ID | Priority | Requirement and acceptance gate | Implementation tracking |
|---|---|---|---|
| FR-01 | P0 | Preflight returns verified chain/genesis and explicit supported/not-supported result | #18, #13, #55 |
| FR-02 | P0 | Holder set and total independently reconcile to frozen finalized source | #20, #21, #27–#29 |
| FR-03 | P0 | Holder-authorized destination mapping cannot be reassigned by migration admin | #22, #37 |
| FR-04 | P0 | Canonical manifest and multiple independent implementations produce identical roots/proofs | #25, #26 |
| FR-05 | P0 | No activation on unverified/contested root or unfunded settlement path | #31, #32, #36, #38 |
| FR-06 | P0 | Holder receives actual supported settlement asset; duplicate/replay attack rejected | #38, #39, #58 |
| FR-07 | P0 | Operator and reviewer permissions segregated; high-risk actions have review trail | #45, #49, #79 |
| FR-08 | P0 | Real migration data survives worker restart; no duplicate jobs/actions | #43, #46 |
| FR-09 | P0 | Public UI never claims verified eligibility without actual valid evidence | #56–#58 |
| FR-10 | P1 | Evidence/transaction receipts independently verifiable and exportable | #31, #47, #59 |
| FR-11 | P1 | Disputes and emergency pause follow documented immutable limits | #32, #41, #60, #82 |
| FR-12 | P1 | Audited SDK and docs let compatible teams self-integrate | #62–#68 |

## 7. Operator and claimant failure policy

| Case | Required safe behavior |
|---|---|
| Wrong source chain, source contract, unsupported asset, unenumerable holder mapping | Stop preflight; explain exact unsupported assumption; do not allow a fraudulent "verified" root |
| RPC outage, stale/unfinalized block, conflicting genesis/storage proof | Pause acquisition/retry without mixing blocks; block activation; preserve audit history |
| Omitted/duplicate holder, bad supply reconciliation, tampered beneficiary | Independent verification fails with explainable evidence; freeze/activation cannot advance |
| Destination wallet does not match authorized mapping | Block claim; user receives account-specific explanation; cannot override source signed cutoff silently |
| Insufficient settlement collateral/mint authority | Stop activation or claim before consuming entitlement; report remediation route |
| Double claim, front-running, copied proof, wrong chain, malformed signature | Reject without changing settled state; show non-sensitive error; preserve ability to claim correctly |
| Transaction dropped/reverted, user rejects signature, not enough gas | No success notification; maintain claimability; provide retry guidance, transaction search and support |
| Wrong commitment found before activation | Trigger dispute/review hold; invalidate or replace under defined preactivation governance only |
| Security event after irreversible claims | Pause prospective claims when lawful/possible, disclose irreversibility, preserve evidence and escalation; no invented rollback |
| Lost source/destination keys | Explain policy and recovery limitations; no admin backdoor that can seize another user’s entitlement |

The detailed testable user-journey matrix is in [USER_JOURNEYS.md](./USER_JOURNEYS.md).

## 8. Non-functional requirements and release targets

**Targets below are proposed, not achieved measurements.** Initial engineering checks must measure and revise them before a production SLA is offered.

| Priority | Category | Requirement / target |
|---|---|---|
| P0 | Security | In-scope critical/high findings resolved or formally blocked before real-value launch; independent review required for asset-bearing path (#74) |
| P0 | Correctness | 100% known golden vector compatibility, deterministic manifests and hard failure on incomplete or unverified snapshots; randomized security invariants (#26, #69–#73) |
| P0 | Observability | Every high-risk transition has actor, time, chain/root/transaction proof, versioned immutable audit event and operator-review record |
| P0 | Data integrity | Durable transactional DB + content-addressed evidence; crash recovery restores exact migration state and never duplicates claims (#43–#47) |
| P0 | Usability | User sees chain, destination, asset, entitlement, estimated fees and irreversible consequences before signing; no mock-success states |
| P1 | Availability | Staging goal 99.5% API availability; candidate production SLO ≥99.9% only after 30-day evidence and an incident process (#80) |
| P1 | Performance | Proposed normal UI interaction p95 <2s excluding RPC/chain finality; migration worker performance and actual claim gas must be benchmarked at 1k/10k+ holders (#75) |
| P1 | Recovery | Proposed RPO ≤15 minutes and RTO ≤4 hours for recoverable off-chain services, contingent on successful restoration drill (#81) |
| P1 | Accessibility | WCAG 2.2 AA design target for core setup and claim routes; keyboard operation, contrast, readable error states and mobile coverage (#52, #61) |
| P1 | Privacy | Minimize cross-wallet correlations/PII; controlled retention, consent, proof publication and deletion rules where compatible with immutable public chain evidence (#33, #86) |
| P1 | Scalability | Worker sharding/quotas and reproducible benchmarks; no unsupported scale promises ahead of results (#46, #75, #83) |

## 9. Fees, business model and support expectations

- Migration project owners should see estimated gas/faucet costs, RPC/storage/verification service fees (if any), destination asset backing requirement and claim costs **before** source freeze. Actual gas/fees cannot be guaranteed and must be distinguished from forecasts.
- Initial pricing hypothesis: fee per verified migration plus optional enterprise support; **not agreed or live**. No unauthorized deductions from holder allocations. Validate willingness to pay and operating cost (#85, #88).
- Protocol teams are responsible for sending advance holder communications, obtaining source governance approval, and publishing final freeze/eligibility dates. Metorah provides templates/status evidence, not legal authority to seize or lock others' assets.
- Support needs public security/status disclosures, expected finality time estimates only when measured, incident escalation and claim dispute references. SLA and insurance/guarantees must not be invented (#82, #90).

## 10. Evidence-backed success metrics

**Only count verified real activity, segment testnet and production clearly.** Product metrics: compatible source contracts passing preflight; verified migrations by assurance class; independently reconciled holder counts and amounts; activation failure reasons; eligible holder claim completion rate; median/p95 time to verified snapshot and final claim; unsettled liability; reported mapping errors/disputes; partner conversion and revenue once real. Do not report synthetic model claims as actual adoption.

## 11. Release gates and current baseline

**Current as of 2026-10-15:** one historical offline Python model (16 unit tests passing) and Solidity draft ledger (11 Foundry tests passed on CI for import #11). There is no WASM source deployed, no Portaldot V3 endpoint proven, no finalized source proof, no independent completeness witness, no full backed fungible settlement, no backend/production claimant UI and no independent external audit. This is **not production-ready**.

- **Developer preview:** supported local tools run, canonical manifest vectors pass and architecture/trust assumptions review is complete. Test funds only.
- **Testnet end-to-end:** organizer-confirmed Portaldot chain/runtime, actual freeze and source-state proofs, complete enumeration, funded settlement, real wallet claim, fault-injection and transaction/evidence records.
- **Closed design-partner pilot:** independent security review, documented operational ownership, incident runbooks, reconciled settlement, guarded onboarding/support and written partner acceptance.
- **Production-value launch:** independent critical-path audit and fixes, live network and regulatory review, qualified signers/governance, disaster recovery exercise, SLO evidence, and explicit risk sign-off. No automatic assumption that winning the hackathon satisfies these gates.

## 12. Decisions still requiring evidence

1. Whether an organizer-approved Portaldot V3 WASM runtime and EVM deployment domain are actually available and suitable (#18).
2. Whether finalized storage proof validation can be performed trust-minimized for the chosen runtime or must be disclosed as quorum attestation (#14, #27–#29).
3. Which source interface can guarantee complete enumeration and authorized beneficiary mappings (#20–#23).
4. Which destination asset backing model is financially and legally permitted (#38, #86).
5. Which specific customer will sponsor or pilot the first supported migration (#85, #89).

**This PRD is a controlled hypothesis and engineering acceptance baseline, not evidence that its features are already implemented.**
