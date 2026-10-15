# Metorah release gates — governance and security policy

**Version 1 (2026-10-15), issue #17.** Status: *approved design policy, unimplemented live deployment gates*. This is a specification, not certification that Metorah can handle funds or an operational release approval. Related: [threat model](SECURITY_TRUST_MODEL.md), [migration lifecycle](MIGRATION_LIFECYCLE.md), [evidence standard](EVIDENCE_POLICY.md), [risk register](RISK_REGISTER.md).

## Staged releases and go/no-go matrix

| Gate | Permitted use | Minimum objective evidence and review | Decision |
| --- | --- | --- | --- |
| R0 — **Internal research** | Local Python/Foundry tests, design papers, no real migrated assets | Commit SHA, reproducible CI runs, explicit simulation/unverified badges, no public “deployed” claims | Allowed to publish *research*, not product launch |
| R1 — **Verified testnet engineering pilot** | Test assets exclusively, approved Portaldot environment | Real chain identity, finalized source freeze and storage proofs, complete holder inventory, authenticated beneficiary mapping, canonical cross-language test vectors, legitimate test-token settlement, real chain tx/block refs, exhaustive integration/fuzz tests; protocol/security sign-off | **NO-GO today** |
| R2 — **Closed design-partner beta** | Restricted trial only after risk assessment; no production-value customer funds by default | All R1, independent review of source verifier and contracts, critical/high findings closed, signed partner runbook, incident/pausing drills, customer support and legally reviewed role/custody model; explicit scoped written acceptance | **NO-GO today** |
| R3 — **Production launch / customer assets** | Specifically reviewed chains and asset adapters with live customer funding | All R2 plus independent security audit, chain compatibility audit, independent reconciliation, real asset solvency, multisig/secrets, backup/restore, recovery and operational SLOs, legal/regulatory review as applicable, documented residual-liabilities and governance policy, signed final release review | **NO-GO today** |

**Disallowed shortcuts:** a screenshot, GitHub Action green check, administrator-signed CSV/root, self-reported “finalized” JSON, generic Substrate dev chain, passing Foundry against an internal draft, or hackathon deadline is **never sufficient** for R1–R3.

The R1–R3 checklist is not automatically satisfied by passing the offline `tools/release/check.py`: until a real evidence verifier and production release policy adapter exist, that script always blocks elevated release tiers.

### Hard blocking conditions (even with unanimous operator approval)

- Wrong/unknown source genesis or unconfirmed Portaldot V3 deployment environment; missing WASM/ink! compatibility (#18–#20).
- Source can still mutate value or recipient mapping after supposed freeze; holder set unknown or incomplete (#21–#23, #29).
- No validated chain finality or trie/storage proof; simulated chain data presented as real (#27–#31).
- Root depends only on discretionary operator authorization; wallet mappings not source-authenticated (#36–#37).
- Destination contract only records accounting credits, lacks legitimate full backing, or double-claim safety not proved (#38–#41).
- Critical/high vulnerabilities unresolved; no independent audit and no reproducible end-to-end chain evidence (#70–#74).
- Single-person custody/activation keys, untested incident response and backups, unclear legal custody/regulatory position (#78–#86).

### Sign-off roles and separation

Each release decision records scope, target chain/asset/contract hashes, reviewed source commit, exact evidence report SHA, outstanding risks and signed acceptance by engineering owner, independent security reviewer, operations owner, and product/business owner. These represent distinct responsibilities. A single account must not self-approve privileged root/funding changes.

The **review board** may deny a launch; it cannot override cryptographic/funding requirements using an administrative signature. Qualified legal review is mandatory before moving into custody/issuance activities that require it.

## Release workflow

1. Tag a release candidate only after exact commit and dependency/toolchain versions are recorded; immutable manifest and reproducible test artifacts attached.
2. Record intended *scope* (chain genesis/runtime, source/destination contracts/code hash, asset, adapter, fees/units, claimant policy, max allocation) and explicit out-of-scope features.
3. Collect source finality/storage/holder-coverage evidence, published canonical manifest, entitlement reconciliation, wallet binding authorization, governance approval and destination solvency proof. Each item must be independently re-checkable.
4. Run tests and inspect actual CI logs and contract artifacts, then security review and partner/customer operational rehearsal.
5. Recompute or independently reproduce evidence. Any mismatch, missing data, unresolved severe finding or excessive risk → **NO-GO**.
6. Record a signed go/no-go decision (names/roles, timestamp, evidence hash, acknowledged risks). For public disclosure, publish *only verified statements* with exact chain/commit references.
7. Deploy only to reviewed scope with monitored canary, reconciled chain events, dedicated on-call and an explicit incident route.

## Rollback and recovery truthfulness

- **Before activation:** reject/replace a false snapshot under documented challenge and governance, or cancel a prepared migration when the source remains safe.
- **After source freeze but before activation:** do not casually unfreeze unless actual source protocol permits a demonstrably safe recovery; immutable source may need dispute resolution without restoration.
- **After destination activation/settlement:** EVM token transfers and confirmed claims are **not reversible** by server rollback. Emergency pause can stop new claims but cannot rewrite users' paid balances/beneficiaries. Compensation or a new migration requires a separate legally and technically approved response.
- Application DB/frontend/worker releases may roll back only if committed canonical manifest versions, chain events, and API compatibility remain consistent. CI rollback is not a blockchain rollback.

## Evidence retention and future enforcement

Evidence bundles must be content-addressed and cross-linked to GitHub commit and immutable on-chain identifiers. Security findings tracked with owner/deadline and closure test. Do not expose private account mappings or sensitive user data just to produce public transparency logs.

**Current status (2026-10-15): R0 only. R1–R3 blocked.** No claim of completed audit, deployed Portaldot contract, or funded settlement has been established. This document is reviewed again after chain qualification (#18) and security audit (#74).
