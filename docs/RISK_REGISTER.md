# Metorah startup engineering risk register

**Baseline date:** 2026-10-15. All controls are proposed or under development unless an evidence link proves otherwise. Owners are responsible *roles*, not named individuals. Revisit before every release and after all security incidents.

| ID | Risk / impact | Severity | Accountable owner | Mitigation and blocking exit criterion | Tracking | Status |
| --- | --- | --- | --- | --- | --- | --- |
| R-01 | Unverified organizer Portaldot V3 runtime, wrong chain | Critical | Protocol lead | Get official genesis/RPC/runtime/toolchain compatibility, reproducible deploy evidence | #18–#19 | **Open / blocks R1+** |
| R-02 | Source cannot freeze permanently or enumerate all holders | Critical | WASM lead | Prove final freeze and complete on-chain holder registry, no upgrade bypass | #20–#23 | **Open / blocks R1+** |
| R-03 | Forged finalized header/trie evidence or omitted entitlements | Critical | Cryptography lead | Independently validate finalized state root, storage keys/proofs, full holder set and sum | #27–#29, #72 | **Open / blocks R1+** |
| R-04 | Operator can publish arbitrary root and call it verified | Critical | Protocol governance | Enforce verified evidence and challenge period before activation; signed approval is insufficient | #31–#32, #36 | **Open / blocks R1+** |
| R-05 | Unauthorized beneficiary, destination mismatch or replay | Critical | Wallet security lead | Source-account-signed domain mapping and replay-safe claiming; fuzz attacks | #22, #25–#26, #37, #70 | **Open / blocks R1+** |
| R-06 | Destination settlement credits are not redeemable funds | Critical | Solidity lead | Reviewed mint/escrow authority, funded backing and conservation, verified receipts | #38–#40 | **Open / blocks R1+** |
| R-07 | Reentrancy, replay, double claim, bad token semantics | Critical | Security lead | Comprehensive adversarial and property testing; external audit for real-value launch | #39–#41, #70, #74 | **Open / blocks R2+** |
| R-08 | Compromised privileged signing key or single approver | High | Security/operations | Hardware/multisig separation, key rotation, audited emergency pause | #41, #79 | **Open / blocks R2+** |
| R-09 | Inconsistent source snapshots on RPC outages/reorg | High | Chain operations | Pin finalized checkpoint; redundancy; durable resumable verification | #30, #46, #83 | **Open / blocks R1+** |
| R-10 | Incorrect claim UI or unreliable backend hides failures | High | Product engineering | Typed API auth, chain receipt reconciliation, failure journeys and E2E tests | #44–#61, #73 | **Open / blocks R2+** |
| R-11 | DB outage/worker failure erases audit or state | High | SRE | Immutable artifact store, audited state transitions, restore/reindex drills, alerts | #43, #47–#48, #80–#82 | **Open / blocks R2+** |
| R-12 | Sensitive cross-chain wallet mapping disclosed | High | Privacy/compliance | Data minimization, encrypted evidence, retention and review | #33, #47, #86 | **Open / blocks R2+** |
| R-13 | Unsupported assets/vesting/NFTs silently truncated | High | Product/protocol | Fail-closed compatibility policy; certify adapters by category | #13, #42, #62 | **Partially mitigated offline; blocks launch for unsupported assets** |
| R-14 | Audit/supply-chain compromise or dependency drift | High | Security engineering | Independent review, code hashes, toolchain pinning and dependency checks | #16, #69, #74, #76 | **Partially mitigated by CI; audit incomplete** |
| R-15 | Real customer use creates unreviewed custody/regulatory obligations | High | Legal/product | Jurisdictional counsel review, custody analysis, signed terms, no real funds meanwhile | #86 | **Open / blocks R3** |
| R-16 | Unclear residual claims and immutable rollback promises | High | Governance/product | Document irreversible cutover, paused claims, funded liabilities and dispute path | #15, #32, #41, #60, #82 | **Design documented; implementation open** |
| R-17 | Brand collision or domain/legal IP dispute | Medium | Founder/brand | Live trademark search, registrations and availability before costly launch | #87 | **Open / commercial** |
| R-18 | No validated customer demand/economics | Medium | Product/founder | Customer interviews, pilot evidence, cost/claim benchmarking and pricing | #85, #88–#91 | **Open / commercial** |

### Review instructions

- No vague "fixed" statuses. Close only when specific evidence (commit, CI, authenticated chain artifact, audit report or signed decision) is linked to the risk.
- No acceptance waiver can overrule hard cryptographic/source retirement/asset backing requirements.
- In R1 test-only pilots, assign real named owners and incident contacts in the controlled internal record before transactions.
- Review monthly during development, before each phase gate, after contract/protocol upgrades and after security incidents.
- Escalate critical unresolved risk as release NO-GO, even if hackathon or marketing deadlines approach.
