# Metorah security trust model and evidence-claim policy

**ADR/security draft v1 — 2026-10-15. This is an engineering specification, not an audit or a claim that a live verifier, source contract, or settlement system exists.**
Owner: protocol/security engineering. Tracking: #14; dependent implementation #18, #20–#29, #31, #32, #36–#41, #70–#74.

## 1. Security objective and scope

Metorah's purpose is *continuity of entitlements across a deliberate source-contract retirement and destination settlement*. The initial certifiable class is a cooperative, **enumerable, irreversibly freezeable fungible entitlement ledger** on a chain actually verified to support the source WASM runtime. A valid signed operator statement or a valid Merkle inclusion proof **cannot by itself establish that the source was real, final, complete or safely retired**.

An initial release must refuse unsupported or unprovable asset classes and must not activate or settle without an independently checked source state, beneficiary authority, destination backing, and approved activation. This design does **not** solve arbitrary storage migration, validator collusion, a malicious underlying token, an upgradeable source with a bypassable freeze, or compromised source-wallet signing keys.

### Critical invariants (must later be enforced on chain, not only in this document)

- **I-1 Source finality and uniqueness:** evidence is bound to one trusted chain genesis, source contract, approved runtime, finalized block hash and state root; no records from different blocks, forks or contracts are mixed.
- **I-2 Freeze/retirement:** no source entitlement can remain transferable, minted, burned or otherwise reallocated after the finalized migration cutoff. Upgrade or privileged bypass paths must be ruled out; if not, migration is **BLOCKED**.
- **I-3 Complete enumeration:** the independently verified set of unique holders is exhaustive against the frozen on-chain inventory (including tombstone rules). Every positive source entitlement occurs exactly once in the manifest. A sum-only check is insufficient.
- **I-4 Allocation conservation:** aggregate destination allocation equals the exactly specified source entitlement amount after explicit units/decimal/rounding policies. No silent fees or omissions.
- **I-5 Beneficiary control:** a destination account is bound through source-account-authenticated registration and domain-separated to destination chain, contract, migration and cutoff; operator, relayer or frontend cannot redirect it.
- **I-6 Exactly-once settlement:** the same entitlement index and migration can be settled at most once; failure of an external transfer must preserve the user's ability to claim. Claimed value cannot exceed verified allocation or available legitimate backing.
- **I-7 Immutable activated terms:** once activated, an operator, compromised API, or root administrator cannot alter manifest, recipient, amount or backing policy for already entitled users. Review, challenge and cancellation exist *before* activation; any postactivation pause cannot transfer or rewrite users' rights.
- **I-8 Observability without trust substitution:** an indexer, API, screenshot, explorer, multisig approval or web dashboard is not a substitute for independently verified protocol evidence or actual chain receipts.

## 2. Actors and trust boundaries

| Actor/boundary | Capabilities | Attacker model / guard |
| --- | --- | --- |
| Source governance/admin | Freeze, potentially upgrade and authorize issuance | Assume malicious or compromised. Audit privilege reachability; refuse if permanent freeze can be bypassed. Source admin signature alone never proves complete holdings. |
| Source holder | Authorize wallet binding; may lose/compromise keys | Authenticate in source runtime; cutoff and nonce/domain separation; no arbitrary administrator remapping. |
| Source consensus/validators | Establish finalized header/state root | Trusted only under chain-specific consensus/finality and checkpoint assumptions. Validator-majority collusion or dishonest finalized state is out of protocol scope and must be disclosed. |
| Source RPC(s) | Relay headers, trie nodes and contract metadata | Untrusted transport; validate against trusted finalized header and genesis; reject stale/inconsistent proofs and wrong chains. Multiple RPCs aid availability, not cryptographic proof by themselves. |
| Indexer/snapshot worker | Enumerate and propose manifest | Fully untrusted for highest-assurance mode. Verify all indexed entries against chain state; independently reconcile holder set and totals. |
| Metorah API/UI/relayer | Orchestrate and present transactions/proofs | Treat as potentially compromised; clients independently validate immutable identifiers and beneficiary/amount, server cannot claim authenticity by self-report. |
| Operator/root approvers | Propose commitment, review evidence, pause where authorized | Potential collusion. Their quorum approval is governance assurance only, not source authenticity. Highest assurance cannot accept arbitrary operator-selected root. |
| Destination chain and token issuer/escrow | Execute claim and transfer/mint asset | Trust destination finality, issuer's legitimate mint authority or escrow backing, safe token assumptions and correctly deployed contract code. |
| External auditor/reviewer | Inspect code, evidence and deployments | Useful independent assurance, not a substitute for enforcing source proof checks and settlement invariants in deployed code. |

**Trust boundary diagram:** source-finalized state → independently checked chain/storage evidence → exhaustive holder reconciliation → immutable canonical manifest → independently gated destination activation → backed claim settlement. Administrator-written data may enter only as an *unverified proposal*, not as an authenticated state root.

## 3. Assurance modes and allowed public language

| Mode | Data authority | Permitted exact concept | Forbidden implication |
| --- | --- | --- | --- |
| `simulation` (implemented model) | Synthetic local balances and signatures | **Offline simulation — not chain authenticated** | Real deployment, custody safety, proven chain finality |
| `operator_snapshot` (proposed pathway) | Operator-provided records/approvals | **Operator-provided snapshot — independently unverified** | Trustless, authenticated source state, complete holder proof |
| `independent_verified` (TARGET, NOT IMPLEMENTED) | Validated finalized header and trie/storage proofs *plus* exhaustive inventory, freeze, bindings, backing | **Independently authenticated** only once all acceptance gates are actually enforced and linked to specific public evidence | “Zero trust” or immunity to chain consensus compromise, wallet theft or malicious tokens |

**Hard rule:** no unsupported live component may emit `source_state_authenticated=true`, `can_activate=true`, `can_claim=true` or display “trustless/verified migration.” An attestation may be *cryptographically signed*, but what is signed is still an **operator claim**, not a chain-authenticated holder set.

The executable `tools/assurance/evaluate.py` is only a **fail-closed presentation policy** for this repository's currently unverified stages. It does **not** authenticate signatures, run a trie verifier or authorize on-chain activity. An interface or SDK must not bypass it for claims labels; a real runtime gate will require chain-specific proof enforcement and a security review before the `independent_verified` mode is enabled.

## 4. Minimum independently verified evidence (future implementation contract)

A future security-grade report must bind *all* of the following in canonical versioned binary encoding: approved network and source genesis, source contract/account and code hash, immutable source schema/adapter version, actual finalized header hash and state root, finality proof/trust anchor, exact freeze/retirement event and post-freeze read-only evidence, verified state/storage keys/proofs and set enumeration, unique holder count and per-holder units, reconciled sum and roundings, source-signed destination beneficiaries, destination chain ID and exact claim/settlement contract, asset type/issuer/funding proof, immutable migration ID and commitment, verification algorithm/build hash and reproducible public proof report. No “all true” JSON object from an operator should be allowed to replace cryptographic verification of these inputs.

Activation protocol (not built yet): (1) qualify chain and source schema, (2) source-wallet beneficiary registration, (3) authorized irreversible freeze, (4) await finalized checkpoint, (5) verify trie proofs and exhaustive holder set independently, (6) generate canonical manifest and review/challenge window, (7) verify sufficient and legitimate backing, (8) enforce reviewed activation policy against same immutable evidence hash, (9) execute and independently reconcile claims. If any check fails, stay in blocked/disputed mode. Do not make a “rollback” promise for already confirmed token transfers.

## 5. Threat register / attack-to-control mapping

| Threat | Consequence | Required prevention/detection | Implementation tracker |
| --- | --- | --- | --- |
| T01 Admin commits arbitrary Merkle root | Invented/missing entitlements | Chain-verified membership *and* complete inventory; root bound to independently authenticated evidence, not operator statement | #25–#29, #31, #36 |
| T02 Snapshot omission with rehashed root | Silent theft or stranded funds | On-chain enumerable complete inventory and independent per-holder reconciliation; totals and counts alone not enough | #21, #29, #72 |
| T03 Wrong chain/contract/fork | Unrelated entitlements accepted | Check genesis, code, finalized hash/state root and migration-domain typed encoding | #18, #27–#28, #25 |
| T04 Forged RPC data | Fabricated balances | Trusted finality anchor plus trie proof verification; fail closed | #27–#28 |
| T05 Source freeze can be bypassed | Double use of original and destination | Verify all privileged mutation/upgrade paths absent or irreversibly disabled; post-freeze tests | #20, #23, #71 |
| T06 Source and destination mappings altered | User claims redirected | Source-authenticated beneficiary, cutoff, nonce, chain and contract domain | #22, #37 |
| T07 Frontrun copied inclusion proof | Unauthorized claim | Bind actual destination to authenticated leaf; proof possession alone grants no change of destination | #25–#26, #37 |
| T08 Proof replay / duplicate claim | Double settlement | Per-migration claim bitmap/nullifier and scoped leaf encoding | #26, #39, #70 |
| T09 Malicious destination token/reentrancy | Drain/freeze/unbacked claims | Trusted asset interface/escrow authority, effects-before-interactions, safe transfer and revert semantics | #38–#39, #70 |
| T10 Decimal, rebasing or fee-on-transfer mismatch | Loss of value | Explicit units/rounding; reject unsupported token semantics; reconcile conservation | #13, #38–#40 |
| T11 Partial source scan after outage | Incomplete snapshot | Pin a *single* finalized header, resumable full-set enumeration and fail-closed worker | #29, #30, #46 |
| T12 Administrator/signer quorum colludes | Bad root authorized | Independent source verification enforced separately; quorum never grants “trustless” status | #14, #32, #36, #79 |
| T13 Compromised backend, API or user interface | Phishing/false eligibility | Signed provenance and local verification, least privilege, no hot private keys, exact recipient display | #44, #49, #57–#58, #79 |
| T14 Validator collusion or dishonest finalized source | Fundamentally invalid proof root | State finality and consensus are explicit chain trust assumptions; circuit breaker and disclosure, not a claimed cryptographic cure | #18, #27, #82 |
| T15 Upgrade/pausing abuse after activation | Admin steals or rewrites claims | Immutable activated manifest and allocation, limited pause, multisig/timelock, recovery runbook | #36, #41, #82 |
| T16 Chain reorg / indexer false confirmation | Phantom settled funds | Confirm finality and reconcile receipt against canonical chain state | #48, #73, #80 |
| T17 Missing beneficiary or lost source wallet | Entitlement stranded | Pre-cutoff coverage, explicit unclaimed policy and dispute process; no admin redirection | #22, #32, #60 |
| T18 Storage/privacy leakage | Link source and destination financial identities | Disclosure minimization, protected artifacts, consent/retention policy | #33, #47, #86 |
| T19 Software supply chain compromise | Altered verifier or destination binary | Pinned compiler and dependencies, reproducible artifact signatures, static analysis, audit | #69, #74, #76 |
| T20 Funding shortfall/custodian insolvency | Receipts without redeemable value | Verify actual escrow backing or legitimate mint authority before activation; ongoing invariant reconciliation | #38–#40, #80 |

Risk cannot be marked *resolved* by documentation alone. Each control must be tested with actual chain-compatible binaries, negative cases and adversarial evidence; acceptance remains tracked in the linked issues.

## 6. Failure response and claims that MUST NOT be made

- Before activation: wrong/omitted source state, contested owner mapping, disputed finality or missing backing → **block activation; preserve evidence; allow reviewed cancellation/replacement under policy**.
- After activation: pause may be available, but **previously settled claims cannot be assumed reversible**. A remediation must not confiscate unrelated entitlements or create more supply.
- Customer assets: **NO-GO** until independent security review, verified chain compatibility, actual source and destination deployment with receipts, real asset backing, and rigorous end-to-end tests (#73–#74).
- Marketing/product/SDK: do not say “fully trustless,” “any chain,” “zero risk,” “all state,” “authenticated,” “live” or “deployed” without scope-specific and reproducible evidence.
- This document and a passing offline assurance-policy test provide **no runtime protection** against an operator deploying their own contract. Actual enforcement belongs to the protocol's contract/verifier milestones.

## 7. Traceability and review gate for issue #14

Acceptance: (a) explicit trust assumptions per mode and threat boundaries, (b) highest-assurance design **requires** independent proof enforcement so compromised operator root cannot silently rewrite activated allocations, and (c) executable policy/tests block promotional false-verified labels *today*. The second is a **design invariant, not currently deployed enforcement**; implementation closure is conditional on later tickets. Review this model after official Portaldot runtime facts are established in #18 and after a qualified independent audit.
