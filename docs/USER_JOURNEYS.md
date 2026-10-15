# Metorah — Acceptance and failure journeys

**Status:** executable acceptance scenarios proposed for the product; **not** all automated or implemented. Trace each scenario to the PRD and its engineering issue. A happy-path UI with mock data cannot be used as acceptance evidence.

## Journey A — Protocol migration owner

### A1. Eligible source contract and draft setup (FR-01, FR-07)
**Given** an authenticated operator belongs to an authorized organization and chooses an approved finalized WASM source chain and contract.  
**When** the readiness check detects complete holder enumeration, irreversible freeze controls and an appropriate adapter.  
**Then** Metorah may create a persisted migration draft with exact source genesis, source contract, destination chain, asset, intended approvals, supported assurance class and preflight warnings. Nothing is frozen or deployed merely by creating a draft.

**Failure:** if runtime is unverified or source cannot enumerate all positive balances, return UNSUPPORTED/BLOCKED with a specific reason; no activation step should be available. If a user is not an authorized organization member, reject before draft visibility or mutation.

### A2. Pre-freeze holder mapping and informed consent (FR-03, FR-07)
**Given** an eligible migration draft and two source users.  
**When** each user authenticates a destination beneficiary through the source chain and the operator proposes cutover.  
**Then** the UI displays registration coverage, missing beneficiaries, expected downtime, asset backing and estimated/unknown fees; the freeze action requires a separate authorized confirmation.

**Failure:** a malicious admin cannot replace the user's beneficiary; destination registration after the cutoff cannot alter a finalized manifest. Unmapped holders require an explicit protocol policy rather than silent assignment.

### A3. Freeze, authenticate, reconcile, activate (FR-02, FR-04, FR-05)
**Given** a fully prepared source with consent and valid authorization.  
**When** a real freeze is finalized and an independent verifier reconstructs source balances and commitments pinned to one finalized header.  
**Then** the source state becomes immutable, total balance/owner count reconcile exactly, and a transparent signed evidence report is available for review before destination funding and activation.

**Failure:** any inconsistent block roots, missed holders, bad entitlement, incomplete storage proof, inadequate settlement collateral, or contested review blocks activation and provides an audit trail. Repeat requests must not duplicate freeze/activation.

### A4. Reconciliation and closure (FR-06, FR-10)
**Given** an activated migration and multiple on-chain claim transactions.  
**When** the operator opens the migration control room.  
**Then** verified allocation, actually funded/authorized backing, successful settlements, failed attempts and remaining liability are visible with independent chain evidence. Completion must satisfy defined claim-window and residual-funds policy.

**Failure:** chain reorganization or event-indexer outage cannot silently mark an unconfirmed claim final or conceal an asset shortfall.

## Journey B — Wallet holder / claimant

### B1. Find the genuine migration and eligibility (FR-09)
**Given** a holder has a source AccountId32 and a linked destination wallet.  
**When** they look up a migration on the claim portal.  
**Then** the UI identifies exact source and destination, verification assurance mode, their entitlement and mapping status only if matching authenticated evidence exists; public information excludes private organization data.

**Failure:** mismatched genesis/chain ID, wrong beneficiary, unsupported wallet, dispute or missing proof yields a blocking state, not a fake balance.

### B2. Claim a verified entitlement (FR-03, FR-06)
**Given** a valid, active, adequately backed migration and a source-authorized beneficiary.  
**When** that beneficiary connects a supported destination wallet, examines the exact token/amount/fees, approves a transaction and submits a valid inclusion proof.  
**Then** one claim settles the actual authorized asset to that exact beneficiary and the UI waits for appropriate confirmations before issuing a verifiable receipt.

**Failure:** a copied proof submitted from another account, changed amount, wrong destination chain, replayed migration ID or already-consumed index is rejected without granting funds.

### B3. Wallet rejection, failure and recovery (FR-06, FR-11)
**Given** the claimant has not yet settled.  
**When** they reject a signature, lack gas, experience RPC failure or a transaction reverts.  
**Then** their claim remains available if no valid settlement was finalized; the app displays an accurate retry or support instruction and never reports completion optimistically.

**Failure:** an on-chain success with temporarily failing backend must be recovered from chain logs without demanding another settlement.

### B4. Disputes and lost keys (FR-10, FR-11)
**Given** a beneficiary mismatch, omitted account or lost key report.  
**When** the claimant submits evidence and opens a support request.  
**Then** the response states whether migration is preactivation (correctable under reviewed policy) or postactivation (potentially irreversible), preserves audit evidence, and follows documented governance without inventing an override.

## Journey C — Integrator and independent reviewer

### C1. Source integration and capability certification (FR-01, FR-12)
**Given** a developer with an enumerable freezeable contract.  
**When** they run Metorah's SDK/CLI compatibility checks and generate a local source adapter report.  
**Then** supported features, required permissions, chain version and unsupported entitlements are reported deterministically with reproducible commands.

**Failure:** an adapter claiming completeness but unable to prove all holders must fail certification; no automatic arbitrary-contract migration is permitted.

### C2. Independent evidence verification (FR-02, FR-04, FR-05, FR-10)
**Given** a publicly disclosed manifest, trusted finalized checkpoint and required Substrate storage evidence.  
**When** an independent verifier runs without Metorah's private database or operator API.  
**Then** it independently validates exact source root, every eligible holder, beneficiary domain, source total, Merkle root and proof version. The results and verifier build should be content-addressable.

**Failure:** change to any record, proof, chain identity or report bytes must yield explicit failure; valid Merkle membership alone is not sufficient for a passing complete-snapshot report.

### C3. Governance challenge before activation (FR-05, FR-11)
**Given** a reviewer discovers conflicting evidence during the published review period.  
**When** they submit a signed challenge.  
**Then** activation pauses pending authorized resolution and the reason, evidence and disposition remain in an immutable audit trail.

**Failure:** a privileged operator cannot silently dismiss a valid challenge or replace an already active root.

## Evidence required to mark journeys accepted

- Public PR/commit containing implementation plus automated positive/negative tests.
- Actual Portaldot network/genesis and finalized storage evidence for chain-dependent cases (not invented block hashes).
- Actual Foundry contract and runtime test logs, including supply invariants and invalid-claim attack rejection.
- Browser E2E traces/screenshots only from working API/chain integrations; no mocked success states.
- Reviewer-verifiable receipts, event/reorg reconciliation, support and incident handling outcomes.

**Current product state:** only a historical offline Python experiment and a draft Solidity credits contract exist. This document does not assert that any of these journeys is complete.
