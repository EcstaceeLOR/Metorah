# Preactivation challenge policy (Issue #32)

## Assurance boundary

This module implements a deterministic, **offline E2 review policy**, not destination-chain authorization. Even a successful review returns `can_activate=false`, `can_claim=false` and `source_chain_authenticated=false`. No real Portaldot V3 proofs, external reviewer identities, chain finality, destination settlement, durable server records, or production clock are supplied by this module. Never use its verdict by itself to move funds.

## Review flow

1. Open a review for one migration ID and exact SHA-256 manifest digest. Record proposer, at least two distinct reviewers and an independent guardian; set an explicit review closing time.
2. Before the deadline, any identified participant may file a typed challenge with a SHA-256 commitment to a separate evidence package. Challenges clear all previous approvals and prevent approval while open.
3. A reviewer other than the challenger may reject a challenge with a recorded reason/evidence commitment, or uphold it to invalidate the review. A guardian can freeze review or cancel it; the proposer can cancel.
4. Review can pass *only* after the deadline, with no unresolved/upheld challenges, no guardian hold and affirmative approval from every configured reviewer. This is a policy-screen outcome, **not** cryptographic source authentication.
5. A changed manifest requires a *fresh* review window, fresh approvals and a new immutable revision. Cancelled/invalidated reviews cannot be resumed silently.
6. Every recorded action contributes to a SHA-256 hash chain with a sequence number and previous-event commitment. Hash chaining detects tampering against a **previously externally pinned head**; without a trusted external witness it cannot prevent entire-history replacement or rollback.

## Unfinished production requirements

- Authenticate all actors using the production organization identity/role system; derive timestamps from a trusted service, not caller-supplied integers.
- Persist reviews and challenges transactionally with optimistic revision locks, durable challenge evidence, nonce/idempotency rules, an append-only externally witnessed audit log and independent evidence retrieval.
- Bind independent signed verification reports and authenticated Portaldot finality/storage proofs to *the same exact manifest*; do not accept a backend-reported PASS as chain finality.
- Wire a destination E3 contract-level preactivation hold/cancellation and irreversible activation boundary, transaction receipts and postactivation disclosure. Funds already claimed **cannot be undone** by cancelling a report.
- Challenge resolution must be subject to explicit service rules, multiple unbiased reviewers, deadlines/appeals, operator-conflict prevention and legally reviewed retention/privacy procedures.
- Preserve fail-closed availability behavior when sources, witnesses, reviewers or destination state cannot be verified.

Run the adversarial offline suite with `python -m unittest discover -s test -p 'test_dispute_policy.py' -v`.

**Release gate:** Do not close #32 until the actual E3 state transitions, durable storage, authenticated identities and independent reproducible challenge evidence pass integration and security tests. 
