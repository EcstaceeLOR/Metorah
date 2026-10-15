# Metorah evidence and provenance standard

**2026-10-15 / issue #17.** Distinguish claim, verification result, on-chain observation and independently reproducible proof. A textual URL or fabricated transaction string does not satisfy the chain-evidence gate.

## Assurance grades

- **E0 — specification only:** design/issue/ADR with no executable or chain evidence; label proposed.
- **E1 — offline executed:** commands, environment versions, exact commit, CI run ID and actual pass/fail test output; may support claims about simulation or compilation only.
- **E2 — real chain observed:** chain genesis/hash, specific RPC, block number and hash, transaction hash, contract address/code hash, event/log, timestamp and confirmation/finality status, corroborated by independent query. Shows observation, not complete migration safety.
- **E3 — independently verified source:** E2 + trusted finalized header/checkpoint, actual verified trie/storage proofs tied to header root, exhaustive certified holder set, value reconciliation, source retirement and source-authenticated beneficiary mapping; exact proof format version and independent verifier binary/source hash.
- **E4 — economically settled and security reviewed:** E3 + legitimate asset/escrow backing evidence, destination contract source and compiled bytecode, real claim receipts, adversarial/reentrancy/invariant tests, audit and incident/readiness sign-offs, chain/asset-specific operational approvals.

E0/E1 cannot be marketed as E2+. An operator quorum signature merely authenticates which operator *said* a thing; it does not raise an E0/E1 source record to E3.

## Minimum release evidence bundle

Use structured signed report JSON (schema to be implemented in #31) with:
- `evidence_version`, chain/contract/asset scope, migration and manifest ID, exact repository and commit SHA, reproducible build fingerprint and verifier version.
- Factual `environment`: chain genesis, network/runtime version, RPC provider and independent validation, finalized header/hash/state root, and trust anchor; never "dummy finality" in a real-chain report.
- `source`: frozen contract ID/code, exact freeze transaction and finalized block, complete on-chain enumeration and all per-holder checked proofs/verification verdict, holder count and allocations.
- `beneficiary_mapping`: source-signed destination bindings and exact domain/cutoff check, appropriately privacy-preserving.
- `destination`: exact chain ID and contract/code hash, asset escrow/mint authority and backing proof, per-claim transaction receipts and aggregate outstanding liabilities.
- `checks`: CI run URLs and run IDs, reproducible commands, automated test counts, fuzz seeds where meaningful, external audit findings, reviewer/sign-offs, challenge outcomes and risk waivers.
- `limitations`: remaining unverified claims, scope restrictions, unresolved severity risk, retention/redaction policy, and no-production-funds marker.

**Provenance rule:** record actual observables from tool output, signed RPC evidence and GitHub APIs. Do not guess transaction hashes, simulated node IDs or timestamps. The reference local_model artifacts are E1 at most, never Portaldot proof.

## Audit and discrepancy behavior

Every proposed release is rejected on any missing critical evidence, block/root mismatch, holder omission, unsupported asset, unauthorized beneficiary, funding shortfall or unresolved critical/high finding. If data cannot be verified independently or a toolchain/RPC is unavailable, report **UNVERIFIED/BLOCKED**, not PASS.

Signed final evidence should be content-addressed, independently downloadable and privacy reviewed. Audit logs are append-only; backend restart cannot erase prior rejected attempts or chain events. Do not put private keys or full user financial dossiers in public artifacts.

## Required documentation in pull requests

Each PR includes issue ID, change summary, risk and threats addressed, exact commands and observed results, CI links, migration/ABI changes, and explicit not-tested or blocked items. A merger verifies success, then closes linked issue. Production release review remains separate even when a PR is merged.

The `tools/release/check.py` current version is a **noncryptographic label guard**. It does not validate any chain proof, audit signature or receipt. Future secure release enforcement must be implemented only after verified finality, storage, wallet mapping, settlement and external review.
