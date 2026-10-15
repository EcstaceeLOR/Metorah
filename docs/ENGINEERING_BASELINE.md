# StateLift — engineering baseline (2026-10-15)

## What was actually reviewed

Source: `StateLift_Starter_2026-10-15.zip` (original starter packaged in this review).

- One Solidity destination contract in `src/StateLiftClaimLedger.sol`.
- One existing offline simulation in `local_model/`.
- Architecture and threat-model documents, but no actual WASM contract, deployment scripts, frontend or backend.
- No prior Foundry tests in the starter.

## Execution evidence and limitations

- `python -m unittest discover -s local_model -v` — **16/16 passed** in Python 3.13.5 on 2026-10-15.
- `cd local_model && python run_experiment.py` — **exit 0**, report recorded **16/16 checks passed**, `source_total=1000`, `claimed_total=1000`, `unclaimed_total=0`; explicitly **OFFLINE-SIMULATION**.
- `forge` and `solc` binaries were not present in the reviewer runtime. Outbound DNS for GitHub and npm was unavailable. **No Solidity build or Foundry test was executed**. New test source at `test/StateLiftClaimLedger.t.sol` and GitHub Actions at `.github/workflows/validation.yml` are **unverified until CI runs**.
- No runtime/node binaries and no usable Portaldot V3 RPC were available in the review runtime. **No Portaldot contract has been deployed or exercised**.
- Repository search (`StateLift in:name user:EcstaceeLOR`) returned no repositories. This package has **not** been pushed to GitHub.

## Findings and security gates

### Critical — Python to EVM proof incompatibility

`local_model/statelift.py` uses domain-prefixed **SHA-256** on canonical JSON entries and *positioned* Merkle siblings. `src/StateLiftClaimLedger.sol` uses **Keccak-256** on Solidity ABI-encoded entries and *sorted pair* hashes. They are different commitment formats. Python test success does not imply Solidity claim compatibility. Specify one canonical `STATELIFT_V2` manifest, use an Ethereum Keccak implementation in the builder, and require golden vectors verified independently in Python/TypeScript/Solidity.

### Critical — administrator controls root; no trusted source verification

`commitRoot` requires only an administrator and nonzero root/manifest. `sourceFreezeEvidenceHash` is stored but never verified. There is no finalized header verification, source trie proof verification, holder-completeness proof or independent challenger verification. A malicious/mistaken administrator can create invalid or inflated claims. Name the trust assumption; provide auditable raw evidence and reconciliation; do not advertise the current mechanism as trustless.

### Critical — no WASM source or retirement evidence

There is no deployed or locally compiled ink!/WASM source implementation. No on-chain transfer freeze, snapshot height, chain state proof, or prevention of post-migration source use is demonstrated. An ordinary source mapping that cannot enumerate all users cannot prove migration completeness.

### High — source to EVM ownership mapping is not proven

The Python model uses Ed25519 signatures over a simulation-specific binding payload. The Solidity contract does not verify source AccountId32 ownership, and its leaf beneficiary is supplied entirely by the root producer. For a cooperative source contract, the preferred v1 approach is a user-authorized `register_destination(H160)` transaction *on the source chain before freeze*, storing the binding in source state. Any fallback for unregistered accounts needs a separately reviewed proof scheme.

### High — ledger not a redeemable asset

Claims increase `credits` only. No ERC-20 token, ERC-721 NFT, withdrawal, vault accounting or asset redemption. `totalClaimed <= totalAllocation` cannot establish the allocation's honesty or unique source entitlement ownership.

### High — immutable bad root / operations

`commitRoot` is write-once, which protects against root swaps but permanently traps allocations if the root is wrong or the manifest unavailable. Adopt a preactivation audit/challenge period and recovery plan; do not add unrestricted root overrides after activation.

### Medium — testing and reliability gaps

No Solidity unit/integration tests, no property-based invariant suite, no gas cost measurements, no replay fixtures across implementations, no chain environment verification, no backend/indexer or frontend.

## Next milestone: M1 — canonical protocol + executable destination safety

**Goal:** Prove claims against a single interoperable migration manifest, then determine whether the advertised Portaldot V3 VM support exists on the actual qualifying testnet.

Acceptance gates:

1. Obtain organizer-authoritative Portaldot V3 testnet RPCs, chain identifiers, faucet, supported ink! ABI/runtime and deployment/explorer instructions. Verify them with read-only chain queries before using funds. If the V3 testnet is not available, record a BLOCKED status instead of quietly substituting a different chain.
2. Specify a canonical immutable manifest: version, finalized source genesis/contract/block hash/state root, canonical holder index, source AccountId32, explicit source-authorized EVM beneficiary, asset identifier and units, destination chain ID/contract, migration ID, total, hash algorithm and tree construction. Require deterministic sorting, duplicate rejection, exact totals and replay domains.
3. Implement cross-language serialization and Merkle golden vectors, including uneven leaf counts, invalid domains and leaf tampering. No Python-only SHA-256 proof may be passed to the EVM claim code as if compatible.
4. Build and run `forge build` and `forge test`; all destination positive/negative cases must pass on actual Foundry, with saved command output and compiler version.
5. Create `EcstaceeLOR/StateLift` as a public repo (if nonexistent), push incremental work in PRs and enable CI; capture real CI evidence. The GitHub connection available during this audit permits searching existing repos but does not expose a create-repository action.

**M2 then targets source ink!/WASM with irreversible freeze, authorized destination registration and complete holder enumeration, against the confirmed runtime. M3 targets finalized source header/storage evidence and authenticated root commitment, with claims and supply reconciliation.**

**M1 is not complete until all real builds/tests and the Portaldot network probe are evidenced.** Do not label it production-ready based on local simulations.

## Recommended build sequencing

M0 audit (this report) -> M1 canonical protocol + verification + EVM tests -> M2 ink! source & evidence -> M3 authenticated commit and claim adapter -> M4 indexer/API and wallet flows -> M5 frontend product and E2E -> M6 security review, observability, docs and hackathon deployment.

## Hackathon constraint

Portaldot Hacker House 2026 materials describe V3 EVM/WASM support and a testnet deployment requirement. Historical Portaldot docs demonstrate `pallet-contracts` ink! on a dev node but do not by themselves prove availability of a current V3 EVM endpoint. Treat organizer confirmation and live RPC evidence as a release gate.
