# Metorah — source compatibility and supported asset policy

**Status:** specification and **offline declarative preflight** only; no RPC, bytecode introspection, state trie verification or WASM source adapter has yet been implemented. See product PRD (#12), chain verifier (#18, #27–#29), source adapter (#20–#23, #62), settlement contract (#38), and live integration (#73).

## Decision rule

Metorah must **refuse migration when it cannot prove it will preserve all required entitlements**, not silently drop unsupported state. The first certified class is a purpose-built, cooperative WASM source fungible-entitlement ledger with complete enumerability, finalizable irreversible freeze, independently verifiable state, source-authorized beneficiary registration and destination EVM settlement backed by legitimate tokens/escrow/mint authority.

An ERC20-looking balance getter alone is **not enough**: typical mappings do not enumerate all holders. Merkle inclusion proofs do **not** prove the holder set is complete. Off-chain CSV snapshots and indexes are not authentic by default.

### Proposed release support matrix

| Contract state category | First certified release | Preconditions or reason |
|---|---|---|
| Enumerable fungible balances | **Candidate only**, pending chain and security certification | Known complete holder registry; immutable snapshot; source-authorized mapping; finalized storage evidence; exact total; backed destination settlement |
| Conventional unenumerable fungible token/mapping | **Blocked** | Cannot prove completeness of all holders from queried balances alone |
| ERC721 NFT identities and token metadata | **Not supported** | Needs token-ID uniqueness, metadata and ownership-specific proof/settlement adapter |
| ERC1155 multi-asset balances | **Not supported** | Per-token ID inventory and supply conservation missing |
| Governance voting, delegation and roles | **Not supported** | Non-fungible privileges and delegate effects need authority semantics |
| Allowances / approvals | **Not supported** | Approval reinstallation can introduce risk and cannot be inferred from balances |
| Vesting / staking / locked funds | **Not supported** | Time-locks, reward accounting and terms must migrate exactly |
| Rebasing / fee-on-transfer / interest-bearing shares | **Not supported** | Ratio, fee and rounding semantics may violate conservation |
| Private or non-public balances | **Not supported** | Privacy and proof design not independently reviewed |
| Arbitrary contract state / immutable contracts without safe freeze | **Blocked** | No reliable full-state interface or old-state retirement proof |
| Unsupported chain/runtime, unknown origin or destination | **Blocked** | Contract can only be verified in a trusted, actually supported execution environment |

No one should infer from this table that live Portaldot V3 WASM or EVM has already been verified. The official runtime, RPC genesis, explorer and toolchain are separate acceptance gates (#18).

## Abstract adapter contract (design, not ink! ABI)

A certifiable source adapter must eventually provide independently readable/verifiable properties:

1. **Provenance:** chain genesis, runtime version, source contract identifier, asset ID, units/decimals and supported adapter version.
2. **Full inventory:** deterministic total count and index → unique source account for every positive entitlement; zero/deleted holder rules; independent total of all balances.
3. **Pre-freeze source rights:** source wallet signs/registers beneficiary scoped to destination chain/contract/migration; mutation and registry events available for forensic review.
4. **Freeze boundary:** authorized irreversible freeze, finalized event/checkpoint, blocked transfer/mint/burn and any entitlement-affecting storage changes after freeze.
5. **Independent proof:** storage keys/schema metadata, storage proofs against a finalized state root, and independent completeness reconciliation for entire holder set.
6. **Destination readiness:** exact asset ID and balance semantics, decimal conversion policy, settled supply backing and reviewed contractual mint/escrow authority.
7. **Failure evidence:** explicit reasons when contract is unsupported, source not final, holder count inconsistent, unmapped account present or funding insufficient.

Do not assume an indexer can self-declare these values true. Later live checks must authenticate them on-chain before any high-risk transition.

## Machine-readable capability screen

`tools/compatibility/policy.v1.json` is the human-auditable v1 policy definition. `tools/compatibility/check.py` screens *operator-supplied* JSON metadata against the release restrictions and fails closed on missing, ambiguous or extra features. It **never returns authorization to freeze or activate**, even for valid input.

```sh
python tools/compatibility/check.py tools/compatibility/example-candidate.json
python -m unittest discover -s test -p test_compatibility.py -v
```

The example uses an all-zero **synthetic genesis placeholder** and is a fixture only; it must never be displayed as an observed chain genesis, verified V3 deployment or successful eligibility proof. A successful result is `CANDIDATE_REQUIRES_INDEPENDENT_VERIFICATION`, and `can_freeze=false`, `can_activate=false`, `source_state_authenticated=false` remain mandatory until a separate authenticated runtime verifier exists.

Operators should see the detected incompatible features and missing requirements **before** proposing a freeze transaction, accompanied by links to support/guidance. Unsupported migrations cannot bypass these checks through the UI or backend.

## Versioning and evidence rules

Changing an accepted asset type or requirement requires a new policy version, compatible JSON schema/SDK changes and adversarial conformance tests. Runtime proof certification and on-chain entitlement settlement are separate gates. This policy is **not** a security audit or chain guarantee.
