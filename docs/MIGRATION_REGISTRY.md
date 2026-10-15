# Migration registry and deterministic CREATE2 ledger deployment — Issue #35

The `MetorahMigrationRegistry` deploys **accounting-only** `MetorahClaimLedger` contracts in isolated source/destination domains. It does not enable settlement, verify source finality, deploy to Portaldot, or authorize release of customer assets.

## Canonical identity

`migrationId = keccak256(abi.encode(ID_DOMAIN, registryAddress, sourceGenesis, sourceContract, destinationChainId, mode, uint32(manifestVersion), assetId))`. Every field has a fixed ABI type, and nonzero field checks apply. The destination chain ID must equal `block.chainid`, and the contract rejects calls made on a different chain than the domain specifies. The registry address scopes identities to the deploying registry; do not treat the same source tuple on separate registries as the same migration ID. Keccak collision resistance is a cryptographic assumption, not absolute mathematical impossibility.

**Source contract ID and asset ID are bytes32**: the upstream canonical adapter is responsible for validating real source runtime encodings. Never hash an arbitrary user-input label and pretend it is a verified on-chain address. Mode and manifest version are caller-supplied policy identifiers, *not* evidence that this conversion mode or schema is supported by a live chain. Enforce approved modes and versions at the higher-level integration gate.

CREATE2 salt is the migration ID. The predicted address includes the full `MetorahClaimLedger` creation bytecode, migration ID, opaque freeze evidence hash and total allocation. This ensures deterministic addresses for a given registry deployment and **exact** input tuple. The same migration domain can only be deployed once per registry, regardless of differing freeze hashes/caps. The factory owner is privileged to reserve new domains; this restriction prevents permissionless registry squatting but does not prove that the owner's data is correct.

## Administrator authority

The newly created ledger initially trusts the deploying registry as administrator. The factory immediately nominates the requested administrator via `proposeAdministrator`, and only that nominee may call `acceptAdministrator`. The nominee cannot publish a root before accepting, and the current administrator must be the one to propose. Pending nomination is cancellable/replacable by the administrator until commitment. No handoff is allowed after a root is committed. If an administrator never accepts, the factory-owned ledger remains uncommitted and the domain is reserved; operator procedure must validate the nominee and record acceptance before declaring the registration operational.

**Warning:** after handoff, the nominee can unilaterally commit an arbitrary Merkle root. These are inert accounting credits, but this is still a privilege/control defect for an eventual fund-bearing migration. Evidence gating, authenticated finality, authorization roles, challenge window, backing checks, and external audits belong to subsequent E3 issues (#36 onwards).

## Reproducible checks

```sh
forge build
forge test -vvv
```

Tests assert CREATE2 address prediction, registry lookups, domain-separation sensitivity, invalid input rejections, duplicate collision policy, factory authorization, two-step administrator handover, non-transfer/accounting semantics and old direct-ledger constructor compatibility.

No actual transaction, contract address, source root, or Portaldot runtime compatibility is claimed by these Foundry fixtures. Check the PR's Solidity CI run and commit SHA before reporting tests as successful. Do not use these contracts with real assets without security, custody and settlement review.
