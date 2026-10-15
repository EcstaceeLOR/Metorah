# Metorah — Migrate Contracts. Preserve Everything.

**Metorah** is being developed as a verifiable state-continuity protocol for securely preserving blockchain-application entitlements through smart-contract migrations.

> **Engineering status (2026-10-15): research/starter only.** This repository currently contains an offline Python feasibility simulation and a draft EVM claims **accounting ledger**, not a deployed cross-VM bridge, production asset settlement, verified source proof, or completed application.

## What is implemented

| Component | State | Important limitation |
| --- | --- | --- |
| `local_model/` | Python simulation with 16 local unit tests | Uses synthetic finalized blocks and synthetic account ownership; **no real-chain proof** |
| `src/MetorahClaimLedger.sol` | Draft destination Solidity contract | Administrator-chosen Merkle root, credits only; **no custody/minting or authenticated source state** |
| `test/MetorahClaimLedger.t.sol` | Self-contained Foundry tests written during prior review | Foundry test results must be independently verified in CI |
| `.github/workflows/validation.yml` | CI workflow definition | Runs only after commit and permissions/toolchains are available |
| `docs/` | Architecture, threat model, baseline audit | Historical audit reflects the original StateLift starter; not a completed security audit |

**Important:** the Python Merkle commitment is SHA-256 with directional paths; the Solidity draft is Keccak-256 with sorted sibling hashing. Their proofs are **not interoperable**. The legacy domain separators (`statelift/poc-v1/*`, `STATELIFT_LEAF_V1`) intentionally remain unchanged to preserve existing test vectors; renaming display identifiers does not silently alter signed/hashing formats. A single canonical, versioned proof format is tracked in [issue #25](https://github.com/EcstaceeLOR/Metorah/issues/25).

## Local reproducibility

Requires Python 3.10+ and installed dependencies from `local_model/requirements.txt`.

```sh
python -m pip install -r local_model/requirements.txt
python -m unittest discover -s local_model -p 'test_*.py' -v
(cd local_model && python run_experiment.py)
```

Solidity build/test requires Foundry installed (not present in the reviewer's local sandbox):

```sh
forge --version
forge build
forge test -vvv
```

### Evidence status

- Python: 16 of 16 unit tests passed in a local execution on 2026-10-15, as separately recorded in the PR test notes. This is **offline simulation** evidence only.
- Solidity: **not locally compiled or tested** where this baseline was prepared; do not claim compilation success until actual Foundry/CI logs prove it.
- Network: **Portaldot V3 RPC/runtime, WASM source deployment, and EVM destination deployment unverified**.
- Historical JSON in `local_model/artifacts/` is simulation output from the original StateLift experiment, not blockchain transaction evidence.

## Product roadmap

See [GitHub issues](https://github.com/EcstaceeLOR/Metorah/issues). Core release blockers include WASM source with irreversible freeze and full holder enumeration, authenticated finalized source-state proof and completeness checking, owner-approved EVM beneficiaries, canonical cryptographic manifests, real solvent settlement, backend lifecycle, end-user claim UI, and independent security review.

Do **not** use the draft with customer funds or advertise it as production-ready.
