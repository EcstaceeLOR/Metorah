# Metorah developer environment

**This is a working repository foundation, not a deployed application.** Run commands from the repository root.

## Requirements

- Node 24.13.0 (`.nvmrc`) and pnpm 10.19.0 (`package.json#packageManager`) for JS workspaces.
- Python 3.13.7 (`.python-version`) and a fresh virtual environment for the offline model.
- Foundry `v1.3.6`, Solidity `0.8.24` (`foundry.toml`) for currently present contracts.
- Rust 1.90.0 pinned in `rust-toolchain.toml` **provisionally** for future WASM work; this does *not* mean Portaldot contract compatibility or any deployed source contract. Confirm source toolchain only after #18.

## Setup and checks

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm check
pnpm -r test
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r local_model/requirements.lock
python -m unittest discover -s local_model -v
python -m unittest discover -s test -v
(cd local_model && python run_experiment.py)
forge --version
forge build
forge test -vvv
```

Windows PowerShell virtualenv activation: `.venv\Scripts\Activate.ps1`. Command-line tools not installed are preflight failures, not evidence of failed or successful contracts.

## Repository map

```text
.github/workflows/validation.yml     Validation gates
src/, test/*.t.sol                   Solidity claim-ledger baseline and tests
local_model/                          Offline Python feasibility + pinned deps
tools/compatibility/                 Declarative source capability screen
tools/assurance/                     Fail-closed presentation policy
tools/lifecycle/                     Offline lifecycle transition reference
packages/protocol-core/              Shared noncryptographic JS vocabulary
docs/adr/                             Architecture decisions
apps/                                 Reserved for real web/API/worker implementation
```

## Adding packages

Package-local scripts must run deterministically; update `pnpm-lock.yaml`, CI and docs whenever dependencies change. Do not place secrets or production wallet key material into `.env.example`. Do not create blank frontend screens or fake RPC data to satisfy a structural milestone.

## Evidence policy

Unit tests can establish local behavior, *not* chain state authenticity, asset backing or Portaldot deployment. Cite commit SHA, workflow run ID, actual block/tx and chain ID for any real integration claim. The shared lifecycle vocabulary is not the future proof encoding; cross-language cryptographic vectors are #25–#26.
