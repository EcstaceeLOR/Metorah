# Metorah — Feasibility Experiment (October 15, 2026)

> **STATUS: LOCAL LOGIC VERIFIED; REAL PORTALDOT MIGRATION NOT YET VERIFIED.**
>
> This is an offline Python protocol model, not Solidity, ink!, WASM, EVM,
> a deployed contract, or evidence of a chain-authenticated state proof.

## What was done

- Modelled a cooperating, freezeable source ledger with five accounts and 1,000 units.
- Allowed a source transfer before freeze, disallowed changes after freeze.
- Canonicalized positive entitlements to a domain-separated Merkle commitment.
- Independently compared the entire snapshot against an enumerable, trusted local ledger.
- Accepted claims only with a valid Merkle proof and a signed destination binding.
- Rejected balance tampering, record omission, account theft, redirection,
  replays, double claims, and use of the wrong destination domain.
- Verified full allocation conservation and zero unclaimed supply.
- Ran deterministic randomized cases for 60 additional migration scenarios.

## How to reproduce

Requires Python 3.10+ (tested with Python 3.13). **Never fund the deterministic demonstration keys.**

```sh
python -m pip install -r requirements.txt
python run_experiment.py
python -m unittest discover -v
```

The experiment produces JSON files in `artifacts/`:

- `experiment-report.json`: actual executed outcomes and security assumptions
- `snapshot.json`: example manifest, Merkle root and simulated source identity
- `claims.json`: accepted simulated claims, not blockchain events

**Warning:** `simulated_state_hash`, `simulated_block_number`, and wallet identities in the report are simulation artifacts. They must not be presented as real Portaldot headers, RPC data or transaction IDs.

## Portaldot probe (read-only)

Portaldot's own docs describe running a local development node:

```sh
# On a Linux machine with network access, independently verify the binary source and integrity first.
wget https://github.com/portaldotVolunteer/Portaldot-node/raw/main/portaldot-testnet-ubuntu.tar.gz
# Inspect the downloaded archive, checksum/signature if available, and extraction contents.
tar -tzf portaldot-testnet-ubuntu.tar.gz | head -30
# Extract into an isolated directory after inspecting it; do not use mainnet funds.
tar -xzf portaldot-testnet-ubuntu.tar.gz
cd portaldot-testnet-ubuntu
chmod +x portaldot_dev
./portaldot_dev --dev --alice --tmp
```

Run `portaldot_probe.py` **in a separate shell**:

```sh
python portaldot_probe.py --url ws://127.0.0.1:9944
```

The probe checks read-only methods (`system_chain`, `state_getRuntimeVersion`,
`chain_getFinalizedHead`, `rpc_methods`, `eth_chainId`). It does not deploy,
sign or submit anything. Check whether the host is trusted before running
any downloaded binary. Do not expose the development-node RPC publicly.

This execution sandbox could not fetch GitHub binaries because outbound DNS/network access is restricted; the attempt to run the local probe therefore cannot establish a native Portaldot deployment.

Official documentation: <https://portaldot-dev.readthedocs.io/en/latest/getting-started/local_test.html>

## What remains UNSOLVED for a real migration

1. **Genuine runtime:** Install and execute the actual Portaldot dev node.
2. **On-chain contracts:** Deploy a source `pallet-contracts` WASM ledger with a privileged,
   irreversible freeze (on the supported historical runtime, not a random modern ink! runtime).
3. **Authenticated source state:** Read from a known finalized block and verify actual
   Substrate state/storage proofs against finalized header roots. A Merkle root
   generated from an offchain indexer alone cannot authenticate the chain data.
4. **Completeness:** Enumerate all stateful entitlements from a contract with a
   known storage schema, and independently cross-check the snapshot. Storage
   reads only prove queried values, **not that all users have been included**.
5. **Destination contract:** Deploy a target claim contract on an organizer-confirmed
   qualifying environment. A local Python class is not an alternative.
6. **Wallet ownership:** For Substrate AccountId32 to EVM H160, use secure
   wallet-specific signatures and address mapping; Ed25519 in this POC is
   **not** an EVM wallet signature.
7. **Freeze and cutover:** Verify the source freeze is permanent and recognized
   by the destination. An immutable unfreezable source cannot be safely migrated
   with this method without extra trust, burn, or lock requirements.
8. **Governance and fraud response:** Reconcile fees, failed claims, mapping
   errors, malicious source administrators, and recovery procedures.

## Decision gate

**GO** on designing a purpose-built legacy source freeze + authenticated snapshot
interface. **NO-GO** on claiming a working WASM-to-EVM Portaldot migration until
real network runtime support, both deployments, and finality-verifiable source
state are demonstrated. This project should stay in feasibility until then.
