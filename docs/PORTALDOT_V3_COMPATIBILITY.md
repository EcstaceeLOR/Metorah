# Portaldot V3 runtime qualification — evidence inventory

**Research recorded October 15, 2026 · Issue #18 · STATUS: NOT VERIFIED.**

This report separates public marketing/descriptive documentation from observed chain evidence. It does **not** claim a verified live V3 node, source WASM deployment, EVM contract or authenticated migration.

## Public source comparison

| Source | What it actually establishes | Does not establish |
| --- | --- | --- |
| [Portaldot Hacker House 2026 announcement](https://x.com/PortaldotL0/article/2104593132570751302) and [Eventbrite listing](https://www.eventbrite.com/e/portaldot-hacker-house-2026-tickets-2002321816454) | Organizer advertises **V3.0 WASM + EVM support** (announcement dated September 28, 2026) | No observed V3 RPC, EVM chain ID, genesis hash, deployed example or exact compatible compiler versions confirmed here |
| [Portaldot Developer v1 chain info](https://portaldot-dev.readthedocs.io/en/latest/chain-info.html) | **Legacy documentation** lists `wss://mainnet.portaldot.io`, SS58 format 42, POT with 14 decimals | Does not establish this URL points to the approved V3 hackathon network |
| [Legacy pallet-contracts RPC docs](https://portaldot-dev.readthedocs.io/en/latest/module-interface/rpc/contracts.html) | Documentation contains `contracts_call` and historic `contracts_* ` RPC surface | No proof that a current V3 node still runs pallet-contracts or accepts any particular ink!/cargo-contract build |
| [Public node binary repository](https://github.com/portaldotVolunteer/Portaldot-node) | Repository includes dated compressed Ubuntu/macOS mainnet and testnet executables, last pushed December 29, 2025 | No GitHub Releases artifacts, supplied detached signature/checksum, reproducible source build or V3 compatibility proven |
| [Polkadot developer docs](https://docs.polkadot.com/develop/parachains/customize-parachain/add-smart-contract-functionality/) | Differentiates Frontier EVM, legacy pallet-contracts and newer pallet-revive interfaces | Not proof which runtime Portaldot V3 runs |

**Important:** the linked Portaldot volunteer repository is a binary distributor, not proof of binary authenticity. Do **not** download and execute binaries in an unsafe environment, expose `--rpc-external` with permissive CORS, or use production funds or seed phrases.

## Evidence still required from organizer or independent trusted runtime checks

- [ ] Official V3 *WASM* WebSocket/HTTP RPC and authenticated chain genesis hash, current runtime name/spec version and chain spec.
- [ ] Exact *EVM* RPC URL and chain ID, on-chain `eth_chainId` + block queries, and whether EVM and WASM share finality/security.
- [ ] Proof through decoded runtime metadata that `Contracts`/ink! or an equivalent WASM contracts pallet is enabled and deployable in V3; exact supported source Rust, ink!/cargo-contract toolchains.
- [ ] Confirm source storage-trie semantics, state proof RPC availability, finality trust anchor and archive access for migration snapshots.
- [ ] Approved faucet, explorer, signing/account mapping mechanics, costs, devnet/testnet availability and permitted hackathon deployment path.
- [ ] Reproducible dev-node build provenance or official signed binary checksums and safe local runbook.
- [ ] Observed real read-only RPC probe output with both endpoints, consistent genesis/finality and contract-method capabilities, then signed/test-asset deployment receipts for compatibility qualification.

## Current execution evidence and constraints

- Local session attempts to resolve `mainnet.portaldot.io` and `github.com` returned `socket.gaierror` (temporary DNS failure). Therefore **no live RPC response could be collected from this environment**. This is an execution limitation, not evidence that the RPC is down.
- `local_model/portaldot_probe.py` performs only read-only JSON-RPC inspection (system chain, genesis, runtime, finalized head/header, RPC method list, EVM chain ID and metadata fingerprint). It refuses insecure remote plaintext URLs and never signs, transfers or deploys.
- Even when a user supplies a matching genesis hash, the probe reports `OBSERVED_MATCHES_CALLER_GENESIS_NOT_V3_VERIFIED`; caller-supplied values are **not independently validated organizer trust anchors**.
- RPC method names and a returned `eth_chainId` do **not** prove WASM deployment, EVM contract support, contract compatibility or honest consensus. Output always states `portaldot_v3_qualified=false` until the real verifiers/deployment are implemented.

## Reproduce offline tests / optionally inspect a trusted node

```sh
python -m unittest discover -s test -p test_portaldot_probe.py -v

# Only after verifying the endpoint identity independently:
python local_model/portaldot_probe.py --url wss://YOUR_OFFICIALLY_CONFIRMED_PORTALDOT_V3_RPC --expected-genesis 0xYOUR_VERIFIED_32_BYTE_GENESIS_HASH --output local_model/artifacts/portaldot-v3-observation.json
```

Do not mistake `OBSERVED_*` for security qualification. The source contract must later be *actually deployed* on a confirmed runtime before issue #18 can be closed, and real chain proof verification is separately issue #27–#29.

**Decision:** Issue #18 **remains open / blocked on official V3 network parameters and real runtime checks**. No verified deployment, no submitted transaction and no certification of the provisional Rust 1.90.0 pin from #16.
