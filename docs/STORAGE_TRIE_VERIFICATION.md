# Metorah verified-storage-trie engine — Issue #28

**Engineering scope:** offline cryptographic membership verification **relative to an explicitly supplied Substrate state root**, plus hash-pinned read-proof acquisition. **NOT verified Portaldot V3 finality or authenticated entitlement settlement.**

## Security objective

A generated migration Merkle root is **not** evidence that an owner's units or bound destination wallet existed in authentic source storage. Before any Metorah release, an independent verifier must authenticate the source chain's finalized state root, prove source storage values and omissions against it, reconstruct all holder rights and validate the source freeze.

The implementation deliberately separates three steps:

1. **Read-only observations (E1 at most):** the #27 adapter `tools/finality/substrate.py` obtains a reported finalized header and exposes a block-hash-pinned read-only storage reader. This does NOT cryptographically authenticate its state root.
2. **Storage trie verification relative to supplied root:** the new `tools/trie_verifier/collector.py` calls `state_getReadProof([keys], checkpointHash)` and `state_getStorage(key,checkpointHash)` for **exactly the same hash**, rejects mismatching proof `at` and returns the raw node bytes. The new standalone Rust `tools/trie-verifier/` binary uses upstream **Parity `sp-trie` version 46.0.0** and `sp-core` 43.0.0 to verify actual Substrate Blake2-256 V0 or V1 tries. Both inclusion `Some(value)` and absence `None` are supported; no hand-rolled Merkle algorithm.
3. **Required E3 trust anchor and contract-specific decoding:** authentic Portaldot V3 runtime/chain identity, GRANDPA/BEEFY/other finality signatures, independently recomputed SCALE header hash, state trie version, Contracts pallet child-trie/storage key derivation, account/balance/registration SCALE decoders and complete holder-set proof. **None of this is established by this PR** (#18/#27/#29).

Even if step 2 verifies, the source may be fabricated if an adversary provided the root. **The verifier always reports root_authenticated_by_finality=false, keys_authenticated_by_runtime_metadata=false, contract_storage_decoded=false, can_activate=false, can_claim=false.** Never pass an RPC-reported state root to a payment contract.

## Offline verifier threat checks

- A verifier caller must explicitly pass `--trusted-state-root`, `--trusted-block-hash` and `--state-version` (0 or 1). The input JSON redundantly includes these and must match exactly; the CLI flags do NOT attest they were independently verified. The root and block cannot be zero.
- The JSON envelope `metorah-substrate-storage-proof-v1` supports **up to 256 lexically sorted, unique, nonempty exact keys**; values must be byte-exact lowercase `0x` hex or JSON `null` (which means a non-inclusion proof, not a value of zero).
- Node data is byte-exact lowercase hex, without duplicate nodes. Hard caps: 512 nodes, 256 KiB per node, 2 MiB overall input. Reject empty/missing nodes, malformed roots, wrong block, wrong layout, duplicate/unsorted keys, missing proof coverage, substituted value, forged absence and mismatched proof root.
- The Rust tool invokes `sp_trie::verify_trie_proof::<LayoutV0<Blake2Hasher>, ...>` or `LayoutV1`, **never** a SHA256 hash comparison or an EVM Merkle verifier. V0/V1 choice must come from trusted runtime storage-version metadata. Do not automatically retry another layout when verification fails.
- No networking, wallet/private keys, contract writes, claim authorization or admin override occurs inside the Rust verifier. It reads a single bounded JSON object from stdin and returns either a nonauthorizing report or a nonzero exit status. External identity and header correctness remain independent verification tasks.
- Python HTTP(S) collector permits only read-only methods. It requires explicit `--enable-network`, operator-supplied RPC/genesis/checkpoint/state version/key bytes and writes a proof-bundle JSON, **never** an approval or verified receipt.

## Reproduction

Run the synthetic no-network tests:

```sh
python -m unittest discover -s test -p test_storage_trie_collector.py -v
cargo test --manifest-path tools/trie-verifier/Cargo.toml --all-targets
```

The crate explicitly pins **direct** `sp-trie =46.0.0` and `sp-core =43.0.0`. Its complete Cargo dependency lockfile and execution environment must be committed/verified before calling the verifier reproducible or audit-ready. The initial implementation's CI executes real Rust trie construction, generated proofs, inclusion, non-inclusion and corruption/replay tests, but is not proof of official network compatibility.

Only with an independently established network and metadata may an operator run the following template after replacing every placeholder:

```sh
python tools/trie_verifier/acquire.py \
  --enable-network \
  --rpc-url https://APPROVED_SUBSTRATE_JSON_RPC \
  --expected-genesis 0xTRUSTED_GENESIS_32_BYTES \
  --checkpoint 0xTRUSTED_FINALIZED_BLOCK_32_BYTES \
  --state-version 1 \
  --storage-keys 0xTRUSTED_STORAGE_KEY \
  --output local_model/artifacts/source-storage-proof.json

cargo run --manifest-path tools/trie-verifier/Cargo.toml --release -- \
  --trusted-state-root 0xTRUSTED_STATE_ROOT_32_BYTES \
  --trusted-block-hash 0xTRUSTED_FINALIZED_BLOCK_32_BYTES \
  --state-version 1 \
  < local_model/artifacts/source-storage-proof.json
```

The placeholders are NOT usable data and this is **not a demonstrated Portaldot run**. Cross-check the exact genesis, inclusion block header and finalized state root outside the RPC being queried. Off-chain agreement of two values returned by the same malicious RPC is not authentication.

## Outstanding startup release blockers

- [ ] Official V3 RPC/genesis/consensus checkpoint and verified authority-set transition, SCALE header hash and finalized ancestry (#18/#27).
- [ ] Official source runtime metadata: contract storage layout, system/Contracts pallet keys, child trie ID/hasher and SCALE types. Derive keys from verified metadata, not manually guessed `storageMap` names.
- [ ] Verify nested child trie root proof anchored by independently finalized **top-level** state root if WASM contracts use child storage. The current implementation accepts top-level V0/V1 proofs only; do NOT incorrectly treat a child trie root as finalized top-level state root.
- [ ] Decode balances and beneficiary registration records with the exact source ABI at the same pinned checkpoint; reconcile all historical holders and zeros (#20–#24/#29).
- [ ] Genuine offline proof-bundle replay from independently gathered official node responses; coverage for runtime upgrades, leaf deletion, key collisions, archive availability and retention.
- [ ] Verify full Cargo.lock and security/audit posture for upstream trie verifier, including dependency provenance and reproducible binary hashes.
- [ ] Any asset migration must separately prove solvent EVM settlement, rate conservation and reviewer signoff (#34–#42).

**Release decision: NO-GO.** Unit tests of synthetic state roots cannot justify real token minting, crediting or claiming.
