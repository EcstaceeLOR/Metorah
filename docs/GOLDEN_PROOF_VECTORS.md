# Metorah four-language golden vectors — Issue #26

**Version:** metorah-golden-v1, referencing the frozen binary \`metorah-canonical-v1\` encoding specified in [CANONICAL_MANIFEST_V1.md](CANONICAL_MANIFEST_V1.md).

**Assurance: E1 encoding parity ONLY.** No Portaldot V3 deployment, real signed chain transaction, authenticated finalized state/root, source trie evidence or destination claim/escrow is asserted. All accounts, headers and holder balances below are **synthetic public data**, never real identities or user funds.

## Deterministic fixture derivation

Tracked artifact: \`fixtures/manifest-v1/golden.json\`. It has fixed expected header SHA-256, first and last leaf SHA-256, manifest digest, Merkle root, and **actual ordered sibling hashes** for each representative proof. It intentionally contains only the first and last leaf/path for the 257-holder case rather than 257 lengthy copies; all four languages independently derive **every** of the 257 leaves and the full root from the seed rule.

The normative generator is \`tools/manifest/generate_golden.py\`; \`--check\` fails if tracked vector bytes drift. Do not update vectors merely to fix a failing verifier. A protocol change requires a new version, explicit ADR and independent cross-language review.

Fixture population sizes: **1, 2, 3, and 257** positive entitlement holders. Each fixture includes historical gaps/tombstones by setting \`historical_index = i + floor(i/8)\`; \`historical_holder_count = N + floor((N-1)/8) + 1\`. For every \`i in 0..N-1\`:

- source account is a 32-byte value whose **last four bytes** are \`uint32_be(i+1)\`; preceding 28 bytes are zero.
- EVM beneficiary is a 20-byte H160 whose **last four bytes** are \`uint32_be(i+1001)\`; preceding 16 bytes are zero.
- entitlement amount is \`uint128((i+1)*(i+11))\` smallest units, binding nonce \`uint64(1 + (i mod 3))\`, leaf index is \`i\`.
- source genesis = 0x11 repeated 32 bytes, cutoff block = 0x22 repeated 32, block height = 12345, state root = 0x33 repeated 32, source contract = 0x44 repeated 32, source code hash = 0x55 repeated 32, migration ID = 0x66 repeated 32, asset ID = 0x77 repeated 32, destination EVM chain ID = 31337, destination contract = 0x88 repeated 20 bytes, fungible entitlement kind = 1 and decimals = 12.

The resulting header is 286 bytes; each leaf 84 bytes, big-endian fixed integers; SHA-256 domain prefixes end with a literal zero byte. Leaves pair **positionally**, with self-duplication of unmatched last node. Headers/leaves are never JSON-hashed. No SHA-3, sorted-pair Merkle proofs, legacy StateLift proof domains, or truncated AccountId-to-H160 conversions.

## Four independent verification implementations

| Language | Implementation | CI regression |
| --- | --- | --- |
| Python | \`tools/manifest/canonical.py\` + \`generate_golden.py\` | \`test/test_manifest_v1.py\`, \`test/test_golden_vectors.py\`, generator \`--check\` |
| TypeScript | \`tools/manifest/canonical_v1.ts\` using Node 24 built-in TS stripping and native \`crypto\` SHA-256, no dependency install | \`tools/manifest/canonical_v1.test.ts\` |
| Rust | \`contracts/wasm/source-ledger/golden_manifest.rs\`, independent field serialization and \`ink::env::hash_bytes<Sha2x256>\`, no Cargo.lock changes | \`cargo test --manifest-path contracts/wasm/source-ledger/Cargo.toml --locked\` |
| Solidity | \`src/MetorahManifestV1.sol\` V1 pure library used by \`test/MetorahManifestGoldenV1.t.sol\`; independent chain-side SHA-256 precompile | \`forge test --match-contract MetorahManifestGoldenV1Test -vvv\` |

Tests verify exact header, leaf, root and manifest digest constants; positional paths (including last-node odd duplication); wrong proof depth; altered beneficiary, source AccountId, index, units, registration nonce, contract, chain and migration ID; reordered/duplicate accounts; balance overflow/counter mismatch. The 257-holder case tests real multi-level proof depth and odd-last-node behavior.

## Local reproduction commands

\`\`\`sh
python tools/manifest/generate_golden.py --check
python -m unittest discover -s test -p test_golden_vectors.py -v
node --experimental-strip-types --test tools/manifest/canonical_v1.test.ts
cargo test --manifest-path contracts/wasm/source-ledger/Cargo.toml --locked golden_manifest
forge test --match-contract MetorahManifestGoldenV1Test -vvv
\`\`\`

Do not try to feed these V1 positional SHA-256 proofs to the legacy administrator-controlled \`MetorahClaimLedger.sol\` (sorted Keccak). Real destination V1 integration requires separate review and explicit chain proof/escrow gates. The artifact's \`source_chain_authenticated\`, \`can_activate\` and \`can_claim\` values stay **false** for all synthetic fixtures.

## Failure handling

A mismatch between even one language and a tracked root/leaf/proof MUST fail CI. Do not silently replace fixtures with the new output. Check whether a platform used little-endian integers, ABI-padded vs packed fields, sorted Keccak vs positional SHA-256, uint128 rounding, noncanonical addresses, missing binding nonce, duplicate-last placement, or different chain/contract domain.

**Security restriction:** this is deterministic cross-language computation, not a protocol audit or proof of economic correctness. A valid hash/root for false source data is still false data. Real chain finality/trie proofs and destination solvent settlement remain mandatory release gates.
