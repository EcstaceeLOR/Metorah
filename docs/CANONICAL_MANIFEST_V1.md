# Metorah canonical manifest V1 — binary specification (issue #25)

**Protocol version: metorah-canonical-v1.** This is a production-intended **encoding specification under review**, NOT proof of Portaldot V3 finality, a trusted snapshot, asset solvency, or an operational bridge. The initial SHA-256 Python simulation and Keccak-256 sorted-pair Solidity claim ledger are **legacy formats and must never be silently treated as V1**.

## 1. Scope and supported rights

V1 supports **one fungible entitlement ledger per immutable asset and migration**. Entitlement kind is exactly `1`; units are nonnegative integer smallest units at the exact 0–18 decimal precision specified by the source. **Positive balances only** appear in leaves. Historical registry slots with zero balances remain in the source enumeration but receive no claim leaf. The manifest requires at least one positive holder and positive total supply; empty allocations are not supported.

The source owner is a **32-byte source AccountId**; the EVM beneficiary is an **independently source-registered 20-byte H160**. NEVER truncate the AccountId or infer its destination. A single destination address may legitimately receive multiple independently authorized source entitlements.

## 2. Endianness and JSON transport rules

All unsigned integers in the binary encoding are **fixed-width BIG-ENDIAN**. No variable-length integers, delimiters within fields, `abi.encode` 32-byte padding, JSON serialization or UTF-8 normalization are used in any hashed binary payload.

JSON is *transport representation*, not hashing input:

- All `bytes32` and H160 values use exactly `0x` followed by 64 or 40 **lowercase** hexadecimal digits; no all-zero critical identifiers, source owners or beneficiaries.
- `uint64` (`finalized_block_number`, `destination_chain_id`, `binding_nonce`) and `uint128` (`total_units`, `units`) use decimal **strings** without leading zeros, signs, exponent notation or fractions. They must be positive, within the native width. This prevents JavaScript double-precision loss.
- `uint32` counts and indexes, `uint8` entitlement kind/decimals use ordinary JSON integers (never booleans). Indexes may be zero; holder and active counts must be positive. `historical_holder_count >= active_holder_count`.
- Keys must match the schema exactly; no optional, duplicate, omitted or unknown header/leaf fields. For independent implementations, JSON parsers must explicitly reject **duplicate object keys** before schema validation.
- V1 encodes a source finalized block number as positive `uint64` regardless of native chain width; actual chain authenticity must be independently verified.

## 3. Immutable header fields (exact order, 286 bytes)

| Offset | Binary width | Field | Notes |
|---:|---:|---|---|
| 0 | 32 | source_genesis | Authenticated genesis required outside this codec |
| 32 | 32 | finalized_block_hash | Exact claimed freeze-cutoff block |
| 64 | 8 | finalized_block_number | uint64 big-endian |
| 72 | 32 | finalized_state_root | Independent source trie proof required |
| 104 | 32 | source_contract | WASM AccountId32 |
| 136 | 32 | source_code_hash | Immutable source code identification |
| 168 | 32 | migration_id | Distinct nonzero migration identifier |
| 200 | 32 | asset_id | Source asset identifier |
| 232 | 8 | destination_chain_id | uint64, positive |
| 240 | 20 | destination_contract | H160 claim/settlement contract |
| 260 | 1 | entitlement_kind | exactly 0x01 (fungible) |
| 261 | 1 | decimals | 0 to 18 inclusive |
| 262 | 4 | historical_holder_count | uint32, every ever-funded historical registry slot |
| 266 | 4 | active_holder_count | uint32, equals exact leaf count |
| 270 | 16 | total_units | uint128, strictly positive |

`header_hash = SHA256(ASCII("METORAH_HEADER_V1") || 0x00 || 286-byte header)`

The source chain genesis, exact cutoff block **and** state root, source contract/code hash, asset, migration ID, destination chain and settlement contract are therefore **part of every leaf's domain**. Supplying them does not authenticate them; that requires E3 chain evidence.

## 4. Canonical entitlement rows (exact order, 84 bytes each)

| Offset | Width | Field | Notes |
|---:|---:|---|---|
| 0 | 4 | leaf_index | uint32, exactly 0..N-1 without gaps |
| 4 | 4 | historical_index | uint32, strictly increasing, less than historical_holder_count |
| 8 | 32 | source_account | AccountId32, nonzero and unique across all leaves |
| 40 | 20 | beneficiary | Nonzero H160 authorized at the same frozen source checkpoint |
| 60 | 16 | units | Positive uint128 smallest units |
| 76 | 8 | binding_nonce | Positive uint64 from final source binding |

`leaf_hash = SHA256(ASCII("METORAH_LEAF_V1") || 0x00 || header_hash || 84-byte leaf)`

Rows are ordered by ascending **historical_index**, **not** SHA value, destination wallet or lexicographic source address. `leaf_index` is its zero-based position in the positive-entitlement list. Duplicate source accounts are forbidden, including accounts whose keys differ only by hex case (the JSON only admits lower case). Every source-derived positive balance requires **exactly one** row; this last completeness claim is established by verified source storage and finality (#27–#29), never by self-reporting manifest metadata.

Conservation: `sum(row.units) == header.total_units`, using checked wider-than-`uint128` intermediate arithmetic; any amount or aggregate greater than `2^128−1` is invalid. `len(rows) == header.active_holder_count`. Zero-balance historical entries are not included as claims.

## 5. Ordered Merkle tree, proofs and digest

- Pair adjacent hashes **left-to-right** in leaf-index order. **Do not sort** siblings by hash. `node_hash = SHA256(ASCII("METORAH_NODE_V1") || 0x00 || left32 || right32)`.
- **Odd-leaf rule:** if a layer has an unpaired last leaf/node, pair that value with an **identical duplicate** of itself. Repeat upward until a single 32-byte root. One-leaf root is that leaf hash; zero-leaf roots are invalid.
- A proof is a list of sibling hashes, bottom to top. Its orientation is **derived from leaf index and current layer width**, not a caller-supplied `side` string. If an odd layer has no sibling, the supplied sibling MUST equal the current node exactly. Proof length MUST equal the number of tree levels (`ceil(log2(N))`).
- `manifest_digest = SHA256(ASCII("METORAH_MANIFEST_V1") || 0x00 || header_hash || merkle_root)`.
- All V1 domain prefixes are literal byte strings with a **single trailing zero byte**. Never reuse the legacy `STATELIFT_LEAF_V1`, sorted Keccak, or `statelift/poc-v1/*` formats under this version.

The event/contract root and manifest digest may be used for a **candidate** root proposal. Neither is chain-authenticated until independent source header/finality and trie verification, complete holder-set proof, and destination escrow/settlement controls are integrated.

## 6. Shared synthetic parity vector — NOT a real migration

Input: 3 positive holders, 4 historical slots, source genesis 0x11 repeated 32 bytes, freeze block hash 0x22 repeated 32 bytes, block number 12345, state root 0x33 repeated 32 bytes, source contract 0x44 repeated 32 bytes, source code hash 0x55 repeated 32 bytes, migration ID 0x66 repeated 32 bytes, asset ID 0x77 repeated 32 bytes, destination chain ID 31337, destination contract 0x88 repeated 20 bytes, fungible kind 1, decimals 12, total units 90.

Rows: (leaf index, historical index, source account byte, beneficiary byte, units, nonce):

- (0, 0, aa×32, 11×20, 10, 1)
- (1, 2, bb×32, 22×20, 30, 2)
- (2, 3, cc×32, 33×20, 50, 1)

Exact SHA-256 expected values (lowercase without 0x; fixed constants independently checked by Python and Foundry):

```text
header      d8a338af8ac7ac775f65646714d3de231b3d679b1ba130bd83ad511fe3f400ba
leaf[0]     31fd1d1354ec4a31635782b658d76a7a24d9c568686a7063c110049b14da876f
leaf[1]     d6bafe136167850d2d43217a5e0fb0ff1a4ed6329a943aab062719c3296b746e
leaf[2]     3b2567bf18b77629a18970da6f354db9816d2497804bcd21c56669e34fab1b1f
node[0,1]   f6112ada26f352d1f304c5f44e1ba41f835e45d3e1d3f4413e879a5b5056e22f
node[2,2]   b50840082b5c970ae048310d964aa71e0802b1e4e5fc11439964ac9a3280f80d
merkle_root d1b8fe5f690cd868bd784a22e50c71c55593ff78f91dde76ffec919efe39a060
manifest    e8de0555b6a4dacbaeb2bee30fad6652341a00d4f83b932c02a07240390e217f
```

The `proof_for(..., 2)` for the last leaf contains its **own leaf hash** followed by node[0,1]; a different first sibling is rejected.

## 7. Implementation, legacy compatibility and activation gates

- Python implementation: `tools/manifest/canonical.py` with fail-closed `build`, `verify_manifest`, `proof_for` and `verify_proof`.
- Independent EVM parity: `src/MetorahManifestV1.sol` and `test/MetorahManifestV1.t.sol`. The Solidity harness is **pure, not a root-authority or escrow contract**.
- Regression tests: `python -m unittest discover -s test -p test_manifest_v1.py -v` and `forge test --match-contract MetorahManifestV1ParityTest -vvv`. Full CI also tests the original legacy model unchanged.
- The existing `src/MetorahClaimLedger.sol` still uses sorted Keccak and an administrator-chosen root. **DO NOT feed V1 proofs into it.** Replacing/wrapping this claim path must be a separately reviewed issue #26 change with cross-language parity, comprehensive claimant replay tests, source-root authorization and economic solvency gates (#36–#41).
- Successful parity tests are **E1 (encoding-only)**. They do NOT establish Portaldot V3 origin, actual freeze finality, complete on-chain storage enumeration, authenticated recipient registration, independent operator threshold signatures or redeemable assets.

**Release decision:** NO-GO for customer funds until all source and destination chain proofs, authority and backing are independently verified and reviewed.
