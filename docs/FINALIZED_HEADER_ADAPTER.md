# Portaldot / Substrate finalized-header acquisition — Issue #27

**Status: implemented a bounded Substrate RPC observation adapter and fail-closed consistency validator. Cryptographic finality is NOT implemented and official Portaldot V3 chain identity is NOT established.** This is a startup product security boundary; the adapter is intentionally unusable as a proof-to-mint or claim trigger.

## Source network / verification prerequisites

Portaldot advertises a Substrate-derived chain and V3 EVM/WASM capabilities, but a project cannot infer that a random publicly listed node, hosted developer site, legacy chain-spec JSON or a third-party dev endpoint represents the correct, officially supported V3 network. Do **not** embed a guessed endpoint or genesis hash, connect to a production wallet, or treat a mock fixture as V3.

Before **live** acceptance, obtain through independent approved channels:

1. Exact V3 network identity and trusted genesis/checkpoint hash; document chain spec and expected network/runtime upgrade version.
2. The supported V3 Substrate JSON-RPC interface and reachable RPC URLs, with HTTPS where remote. Prefer independently operated providers.
3. Consensus/finality format, authority set, trust-anchor rotation, runtime code hash and upgrade governance. A trusted verifier must check the actual finalized header's SCALE hash, GRANDPA/BEEFY/other mechanism proof signatures and the ancestor relationship cryptographically.
4. Storage trie format, finalized state root, archive retention, source contract code and complete beneficiary/registry storage verification (#28–#29).
5. The release policy must reject missing proof material instead of turning an observed RPC label into an E3 permission.

No V3 endpoints or genesis are hardcoded. **The adapter's observed metadata is not a trusted root.**

## Implementation

- \`tools/finality/substrate.py\`: acquire \`chain_getBlockHash(0)\`, \`chain_getFinalizedHead\`, \`chain_getHeader(hash)\`, \`chain_getBlockHash(height)\`, \`state_getRuntimeVersion(checkpointHash)\`. Explicitly configure *expected* genesis and exact checkpoint hash; no default "latest". The process walks **every header** from RPC-reported finalized head down to the checkpoint and compares each parent link's height and canonical hash returned by the same RPC. This is bounded by \`max_finalized_lag\` (default 256, hard cap 4096 links).
- Reject wrong genesis, header missing/invalid, future or old checkpoint, mismatching height mapping, orphaned side fork, shortened/broken ancestry, incorrectly typed runtime metadata, RPC errors, changed finalized head, changed genesis and changed checkpoint state root during a single scan.
- \`PinnedStateReader\` forces each \`state_getStorage(key, checkpointHash)\` request to pass the **exact block hash** selected by the reader, not the node's moving best head. It validates hex storage values and records keys read. The storage bytes are UNAUTHENTICATED until trie proof verification (#28).
- \`tools/finality/http_rpc.py\` implements an intentionally small read-only HTTP(S) JSON-RPC transport with method allowlist, response-byte cap, HTTPS certificate verification through standard Python, bounded timeout, rejected redirects, no URLs with user credentials/query strings, rejected duplicate JSON keys and correlated JSON-RPC request IDs. External plain HTTP is rejected; loopback HTTP is permitted for an isolated developer node.
- \`tools/finality/acquire.py\` is a manual opt-in CLI; it exits without contacting any node unless \`--enable-network\` is supplied, and requires explicit \`--rpc-url\`, \`--expected-genesis\`, \`--checkpoint\` and output path. There is no transaction/signing/broadcast implementation.

**Conservatism:** if a legitimate finalized head advances while the RPC sequence is being checked, the adapter currently rejects the run and requires restarting a fresh pinned observation. An archive snapshot too far behind the head is rejected by the configured **block-height lag policy**, not by wall-clock seconds. Operators must use a suitably verified historical checkpoint workflow for old migrations rather than silently lift the limit.

## Safe command (do not run against an unverified provider)

\`\`\`sh
# Read-only *only after* the independently verified endpoint, genesis and block
# hash are available. No private keys or real-value transactions are involved.
python tools/finality/acquire.py \
  --enable-network \
  --rpc-url https://VERIFIED_RPC_HOST \
  --expected-genesis 0xVERIFIED_32_BYTE_GENESIS \
  --checkpoint 0xEXACT_32_BYTE_FREEZE_BLOCK \
  --max-finalized-lag 256 \
  --output local_model/artifacts/finality-observed.json
\`\`\`

This command is a parameter template, NOT an actual run. The placeholder values must be replaced by operator-verified data; there is no preapproved default RPC. Do not commit real credentials in URLs. Fixture tests are completely offline:

\`\`\`sh
python -m unittest discover -s test -p test_finalized_headers.py -v
python -m unittest discover -s test -p test_finality_transport.py -v
\`\`\`

## Evidence and limitations

Successful report schema: \`metorah-finality-observation-v1\`, status **FINALIZED_HEADER_OBSERVED_UNAUTHENTICATED**. It includes reported genesis, pinned checkpoint hash/height/state root/extrinsics root, reported finalized head hash/height/root, runtime spec metadata, observed ancestry link count, block-height lag and **diagnostic SHA-256 only**. All authority, cryptographic header-hash, source trie, and claim/activation statuses remain **false**.

An attacker controlling RPC can return coherent fabricated genesis, finalized header, ancestry and state root. Therefore a report from *this* module cannot be promoted to finality-proof, source entitlement proof, signed migration root or economic settlement authority. It is strictly observation/candidate evidence, even if all offline consistency checks pass. A finalized-head RPC response by itself says nothing about consensus.

### Dependency and exit criteria

- **Implemented locally:** strict pinned read-only acquisition, bounded ancestry and common reorg/fork detection, explicit network opt-in and adversarial tests.
- **Still blocked:** officially verified Portaldot V3 endpoint/genesis/runtime (#18), actual chain observations, independently verified consensus finality signatures/hash/authority changes (#27) and trie proof verification (#28–#29), freeze/holder reconciliation and destination solvency (#20–#24, #36–#41).
- Required for closure: independently obtained and tested real node responses with known finalized headers **and** auditable trust-anchor bootstrap. Unsupported consensus verification may require adding the appropriate maintained Rust light-client verifier and audited verification source.

**Policy:** no production funds, no approved root, no claim entitlement, no auto-merge of a report into release status based on RPC consistency alone.


## Issue #28 storage proof boundary

Read-only `state_getReadProof` support and a standalone Parity `sp-trie` V0/V1 verifier are now under development in [STORAGE_TRIE_VERIFICATION.md](STORAGE_TRIE_VERIFICATION.md). Their output cannot upgrade an RPC-reported root into trusted finality or decode unverified Contracts pallet storage. The full #27 trust anchor remains essential.
