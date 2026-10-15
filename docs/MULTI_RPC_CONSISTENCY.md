# Multi-RPC consistency and reorganization defense — Issue #30

**Development status: source checkpoint and storage *consistency only*.** This is NOT source authentication, a signed finality proof, or economic approval. A matching group of RPC endpoints can still collude, use the same backend, or serve false data consistently.

## Problem and strategy

A migration cannot safely use one provider's "finalized" label, read one batch of balances, switch to a different block root on reconnect, and publish a Merkle tree. Metorah requires an exact user/owner-approved checkpoint and fail-closed cross-provider consistency throughout indexing and resume.

The new \`tools/finality/quorum.py\` requires **at least three configured RPC provider identities and operator groups** with at least **two independently declared operators** providing valid, agreeing observations. Duplicate declared operator IDs are rejected. Operator independence is CONFIGURATION CLAIM ONLY; independent legal ownership, server topology and shared upstream backend MUST be verified outside this module.

The adapter uses the existing #27 RPC header observer for each operator. It checks expected genesis, pinned block hash/height, the full reported finalized-head ancestry to the pinned block, state root, extrinsics root, runtime version and the **SHA-256 checksum of actual \`state_getMetadata(checkpoint)\` bytes**. Runtime metadata bytes are never fetched at the moving best head. Each responding provider must match the others on the entire pinned tuple. A disagreement is a security error even if two other endpoints form a majority.

The RPC methods are explicitly allowlisted. This does not prove the SCALE-encoded header hash or verify GRANDPA/BEEFY consensus signatures (#27). The \`state_getMetadata\` checksum does not authenticate metadata against the source runtime or governance. Storage-key derivation still requires independent supported runtime metadata review (#28).

### Split-brain and stale finality behavior

- Different state roots, checkpoint heights, extrinsics roots, runtime metadata/version or genesis claims block the scan.
- Two providers reporting different finalized block hashes at the **same finalized height** block the scan.
- Different finalized heights are allowed **only** within the explicit \`--max-head-delta\` tolerance and only when both individually attest that the *same nominated checkpoint* is an ancestor. A stale provider outside that bound blocks all acquisition.
- Even when heads differ within this tolerance, every responding operator must report the SAME canonical block hash at their lowest common finalized height. A fork hidden by staggered finalized heights is rejected.
- A provider's reported finalized height cannot decrease between observations. Finality advances at the moving head do not silently change the storage-read checkpoint.
- Wrong-chain, fork, missing-header and malformed responses are treated as **semantic failures** and block the scan. Only explicit network/transport errors may be excluded as temporary outages; failed providers never cast votes for a partial batch.
- A single network outage is tolerated with at least two remaining independent agreeing and *post-read revalidated* RPC responses. Fewer than two complete votes results in a nonzero failure, leaving only previously committed batches in the journal.
- This policy is intentionally conservative: a correctly advancing chain might trigger a transient scan rejection at one endpoint; rerunning the exact same pinned checkpoint is safer than changing snapshot identity during cutover.

### Resumable, fail-closed acquisition

\`ResumableAcquisition\` accepts strictly increasing, unique, lowercase hex raw storage keys and reads in bounded pages of at most 64 keys. It never invents or guesses chain storage keys.

Every batch:

1. Obtains a fresh multi-RPC pinned-header/runtime metadata consensus.
2. Reads *each requested key* with \`state_getStorage(key, checkpointHash)\` through the hash-locked #27 reader, never an unpinned "latest" call.
3. Requires every responding provider to agree on all values, including the distinction between \`null\` (absent) and \`"0x"\` (present empty bytes). A partial or timed-out provider casts no vote.
4. Rechecks reported head/ancestry/root/runtime metadata **after** the read; votes only from providers passing both checks count.
5. Atomically journals the entire complete batch, bound to a fingerprint of the genesis, block, state root, extrinsics root, runtime metadata checksum, full key list, batch size, declared operators and quorum/lag policies.

On resume, the plan digest must match **exactly**, no registry/metadata change is permitted, and **all previously saved keys are read again from a fresh quorum**. A resumed process cannot append data from another block, root, key plan or runtime to an existing journal. The SHA-256 seal is an *accidental corruption checksum*, not an adversary-resistant signature. Even someone able to recompute that checksum cannot change stored values without failing an independent fresh RPC comparison, assuming at least two honest uncolluding respondents.

The journal also stores each provider's **highest previously reported finalized height**. A restarted process refuses a regressed finality height even if the original freeze checkpoint is still present in both histories; this guard survives process crashes and operator retries.

A finished report says only \`MULTI_RPC_STORAGE_CONSISTENT_UNAUTHENTICATED\`. Its flags are always:
\`genesis_authenticated=false\`, \`finality_cryptographically_verified=false\`, \`trie_membership_verified=false\`, \`operator_independence_verified=false\`, \`can_activate=false\`, \`can_claim=false\`.

### Resource and secret boundaries

- 3–9 endpoints, configurable quorum at least 2.
- 1–4096 storage keys per plan, 1–64 keys per batch, at most 1 MiB raw bytes per returned value.
- Bounded 0–4096 height ancestry checks via #27, configurable max finalized-head offset 0–64 blocks, and a hard 16 MiB journal limit; large key plans must be partitioned without changing the pinned checkpoint.
- Remote RPC addresses require HTTPS with the standard OS certificate validator, no embedded credentials/query strings or HTTP redirects. Plain HTTP permitted only for loopback development.
- No transaction signing, wallet connection, claim authorizations or root approvals.
- The journal and report store **raw source values**; treat them as potentially confidential data, never log them publicly or commit customer details. Restrict filesystem permissions and storage access.
- The CLI only operates when \`--enable-network\` is explicitly provided, never assumes any live Portaldot V3 endpoint or genesis, and never silently overwrites a completed report.

### Offline chaos suite

\`\`\`sh
python -m unittest discover -s test -p test_multi_rpc_consistency.py -v
python -m unittest discover -s test -p test_multi_rpc_cli.py -v
\`\`\`

The suite simulates conflicting state roots, same-height fork splits, honest finalized-head lag, malicious version/metadata, deliberate storage equivocation, false absences, lost network quorum, reorg during read, silent block drift, corrupted journals, interrupted acquisition and subsequent successful resume. It uses only deterministic synthetic RPC fixtures and **NO public RPC**.

### Live use (only after trust-anchor review)

A provider configuration JSON file contains e.g.

\`\`\`json
{"operators":[
  {"provider_id":"rpc-a","operator_id":"independent-a","url":"https://APPROVED_OPERATOR_A"},
  {"provider_id":"rpc-b","operator_id":"independent-b","url":"https://APPROVED_OPERATOR_B"},
  {"provider_id":"rpc-c","operator_id":"independent-c","url":"https://APPROVED_OPERATOR_C"}
]}
\`\`\`

A separate \`keys.json\` file is a sorted JSON array of **exact actual storage-key bytes** derived from independently confirmed runtime metadata, e.g. \`["0x01020304"]\` for *synthetic* test data only.

\`\`\`sh
python tools/finality/multirpc_acquire.py \
  --enable-network \
  --providers providers.json \
  --storage-keys keys.json \
  --expected-genesis 0xTRUSTED_GENESIS_H256 \
  --checkpoint 0xEXACT_FINALIZED_CHECKPOINT_H256 \
  --min-quorum 2 --max-head-delta 2 --batch-size 32 \
  --journal local_model/artifacts/source-acquisition.journal.json \
  --output local_model/artifacts/multirpc-observation.json
\`\`\`

The placeholders above are deliberately unusable: there is **no pre-approved Portaldot V3 endpoint** or real checkpoint hardcoded. To resume after a permitted outage, rerun the command with the *same* operators, keys, genesis, checkpoint, policy and journal. If a completed report already exists, use a new output path after independent review, not an overwrite.

## Hard blockers before production

1. **Official chain identity, independently authenticated consensus finality, trusted SCALE header hashes/authority rotation**: still required (#18/#27). Multiple matching RPC labels are not a signature.
2. **Exact runtime-dependent storage keys, nested Contracts child-trie anchored proof and signed beneficiary mapping**: still required (#28–#29). Raw \`state_getStorage\` does not cryptographically prove membership. Pass these raw bytes through the isolated Parity verifier only after the trusted source state root and metadata are established.
3. **Actual operator independence** is not proven by the configured \`operator_id\` field; diverse infrastructure and out-of-band owner identities must be verified.
4. **Integrate cutover authority, replay-protected signed reports and auditable checkpoint/claim release conditions** (#31–#42).
5. **Real chaos evidence from approved independent V3 nodes**, ideally with a controlled fork/stale/malicious provider, must be archived and reviewed; local fixtures are never equivalent.

**Decision: NO-GO for source entitlement activation or asset movement.** Engineering consistency tests may pass and still have nothing to do with the authentic live source state.
