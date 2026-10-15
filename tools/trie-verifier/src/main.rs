//! Offline root-relative Substrate storage proof verification.
//! This DOES NOT verify who supplied the root, block, runtime, or storage key.
//! No RPC, key material, or asset-release path exists in this binary.

use serde::{Deserialize, Serialize};
use sp_core::{Blake2Hasher, H256};
use sp_trie::{verify_trie_proof, LayoutV0, LayoutV1};
use std::collections::BTreeSet;
use std::io::{self, Read};

const MAX_INPUT: u64 = 2 * 1024 * 1024;
const MAX_NODES: usize = 512;
const MAX_ITEMS: usize = 256;
const MAX_NODE_BYTES: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageItem {
    pub key: String,
    /// Null requests a *non-inclusion* proof, not a proof of the zero value.
    pub value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofEnvelope {
    pub schema_version: String,
    pub block_hash: String,
    pub state_root: String,
    pub state_version: u8,
    pub nodes: Vec<String>,
    pub items: Vec<StorageItem>,
}

#[derive(Debug, Serialize)]
pub struct ProofResult {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub proven_item_count: usize,
    pub node_count: usize,
    pub state_version: u8,
    pub genesis_authenticated: bool,
    pub root_authenticated_by_finality: bool,
    pub keys_authenticated_by_runtime_metadata: bool,
    pub contract_storage_decoded: bool,
    pub can_activate: bool,
    pub can_claim: bool,
}

pub fn parse_hex(source: &str, name: &str, allow_empty: bool) -> Result<Vec<u8>, String> {
    if !source.starts_with("0x") || source.len() % 2 != 0 {
        return Err(format!("INVALID_{name}_HEX"));
    }
    if !source[2..].bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        return Err(format!("INVALID_{name}_HEX"));
    }
    let result = hex::decode(&source[2..]).map_err(|_| format!("INVALID_{name}_HEX"))?;
    if result.is_empty() && !allow_empty {
        return Err(format!("EMPTY_{name}"));
    }
    Ok(result)
}

pub fn parse_h256(value: &str, name: &str) -> Result<H256, String> {
    let bytes = parse_hex(value, name, false)?;
    if bytes.len() != 32 || bytes.iter().all(|b| *b == 0) {
        return Err(format!("INVALID_{name}_HASH"));
    }
    Ok(H256::from_slice(&bytes))
}

pub fn verify(
    proof: ProofEnvelope,
    expected_root: H256,
    expected_block: H256,
    expected_version: u8,
) -> Result<ProofResult, String> {
    if proof.schema_version != "metorah-substrate-storage-proof-v1" {
        return Err("UNSUPPORTED_PROOF_SCHEMA".into());
    }
    if proof.state_version != expected_version || !matches!(expected_version, 0 | 1) {
        return Err("TRIE_LAYOUT_NOT_AUTHORIZED".into());
    }
    if parse_h256(&proof.state_root, "ROOT")? != expected_root {
        return Err("STATE_ROOT_MISMATCH".into());
    }
    if parse_h256(&proof.block_hash, "BLOCK")? != expected_block {
        return Err("PINNED_BLOCK_MISMATCH".into());
    }
    if proof.nodes.is_empty() || proof.nodes.len() > MAX_NODES {
        return Err("INVALID_PROOF_NODE_COUNT".into());
    }
    if proof.items.is_empty() || proof.items.len() > MAX_ITEMS {
        return Err("INVALID_PROOF_ITEM_COUNT".into());
    }
    let mut seen_nodes = BTreeSet::new();
    let mut nodes = Vec::with_capacity(proof.nodes.len());
    let mut total_node_bytes = 0usize;
    for item in &proof.nodes {
        let bytes = parse_hex(item, "NODE", false)?;
        if bytes.len() > MAX_NODE_BYTES || bytes.is_empty() {
            return Err("PROOF_NODE_TOO_LARGE".into());
        }
        total_node_bytes = total_node_bytes.checked_add(bytes.len()).ok_or("PROOF_NODE_OVERFLOW")?;
        if total_node_bytes > MAX_INPUT as usize {
            return Err("PROOF_TOO_LARGE".into());
        }
        if !seen_nodes.insert(bytes.clone()) {
            return Err("DUPLICATE_PROOF_NODE".into());
        }
        nodes.push(bytes);
    }
    let mut comparisons: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::with_capacity(proof.items.len());
    let mut previous: Option<Vec<u8>> = None;
    for item in &proof.items {
        let key = parse_hex(&item.key, "KEY", false)?;
        if key.len() > 1024 {
            return Err("STORAGE_KEY_TOO_LARGE".into());
        }
        if previous.as_ref().is_some_and(|v| v >= &key) {
            return Err("UNORDERED_OR_DUPLICATED_STORAGE_KEY".into());
        }
        let value = match &item.value {
            Some(v) => {
                let bytes = parse_hex(v, "VALUE", true)?;
                if bytes.len() > MAX_NODE_BYTES {
                    return Err("STORAGE_VALUE_TOO_LARGE".into());
                }
                Some(bytes)
            }
            None => None,
        };
        previous = Some(key.clone());
        comparisons.push((key, value));
    }
    let checked = if expected_version == 0 {
        verify_trie_proof::<LayoutV0<Blake2Hasher>, _, _, _>(&expected_root, &nodes, &comparisons)
    } else {
        verify_trie_proof::<LayoutV1<Blake2Hasher>, _, _, _>(&expected_root, &nodes, &comparisons)
    };
    checked.map_err(|_| "INVALID_STORAGE_TRIE_PROOF".to_string())?;
    Ok(ProofResult {
        schema_version: "metorah-storage-proof-result-v1",
        status: "TRIE_PROOF_VALID_FOR_SUPPLIED_ROOT_UNAUTHENTICATED",
        proven_item_count: comparisons.len(),
        node_count: nodes.len(),
        state_version: expected_version,
        genesis_authenticated: false,
        root_authenticated_by_finality: false,
        keys_authenticated_by_runtime_metadata: false,
        contract_storage_decoded: false,
        can_activate: false,
        can_claim: false,
    })
}

fn usage() -> &'static str {
    "Usage: metorah-trie-verifier --trusted-state-root 0x... --trusted-block-hash 0x... --state-version 0|1 < proof.json\n\
     CAUTION: CLI flags do not establish actual trusted finality."
}
fn run() -> Result<ProofResult, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 ||
        args[1] != "--trusted-state-root" ||
        args[3] != "--trusted-block-hash" ||
        args[5] != "--state-version" {
        return Err(usage().into());
    }
    let root = parse_h256(&args[2], "ROOT")?;
    let block = parse_h256(&args[4], "BLOCK")?;
    let version: u8 = args[6].parse().map_err(|_| "INVALID_STATE_VERSION")?;
    if version > 1 { return Err("UNSUPPORTED_STATE_VERSION".into()); }
    let mut stdin = io::stdin().take(MAX_INPUT + 1);
    let mut input = Vec::new();
    stdin.read_to_end(&mut input).map_err(|_| "PROOF_STDIN_READ_FAILED")?;
    if input.len() as u64 > MAX_INPUT {
        return Err("PROOF_INPUT_TOO_LARGE".into());
    }
    let proof: ProofEnvelope = serde_json::from_slice(&input)
        .map_err(|_| "INVALID_PROOF_ENVELOPE")?;
    verify(proof, root, block, version)
}

fn main() {
    match run() {
        Ok(report) => {
            println!("{}", serde_json::to_string(&report).expect("serialized fixed report"));
        },
        Err(error) => {
            eprintln!("TRIE_VERIFICATION_FAILED: {error}");
            std::process::exit(2);
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_trie::{generate_trie_proof, MemoryDB, TrieDBMutBuilder, TrieMut};

    fn h(value: H256) -> String { format!("0x{}", hex::encode(value.as_bytes())) }
    fn x(bytes: &[u8]) -> String { format!("0x{}", hex::encode(bytes)) }

    fn sample(version: u8) -> (ProofEnvelope, H256, H256) {
        let key_one = vec![0x11, 0x22];
        let key_two = vec![0x22, 0x33];
        let value_one = vec![0xa1; 48];
        let value_two = vec![0xb2; 40];
        let missing = vec![0xff, 0xdd];
        let mut db: MemoryDB<Blake2Hasher> = MemoryDB::default();
        let mut root = H256::default();
        let nodes = if version == 0 {
            {
                let mut trie = TrieDBMutBuilder::<LayoutV0<Blake2Hasher>>::new(&mut db, &mut root).build();
                trie.insert(&key_one, &value_one).unwrap();
                trie.insert(&key_two, &value_two).unwrap();
            }
            generate_trie_proof::<LayoutV0<Blake2Hasher>, _, _, _>(
                &db, root, &[key_one.clone(), missing.clone()]
            ).unwrap()
        } else {
            {
                let mut trie = TrieDBMutBuilder::<LayoutV1<Blake2Hasher>>::new(&mut db, &mut root).build();
                trie.insert(&key_one, &value_one).unwrap();
                trie.insert(&key_two, &value_two).unwrap();
            }
            generate_trie_proof::<LayoutV1<Blake2Hasher>, _, _, _>(
                &db, root, &[key_one.clone(), missing.clone()]
            ).unwrap()
        };
        let block = H256::repeat_byte(0x33);
        (ProofEnvelope {
            schema_version: "metorah-substrate-storage-proof-v1".into(),
            block_hash: h(block),
            state_root: h(root),
            state_version: version,
            nodes: nodes.iter().map(|v| x(v)).collect(),
            items: vec![
                StorageItem { key: x(&key_one), value: Some(x(&value_one)) },
                StorageItem { key: x(&missing), value: None },
            ],
        }, root, block)
    }
    #[test]
    fn v0_and_v1_real_substrate_tries_verify_inclusion_and_noninclusion() {
        for version in [0, 1] {
            let (p, root, block) = sample(version);
            let report = verify(p, root, block, version).unwrap();
            assert_eq!(report.proven_item_count, 2);
            assert!(!report.can_activate && !report.can_claim);
            assert!(!report.root_authenticated_by_finality);
            assert!(!report.keys_authenticated_by_runtime_metadata);
        }
    }
    #[test]
    fn changed_value_or_key_is_rejected_by_real_trie_verifier() {
        for version in [0, 1] {
            let (mut p, root, block) = sample(version);
            p.items[0].value = Some("0xff".into());
            assert!(verify(p, root, block, version).is_err());
            let (mut p, root, block) = sample(version);
            p.items[0].key = "0x1123".into();
            assert!(verify(p, root, block, version).is_err());
        }
    }
    #[test]
    fn forged_root_or_block_rejected_prior_to_proof_check() {
        let (p, _root, block) = sample(1);
        assert_eq!(verify(p, H256::repeat_byte(0x55), block, 1).unwrap_err(), "STATE_ROOT_MISMATCH");
        let (p, root, _) = sample(1);
        assert_eq!(verify(p, root, H256::repeat_byte(0x44), 1).unwrap_err(), "PINNED_BLOCK_MISMATCH");
    }
    #[test]
    fn wrong_state_version_is_not_fallback_autodetected() {
        let (p, root, block) = sample(1);
        assert_eq!(verify(p, root, block, 0).unwrap_err(), "TRIE_LAYOUT_NOT_AUTHORIZED");
    }
    #[test]
    fn missing_nodes_duplicate_nodes_and_wrong_absence_rejected() {
        let (mut p, root, block) = sample(1);
        p.nodes.clear();
        assert!(verify(p, root, block, 1).is_err());
        let (mut p, root, block) = sample(1);
        p.nodes.push(p.nodes[0].clone());
        assert_eq!(verify(p, root, block, 1).unwrap_err(), "DUPLICATE_PROOF_NODE");
        let (mut p, root, block) = sample(1);
        p.items[0].value = None;  // must NOT allow missing assertion on included key
        assert!(verify(p, root, block, 1).is_err());
    }
    #[test]
    fn duplicate_or_unsorted_keys_cannot_be_hidden_in_batch() {
        let (mut p, root, block) = sample(1);
        p.items.push(StorageItem {key:"0xffdd".into(), value:None});
        assert_eq!(verify(p, root, block, 1).unwrap_err(), "UNORDERED_OR_DUPLICATED_STORAGE_KEY");
    }
    #[test]
    fn malformed_noncanonical_hex_or_zero_root_fails_closed() {
        assert!(parse_hex("0xAABB", "NODE", false).is_err());
        assert!(parse_hex("AABB", "NODE", false).is_err());
        assert!(parse_h256(&format!("0x{}", "00".repeat(32)), "ROOT").is_err());
    }
}
