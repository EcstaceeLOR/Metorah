//! Independent SHA-256 Rust golden fixture implementation for issue #26.
//! Does not authorize claim roots, attest to chain finality or use real assets.
//! SHA-256 uses ink! runtime-compatible hashing with no new dependencies.
use ink::env::hash::Sha2x256;
use std::vec::Vec;

const HEADER: &[u8] = b"METORAH_HEADER_V1\0";
const LEAF: &[u8] = b"METORAH_LEAF_V1\0";
const NODE: &[u8] = b"METORAH_NODE_V1\0";
const MANIFEST: &[u8] = b"METORAH_MANIFEST_V1\0";

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    ink::env::hash_bytes::<Sha2x256>(bytes, &mut digest);
    digest
}
fn hash_of(tag: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    let mut bytes = Vec::from(tag);
    for part in chunks { bytes.extend_from_slice(part); }
    sha256(&bytes)
}
fn header_bytes(n: u32) -> Vec<u8> {
    let historical = n + (n - 1) / 8 + 1;
    let total: u128 = (0..n).map(|i| (u128::from(i) + 1) * (u128::from(i) + 11)).sum();
    let mut b = Vec::new();
    b.extend_from_slice(&[0x11; 32]); // source genesis
    b.extend_from_slice(&[0x22; 32]); // block hash
    b.extend_from_slice(&12345u64.to_be_bytes());
    b.extend_from_slice(&[0x33; 32]); // state root
    b.extend_from_slice(&[0x44; 32]); // source contract
    b.extend_from_slice(&[0x55; 32]); // source code
    b.extend_from_slice(&[0x66; 32]); // migration
    b.extend_from_slice(&[0x77; 32]); // asset
    b.extend_from_slice(&31337u64.to_be_bytes());
    b.extend_from_slice(&[0x88; 20]); // H160 destination contract
    b.push(1); // entitlement kind
    b.push(12); // source decimals
    b.extend_from_slice(&historical.to_be_bytes());
    b.extend_from_slice(&n.to_be_bytes());
    b.extend_from_slice(&total.to_be_bytes());
    assert_eq!(b.len(), 286);
    b
}
fn leaf_bytes(i: u32, beneficiary_override: Option<u32>) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&i.to_be_bytes());
    b.extend_from_slice(&(i + i / 8).to_be_bytes());
    let mut source = [0u8; 32];
    source[28..].copy_from_slice(&(i + 1).to_be_bytes());
    b.extend_from_slice(&source);
    let mut beneficiary = [0u8; 20];
    beneficiary[16..].copy_from_slice(&beneficiary_override.unwrap_or(i + 1001).to_be_bytes());
    b.extend_from_slice(&beneficiary);
    b.extend_from_slice(&((u128::from(i) + 1) * (u128::from(i) + 11)).to_be_bytes());
    b.extend_from_slice(&(u64::from(i % 3) + 1).to_be_bytes());
    assert_eq!(b.len(), 84);
    b
}
fn leaf_hash(header_hash: &[u8; 32], i: u32, override_beneficiary: Option<u32>) -> [u8; 32] {
    hash_of(LEAF, &[header_hash, &leaf_bytes(i, override_beneficiary)])
}
fn node_hash(l: [u8; 32], r: [u8; 32]) -> [u8; 32] {
    hash_of(NODE, &[&l, &r])
}
struct Tree {
    header: [u8; 32],
    levels: Vec<Vec<[u8; 32]>>,
    manifest: [u8; 32],
}
fn build(n: u32) -> Tree {
    let hd = hash_of(HEADER, &[&header_bytes(n)]);
    let mut levels = vec![(0..n).map(|i| leaf_hash(&hd, i, None)).collect::<Vec<_>>()];
    while levels.last().unwrap().len() > 1 {
        let l = levels.last().unwrap();
        levels.push(l.chunks(2).map(|c| node_hash(c[0], *c.get(1).unwrap_or(&c[0]))).collect());
    }
    let root = levels.last().unwrap()[0];
    Tree { header: hd, levels, manifest: hash_of(MANIFEST, &[&hd, &root]) }
}
fn proof(tree: &Tree, index: usize) -> Vec<[u8;32]> {
    let mut result = Vec::new();
    let mut i = index;
    for level in tree.levels.iter().take(tree.levels.len() - 1) {
        result.push(*level.get(i ^ 1).unwrap_or(&level[i]));
        i >>= 1;
    }
    result
}
fn verify(header: &[u8; 32], index: usize, n: usize, siblings: &[[u8;32]], root: [u8;32],
          override_beneficiary: Option<u32>) -> bool {
    if n == 0 || index >= n { return false; }
    let mut i = index;
    let mut count = n;
    let mut value = leaf_hash(header, i as u32, override_beneficiary);
    let mut used = 0;
    for sibling in siblings {
        if count < 2 { return false; }
        if i ^ 1 >= count && *sibling != value { return false; }
        value = if i & 1 == 1 { node_hash(*sibling, value) } else { node_hash(value, *sibling) };
        i /= 2;
        count = count / 2 + count % 2;
        used += 1;
    }
    count == 1 && used == siblings.len() && value == root
}
fn decode_hash(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut result = [0u8; 32];
    for (i, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[2*i..2*i+2], 16).unwrap();
    }
    result
}
fn expected(n: u32) -> (&'static str, &'static str, &'static str) {
    match n {
        1 => (
            "8cbce6e2540f466f2f38fd605d2c9757ac16039ca19ac1a09b02c8713cf2505e",
            "6045087ba0351018ff064f34336da6bd33b0020c288e023b7af9fd9416a3988c",
            "811f69011a8346c026df8eded7697f23f4c3dd3bfba6a1c34ed9c4d71a332e39",
        ),
        2 => (
            "39c8118a4a072632f2c7c51fceae5d6a1be0609a816d9bf96108a9660a8c9e95",
            "9921a12392018914ca5f46f8bf0783cfa99a733b08ce6805ba3cf0c8349b43e5",
            "b5b2667a831fd38efabb70ce900b375df4438744a80c89cf7d17132883a6371d",
        ),
        3 => (
            "1495c975e592002f4d8a3148032074071c6c18faf06bb55f6b87499859e6de45",
            "15fc7eda49f59fae49474ac00e43b0b256403db0669a8fd616b49a486c7f91d8",
            "99033e12ada957cffb521cf23f3e568eb2a5e6a6ec741bfb4769bf6a9b1d57a8",
        ),
        257 => (
            "e70c3fb5a228b922cd0870eb3faa43cf5458ca55e76c09d65485eb5e9f693939",
            "43bf015333a2537273fd72f750179f27cf6d8869f8f7a488e240f5419e526061",
            "42d131ab1f6a35b13a998e97194e7ea0718cf3a06bd78a7b6bc34698536ec632",
        ),
        _ => panic!("unsupported golden holder count"),
    }
}
#[test]
fn rust_recomputes_all_golden_headers_roots_and_manifest_digests() {
    for n in [1, 2, 3, 257] {
        let tree = build(n);
        let (h, r, m) = expected(n);
        assert_eq!(tree.header, decode_hash(h), "header mismatch N={n}");
        assert_eq!(tree.levels.last().unwrap()[0], decode_hash(r), "root mismatch N={n}");
        assert_eq!(tree.manifest, decode_hash(m), "manifest mismatch N={n}");
    }
}
#[test]
fn rust_recomputes_samples_and_all_proofs_including_odd_and_large() {
    for n in [1, 2, 3, 257] {
        let tree = build(n);
        let root = tree.levels.last().unwrap()[0];
        for i in 0..n {
            let path = proof(&tree, i as usize);
            assert!(verify(&tree.header, i as usize, n as usize, &path, root, None));
        }
        let last = proof(&tree, (n - 1) as usize);
        assert!(last.len() <= 9);
        if n == 3 || n == 257 {
            assert_eq!(last[0], tree.levels[0][(n - 1) as usize]); // duplicate-last
        }
    }
}
#[test]
fn rust_matches_immutable_first_and_last_sample_leaves() {
    let cases = [
        (1, "6045087ba0351018ff064f34336da6bd33b0020c288e023b7af9fd9416a3988c", "6045087ba0351018ff064f34336da6bd33b0020c288e023b7af9fd9416a3988c"),
        (2, "1df90df03ebac540f97a41701cad5c4b03c592c141161918e5f37dbb0f7ee1da", "5afcd211415492eb73f2d9982bf85cb06d704bb117e5fb20c90c2d541b260942"),
        (3, "dc14e916adc5387729a7ee2f0b69677ff11116367bd9c01d1fb5d3e9d4fc1fe3", "e2c918394cdbd29d03adafa8b82295d5f768fbcc0514ad83c2a506fdcc1beaf1"),
        (257, "74bf5db0794e8ecddd251c9f5e036ad50c99da444fcdf293c1918abc6f3fbf3e", "746f1162ebc98d318e60077aff20be72be725d705c0f80033fb5e630c4ea90cc"),
    ];
    for (n, first, last) in cases {
        let t = build(n);
        assert_eq!(t.levels[0][0], decode_hash(first));
        assert_eq!(t.levels[0][(n - 1) as usize], decode_hash(last));
    }
}
#[test]
fn rust_forged_beneficiary_or_wrong_proof_position_is_rejected() {
    for n in [1, 2, 3, 257] {
        let tree = build(n);
        let root = tree.levels.last().unwrap()[0];
        let last = n as usize - 1;
        let mut path = proof(&tree, last);
        assert!(!verify(&tree.header, last, n as usize, &path, root, Some(424242)));
        if !path.is_empty() {
            path[0] = [0x42; 32];
            assert!(!verify(&tree.header, last, n as usize, &path, root, None));
        }
    }
}
#[test]
fn rust_chain_or_migration_scope_replay_has_different_root() {
    let original = build(3);
    let mut changed_header = header_bytes(3);
    // Destination chain ID offset: 232, 8-byte big-endian
    changed_header[239] ^= 0x01;
    let different = hash_of(HEADER, &[&changed_header]);
    assert_ne!(different, original.header);
    assert_ne!(leaf_hash(&different, 0, None), original.levels[0][0]);
    // migration ID at header byte offsets 168..200
    let mut changed_migration = header_bytes(3);
    changed_migration[168] ^= 0x01;
    assert_ne!(hash_of(HEADER, &[&changed_migration]), original.header);
}
#[test]
fn fixture_does_not_bind_real_chain_or_finalize_claims() {
    let source = include_str!("../../../fixtures/manifest-v1/golden.json");
    assert!(source.contains("\"assurance\": \"E1_ENCODING_ONLY\""));
    assert!(source.contains("\"can_claim\": false"));
    assert!(source.contains("\"can_activate\": false"));
    assert!(source.contains("\"source_chain_authenticated\": false"));
}
