/** Independent TypeScript/Node 24 reference for Metorah V1 SHA-256 vectors.
 * Offline encoding only. Never a chain finality or claim verifier.
 * No runtime npm dependencies; BigInt for all u64 and u128 values.
 */
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';

export type ManifestHeader = {
  source_genesis: string;
  finalized_block_hash: string;
  finalized_block_number: string;
  finalized_state_root: string;
  source_contract: string;
  source_code_hash: string;
  migration_id: string;
  asset_id: string;
  destination_chain_id: string;
  destination_contract: string;
  entitlement_kind: number;
  decimals: number;
  historical_holder_count: number;
  active_holder_count: number;
  total_units: string;
};
export type Entitlement = {
  leaf_index: number;
  historical_index: number;
  source_account: string;
  beneficiary: string;
  units: string;
  binding_nonce: string;
};
export type HashCase = {
  headerHash: string;
  leafHashes: string[];
  root: string;
  manifestDigest: string;
  proofFor: (index: number) => string[];
};

const TAG = {
  header: Buffer.from('METORAH_HEADER_V1\0', 'utf8'),
  leaf: Buffer.from('METORAH_LEAF_V1\0', 'utf8'),
  node: Buffer.from('METORAH_NODE_V1\0', 'utf8'),
  manifest: Buffer.from('METORAH_MANIFEST_V1\0', 'utf8'),
};

function ensure(condition: unknown, why: string): asserts condition {
  if (!condition) throw new Error(why);
}
function hexb(value: string, bytes: number): Buffer {
  ensure(typeof value === 'string' && new RegExp('^0x[0-9a-f]{' + (2 * bytes) + '}$').test(value), 'INVALID_HEX');
  const out = Buffer.from(value.slice(2), 'hex');
  ensure(out.some((x: number) => x !== 0), 'ZERO_IDENTITY');
  return out;
}
function integer(value: string | number | bigint, bytes: number, allowZero = false): Buffer {
  let n: bigint;
  if (typeof value === 'number') {
    ensure(Number.isSafeInteger(value), 'INVALID_NUMBER');
    n = BigInt(value);
  } else if (typeof value === 'bigint') {
    n = value;
  } else {
    ensure(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value), 'INVALID_DECIMAL');
    n = BigInt(value);
  }
  ensure(n >= (allowZero ? 0n : 1n) && n < (1n << BigInt(8 * bytes)), 'INTEGER_OVERFLOW_OR_ZERO');
  const out = Buffer.alloc(bytes);
  for (let i = bytes - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}
const hash = (...parts: Buffer[]): Buffer => createHash('sha256').update(Buffer.concat(parts)).digest();
const outHex = (b: Buffer): string => '0x' + b.toString('hex');

export function encodeHeader(h: ManifestHeader): Buffer {
  ensure(h.entitlement_kind === 1 && Number.isInteger(h.decimals) && h.decimals >= 0 && h.decimals <= 18, 'UNSUPPORTED_KIND_OR_DECIMALS');
  ensure(Number.isSafeInteger(h.active_holder_count) && Number.isSafeInteger(h.historical_holder_count) &&
    h.active_holder_count > 0 && h.historical_holder_count >= h.active_holder_count, 'BAD_HOLDER_COUNTS');
  const encoded = Buffer.concat([
    hexb(h.source_genesis, 32),
    hexb(h.finalized_block_hash, 32),
    integer(h.finalized_block_number, 8),
    hexb(h.finalized_state_root, 32),
    hexb(h.source_contract, 32),
    hexb(h.source_code_hash, 32),
    hexb(h.migration_id, 32),
    hexb(h.asset_id, 32),
    integer(h.destination_chain_id, 8),
    hexb(h.destination_contract, 20),
    integer(h.entitlement_kind, 1),
    integer(h.decimals, 1, true),
    integer(h.historical_holder_count, 4),
    integer(h.active_holder_count, 4),
    integer(h.total_units, 16),
  ]);
  ensure(encoded.length === 286, 'HEADER_WIDTH');
  return encoded;
}
export function encodeLeaf(e: Entitlement, h: ManifestHeader): Buffer {
  ensure(Number.isInteger(e.leaf_index) && e.leaf_index >= 0 && e.leaf_index < h.active_holder_count, 'INVALID_LEAF_INDEX');
  ensure(Number.isInteger(e.historical_index) && e.historical_index >= 0 && e.historical_index < h.historical_holder_count, 'INVALID_HISTORICAL_INDEX');
  const encoded = Buffer.concat([
    integer(e.leaf_index, 4, true),
    integer(e.historical_index, 4, true),
    hexb(e.source_account, 32),
    hexb(e.beneficiary, 20),
    integer(e.units, 16),
    integer(e.binding_nonce, 8),
  ]);
  ensure(encoded.length === 84, 'LEAF_WIDTH');
  return encoded;
}
export const hashHeader = (h: ManifestHeader): Buffer => hash(TAG.header, encodeHeader(h));
export const hashLeaf = (h: ManifestHeader, e: Entitlement, hd = hashHeader(h)): Buffer =>
  hash(TAG.leaf, hd, encodeLeaf(e, h));
export const hashNode = (a: Buffer, b: Buffer): Buffer => hash(TAG.node, a, b);

export function canonical(h: ManifestHeader, entries: Entitlement[]): HashCase {
  ensure(Array.isArray(entries) && entries.length === h.active_holder_count, 'LEAF_COUNT_MISMATCH');
  const hd = hashHeader(h);
  const seen = new Set<string>();
  let previous = -1;
  let sum = 0n;
  const leaves = entries.map((e, i) => {
    ensure(e.leaf_index === i, 'NONCANONICAL_LEAF_INDEX');
    ensure(e.historical_index > previous, 'REORDERED_HISTORICAL_INDEX');
    previous = e.historical_index;
    ensure(!seen.has(e.source_account), 'DUPLICATE_ACCOUNT');
    seen.add(e.source_account);
    sum += BigInt(e.units);
    ensure(sum <= ((1n << 128n) - 1n), 'TOTAL_OVERFLOW');
    return hashLeaf(h, e, hd);
  });
  ensure(sum === BigInt(h.total_units), 'SUPPLY_MISMATCH');
  const layers: Buffer[][] = [leaves];
  while (layers[layers.length - 1].length > 1) {
    const level = layers[layers.length - 1];
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(hashNode(level[i], level[i + 1] ?? level[i]));
    }
    layers.push(next);
  }
  const root = layers[layers.length - 1][0];
  return {
    headerHash: outHex(hd), leafHashes: leaves.map(outHex), root: outHex(root),
    manifestDigest: outHex(hash(TAG.manifest, hd, root)),
    proofFor: (index: number): string[] => {
      ensure(Number.isInteger(index) && index >= 0 && index < leaves.length, 'BAD_PROOF_INDEX');
      const proof: string[] = [];
      for (const layer of layers.slice(0, -1)) {
        const sibling = index % 2 === 0 ? index + 1 : index - 1;
        proof.push(outHex(layer[sibling] ?? layer[index]));
        index = Math.floor(index / 2);
      }
      return proof;
    },
  };
}
export function verifyProof(h: ManifestHeader, entry: Entitlement, proof: string[], expectedRoot: string): boolean {
  try {
    ensure(Array.isArray(proof), 'INVALID_PROOF');
    const index0 = entry.leaf_index;
    ensure(Number.isInteger(index0) && index0 >= 0 && index0 < h.active_holder_count, 'BAD_INDEX');
    let count = h.active_holder_count;
    let depth = 0;
    while (count > 1) { count = Math.floor((count + 1) / 2); depth++; }
    ensure(proof.length === depth, 'BAD_PROOF_DEPTH');
    let node = hashLeaf(h, entry);
    let ix = index0;
    count = h.active_holder_count;
    for (const s of proof) {
      const sib = hexb(s, 32);
      const siblingIndex = ix % 2 === 0 ? ix + 1 : ix - 1;
      if (siblingIndex >= count) ensure(sib.equals(node), 'INVALID_DUPLICATE_LAST');
      node = (ix & 1) ? hashNode(sib, node) : hashNode(node, sib);
      ix = Math.floor(ix / 2);
      count = Math.floor((count + 1) / 2);
    }
    return outHex(node) === expectedRoot;
  } catch {
    return false;
  }
}

/** Deterministic public fixture derivation. No wallets, private keys or RPC. */
export function makeFixture(n: number): { header: ManifestHeader; entries: Entitlement[] } {
  ensure(Number.isInteger(n) && n > 0 && n <= 257, 'INVALID_FIXTURE_COUNT');
  const entries: Entitlement[] = Array.from({ length: n }, (_, i) => ({
    leaf_index: i, historical_index: i + Math.floor(i / 8),
    source_account: '0x' + (BigInt(i + 1)).toString(16).padStart(64, '0'),
    beneficiary: '0x' + BigInt(i + 1001).toString(16).padStart(40, '0'),
    units: String((i + 1) * (i + 11)),
    binding_nonce: String(1 + i % 3),
  }));
  const total = entries.reduce((s, e) => s + BigInt(e.units), 0n).toString();
  return {
    header: {
      source_genesis: '0x' + '11'.repeat(32),
      finalized_block_hash: '0x' + '22'.repeat(32),
      finalized_block_number: '12345',
      finalized_state_root: '0x' + '33'.repeat(32),
      source_contract: '0x' + '44'.repeat(32),
      source_code_hash: '0x' + '55'.repeat(32),
      migration_id: '0x' + '66'.repeat(32),
      asset_id: '0x' + '77'.repeat(32),
      destination_chain_id: '31337',
      destination_contract: '0x' + '88'.repeat(20),
      entitlement_kind: 1, decimals: 12,
      historical_holder_count: n + Math.floor((n - 1) / 8) + 1,
      active_holder_count: n, total_units: total,
    }, entries,
  };
}
