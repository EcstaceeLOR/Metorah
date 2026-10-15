import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonical, makeFixture, verifyProof, hashHeader, hashLeaf } from './canonical_v1.ts';

const fixture = JSON.parse(readFileSync(new URL('../../fixtures/manifest-v1/golden.json', import.meta.url), 'utf8'));
test('fixed fixture schema never upgrades authentication or claim status', () => {
  assert.equal(fixture.schema_version, 'metorah-golden-v1');
  assert.deepEqual(fixture.cases.map((x: { holders: number }) => x.holders), [1, 2, 3, 257]);
  assert.equal(fixture.source_chain_authenticated, false);
  assert.equal(fixture.can_activate, false);
  assert.equal(fixture.can_claim, false);
});
for (const v of fixture.cases) {
  test('TypeScript independent canonical roots, leaves and proofs (' + v.holders + ')', () => {
    const { header, entries } = makeFixture(v.holders);
    const result = canonical(header, entries);
    assert.equal(result.headerHash, v.header_hash);
    assert.equal(result.root, v.merkle_root);
    assert.equal(result.manifestDigest, v.manifest_digest);
    assert.equal(header.historical_holder_count, v.historical_holder_count);
    assert.equal(header.total_units, v.total_units);
    for (const sample of v.samples) {
      assert.equal(result.leafHashes[sample.index], sample.leaf_hash);
      assert.deepEqual(result.proofFor(sample.index), sample.proof);
      assert.equal(verifyProof(header, entries[sample.index], sample.proof, v.merkle_root), true);
      if (sample.proof.length) {
        const corrupted = sample.proof.slice();
        corrupted[0] = v.header_hash;
        assert.equal(verifyProof(header, entries[sample.index], corrupted, v.merkle_root), false);
      }
    }
  });
}
test('tampered recipient, source, nonce, index or amounts are rejected', () => {
  const { header, entries } = makeFixture(3);
  const hash = canonical(header, entries);
  for (const field of ['source_account', 'beneficiary', 'units', 'binding_nonce', 'historical_index'] as const) {
    const changed = { ...entries[0] };
    switch (field) {
      case 'source_account': changed.source_account = '0x' + '99'.repeat(32); break;
      case 'beneficiary': changed.beneficiary = '0x' + '99'.repeat(20); break;
      case 'units': changed.units = '11'; break;
      case 'binding_nonce': changed.binding_nonce = '3'; break;
      case 'historical_index': changed.historical_index = 1; break;
    }
    assert.equal(verifyProof(header, changed, hash.proofFor(0), hash.root), false, field);
  }
  assert.throws(() => canonical(header, [entries[1], entries[0], entries[2]]));
  assert.throws(() => canonical(header, [entries[0], entries[0], entries[2]]));
});
test('source genesis, destination chain/contract and migration domain change every leaf hash', () => {
  const { header, entries } = makeFixture(2);
  const reference = canonical(header, entries);
  for (const [field, value] of [
    ['source_genesis', '0x' + 'ab'.repeat(32)],
    ['migration_id', '0x' + 'ab'.repeat(32)],
    ['destination_chain_id', '1'],
    ['destination_contract', '0x' + 'ef'.repeat(20)],
  ] as const) {
    const changed = { ...header, [field]: value };
    const other = canonical(changed, entries);
    assert.notEqual(other.root, reference.root);
    assert.equal(verifyProof(changed, entries[0], reference.proofFor(0), reference.root), false);
  }
});
test('odd tree never accepts a forged sibling in the duplicated-last slot', () => {
  const { header, entries } = makeFixture(3);
  const tree = canonical(header, entries);
  const path = tree.proofFor(2);
  path[0] = tree.leafHashes[1];
  assert.equal(verifyProof(header, entries[2], path, tree.root), false);
});
test('integer precision rejects unsafe JavaScript values and noncanonical decimals', () => {
  const { header, entries } = makeFixture(1);
  assert.throws(() => canonical({ ...header, total_units: '011' }, entries));
  assert.throws(() => canonical({ ...header, destination_chain_id: '031337' }, entries));
  assert.throws(() => canonical(header, [{ ...entries[0], units: '0' }]));
  assert.throws(() => canonical(header, [{ ...entries[0], units: '340282366920938463463374607431768211456' }]));
  assert.equal(hashHeader(header).length, 32);
  assert.equal(hashLeaf(header, entries[0]).length, 32);
});
