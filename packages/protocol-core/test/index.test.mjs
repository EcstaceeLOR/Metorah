import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MIGRATION_STATES, RUNTIME_VERIFICATION_IMPLEMENTED, RELEASE_PHASE,
} from '../src/index.mjs';

test('shared migration status vocabulary is complete and unique', () => {
  assert.equal(MIGRATION_STATES.length, 11);
  assert.equal(new Set(MIGRATION_STATES).size, 11);
  assert.ok(MIGRATION_STATES.includes('PAUSED'));
  assert.ok(MIGRATION_STATES.includes('DISPUTED'));
});

test('bootstrap cannot claim authenticated chain verification', () => {
  assert.equal(RUNTIME_VERIFICATION_IMPLEMENTED, false);
  assert.equal(RELEASE_PHASE, 'DESIGN_AND_OFFLINE_VALIDATION');
});
