/** Dependency-free workspace sanity validator (not a proof validator). */
import { readFileSync, existsSync } from 'node:fs';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
const read = (p) => readFileSync(resolve(root, p), 'utf8');
const pkg = JSON.parse(read('package.json'));
const protocol = JSON.parse(read('packages/protocol-core/package.json'));
const workspace = read('pnpm-workspace.yaml');
const lock = read('pnpm-lock.yaml');
const python = read('local_model/requirements.lock');
const rust = read('rust-toolchain.toml');

assert.equal(pkg.private, true);
assert.equal(pkg.packageManager, 'pnpm@10.19.0');
assert.match(pkg.engines.node, /24/);
assert.equal(protocol.name, '@metorah/protocol-core');
assert.match(workspace, /packages\/\*/);
assert.match(lock, /packages\/protocol-core:/);
assert.match(lock, /lockfileVersion: '9\.0'/);
assert.match(rust, /channel = "1\.90\.0"/);
assert.match(python, /cryptography==/);
assert.match(python, /websockets==/);
for (const p of [
  '.nvmrc', '.python-version', 'foundry.toml',
  'tools/lifecycle/model.py', 'tools/assurance/evaluate.py',
  'packages/protocol-core/src/index.mjs',
]) assert.ok(existsSync(resolve(root, p)), `Missing: ${p}`);

console.log('Metorah workspace check: PASS (structure/toolchain metadata only)');
