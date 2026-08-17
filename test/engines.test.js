'use strict';
// The floor this package advertises has to be the floor it can actually run on.
// commander 15 shipped ESM-only with engines >=22.12 while package.json still
// said >=20, so `npx npm-script-lens` died with ERR_REQUIRE_ESM on every Node
// below 20.19 instead of anything a user could act on. npm and npx only warn on
// an engines mismatch, and CI's floating `node: 20` always resolves to a patch
// new enough to hide it, so nothing else catches this.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { enginesMinimum } = require('../src/publish');

const ROOT = path.join(__dirname, '..');
const pkg = require('../package.json');
const lock = require('../package-lock.json');

const gte = (a, b) => {
  const [x, y] = [a.split('.').map(Number), b.split('.').map(Number)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i];
  return true;
};

// Installed manifest when it is on disk (only that carries "type"), lockfile
// metadata otherwise, so optional deps skipped on this platform still get
// their engines checked.
const manifests = Object.entries(lock.packages)
  .filter(([spec, meta]) => spec.startsWith('node_modules/') && !meta.dev)
  .map(([spec, meta]) => {
    const onDisk = path.join(ROOT, spec, 'package.json');
    const installed = fs.existsSync(onDisk) ? JSON.parse(fs.readFileSync(onDisk, 'utf8')) : null;
    return { name: spec.slice('node_modules/'.length), installed, meta };
  });

test('every runtime dependency runs on the Node floor we advertise', () => {
  const ours = enginesMinimum(pkg.engines.node);
  assert.ok(ours, 'package.json needs an engines.node with a readable lower bound');
  const raised = manifests
    .map(({ name, installed, meta }) => {
      const declared = (installed || meta).engines && (installed || meta).engines.node;
      return { name, floor: enginesMinimum(declared), declared };
    })
    .filter(({ floor }) => floor && !gte(ours, floor));
  assert.deepStrictEqual(raised.map((r) => `${r.name} (${r.declared})`), [],
    `these need a newer Node than engines.node "${pkg.engines.node}" promises. `
    + 'Pin them back or raise engines.node to match.');
});

test('no runtime dependency is ESM-only while the entrypoint is CommonJS', () => {
  assert.strictEqual(pkg.type, undefined, 'this package is CommonJS; update this test if that changes');
  const esm = manifests.filter(({ installed }) => installed && installed.type === 'module').map((m) => m.name);
  assert.deepStrictEqual(esm, [],
    'require() of an ESM-only dependency needs require(esm), which silently raises the real floor to '
    + 'Node 20.19/22.12 whatever engines.node says. Pin it back or convert the CLI to ESM.');
});
