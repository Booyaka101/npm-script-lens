'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { collectNpmDeps } = require('../src/lockfiles');

test('lockfile v3: dedup, scopes, aliases, skips root/workspaces/links; edges', () => {
  const { deps, edges } = collectNpmDeps({
    lockfileVersion: 3,
    packages: {
      '': { name: 'root', version: '1.0.0' },
      'packages/local-ws': { version: '0.0.1' },
      'node_modules/ws-link': { link: true, resolved: 'packages/local-ws' },
      'node_modules/chalk': { version: '5.3.0' },
      'node_modules/@scope/pkg': { version: '2.0.0', dependencies: { chalk: '^5.0.0' } },
      'node_modules/a/node_modules/chalk': { version: '5.3.0' },
      'node_modules/renamed': { name: 'real-name', version: '1.1.1' },
    },
  });
  assert.deepStrictEqual(deps.map(({ name, version }) => ({ name, version })), [
    { name: 'chalk', version: '5.3.0' },
    { name: '@scope/pkg', version: '2.0.0' },
    { name: 'real-name', version: '1.1.1' },
  ]);
  assert.strictEqual(deps[0].lockKey, 'node_modules/chalk');
  assert.deepStrictEqual([...edges.get('@scope/pkg')], ['chalk']);
});

test('lockfile v1: nested dependencies fallback with parent edges', () => {
  const { deps, edges } = collectNpmDeps({
    lockfileVersion: 1,
    dependencies: {
      a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } },
    },
  });
  assert.deepStrictEqual(deps.map(({ name, version }) => ({ name, version })), [
    { name: 'a', version: '1.0.0' },
    { name: 'b', version: '2.0.0' },
  ]);
  assert.deepStrictEqual([...edges.get('a')], ['b']);
});
