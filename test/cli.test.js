'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { collectNpmDeps } = require('../src/lockfiles');

test('lockfile v3: dedup, scopes, aliases, skips root/workspaces/links', () => {
  const deps = collectNpmDeps({
    lockfileVersion: 3,
    packages: {
      '': { name: 'root', version: '1.0.0' },
      'packages/local-ws': { version: '0.0.1' },
      'node_modules/ws-link': { link: true, resolved: 'packages/local-ws' },
      'node_modules/chalk': { version: '5.3.0' },
      'node_modules/@scope/pkg': { version: '2.0.0' },
      'node_modules/a/node_modules/chalk': { version: '5.3.0' },
      'node_modules/renamed': { name: 'real-name', version: '1.1.1' },
    },
  });
  assert.deepStrictEqual(deps, [
    { name: 'chalk', version: '5.3.0' },
    { name: '@scope/pkg', version: '2.0.0' },
    { name: 'real-name', version: '1.1.1' },
  ]);
});

test('lockfile v1: nested dependencies fallback', () => {
  const deps = collectNpmDeps({
    lockfileVersion: 1,
    dependencies: {
      a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } },
    },
  });
  assert.deepStrictEqual(deps, [
    { name: 'a', version: '1.0.0' },
    { name: 'b', version: '2.0.0' },
  ]);
});
