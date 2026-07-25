'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { managerFor, managerById, MANAGERS } = require('../src/pm-contract');

const mkdir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lens-pm-'));
const read = (dir, f) => fs.readFileSync(path.join(dir, f), 'utf8');
const writePkg = (dir, obj) => fs.writeFileSync(path.join(dir, 'package.json'), `${JSON.stringify(obj, null, 2)}\n`);

test('managerFor maps lockfile types (default npm); managerById validates', () => {
  for (const id of ['npm', 'pnpm', 'yarn', 'bun']) assert.strictEqual(managerFor(id).id, id);
  assert.strictEqual(managerFor('something-new').id, 'npm', 'unknown type defaults to npm');
  assert.strictEqual(managerById('pnpm').id, 'pnpm');
  assert.throws(() => managerById('cargo'), /unknown package manager/);
});

test('each manager renders its native allowlist shape and key', () => {
  const approved = [{ name: 'core-js', version: '3.38.1' }, { name: '@scope/x', version: '2.0.0' }];
  assert.strictEqual(MANAGERS.npm.nativeKey, 'allowScripts');
  assert.deepStrictEqual(MANAGERS.npm.renderValue(approved), { '@scope/x@2.0.0': true, 'core-js@3.38.1': true });
  assert.strictEqual(MANAGERS.pnpm.nativeKey, 'allowBuilds');
  assert.deepStrictEqual(MANAGERS.pnpm.renderValue(approved), { '@scope/x': true, 'core-js': true });
  assert.strictEqual(MANAGERS.yarn.nativeKey, 'dependenciesMeta');
  assert.deepStrictEqual(MANAGERS.yarn.renderValue(approved), { '@scope/x': { built: true }, 'core-js': { built: true } });
  assert.strictEqual(MANAGERS.bun.nativeKey, 'trustedDependencies');
  assert.deepStrictEqual(MANAGERS.bun.renderValue(approved), ['@scope/x', 'core-js']);
});

test('npm.write merges allowScripts into package.json, preserving existing', () => {
  const dir = mkdir();
  writePkg(dir, { name: 'p', version: '1.0.0', allowScripts: { 'keep@1.0.0': true } });
  MANAGERS.npm.write(dir, [{ name: 'a', version: '1.0.0' }]);
  const pkg = JSON.parse(read(dir, 'package.json'));
  assert.strictEqual(pkg.allowScripts['keep@1.0.0'], true);
  assert.strictEqual(pkg.allowScripts['a@1.0.0'], true);
});

test('bun.write unions trustedDependencies and flags the replace-default semantics', () => {
  const dir = mkdir();
  writePkg(dir, { name: 'p', version: '1.0.0', trustedDependencies: ['existing'] });
  const { note } = MANAGERS.bun.write(dir, [{ name: 'a', version: '1.0.0' }, { name: 'a', version: '1.0.1' }]);
  assert.deepStrictEqual(JSON.parse(read(dir, 'package.json')).trustedDependencies, ['a', 'existing']);
  assert.match(note, /default trusted list/);
});

test('yarn.write sets dependenciesMeta.built and disables scripts in .yarnrc.yml', () => {
  const dir = mkdir();
  writePkg(dir, { name: 'p', version: '1.0.0' });
  const { note } = MANAGERS.yarn.write(dir, [{ name: 'a', version: '1.0.0' }]);
  assert.deepStrictEqual(JSON.parse(read(dir, 'package.json')).dependenciesMeta.a, { built: true });
  assert.match(read(dir, '.yarnrc.yml'), /enableScripts:\s*false/);
  assert.match(note, /enableScripts/);
});

test('pnpm.write creates a fresh allowBuilds block when there is no workspace file', () => {
  const dir = mkdir();
  const { note } = MANAGERS.pnpm.write(dir, [{ name: 'core-js', version: '3.38.1' }]);
  assert.match(read(dir, 'pnpm-workspace.yaml'), /allowBuilds:\n {2}core-js: true/);
  assert.match(note, /created/);
});

test('pnpm.write appends a block when the workspace file has none, keeping existing keys', () => {
  const dir = mkdir();
  fs.writeFileSync(path.join(dir, 'pnpm-workspace.yaml'), 'packages:\n  - "pkg/*"\n');
  const { note } = MANAGERS.pnpm.write(dir, [{ name: 'a', version: '1.0.0' }]);
  const y = read(dir, 'pnpm-workspace.yaml');
  assert.match(y, /packages:/);
  assert.match(y, /allowBuilds:\n {2}a: true/);
  assert.match(note, /appended/);
});

test('pnpm.write merges into an existing block, preserves surroundings, quotes scoped names', () => {
  const dir = mkdir();
  fs.writeFileSync(path.join(dir, 'pnpm-workspace.yaml'),
    '# top comment\npackages:\n  - "p/*"\nallowBuilds:\n  z-existing: false\n');
  MANAGERS.pnpm.write(dir, [{ name: '@scope/x', version: '1.0.0' }, { name: 'a', version: '1.0.0' }]);
  const y = read(dir, 'pnpm-workspace.yaml');
  assert.match(y, /# top comment/, 'comment preserved');
  assert.match(y, /packages:\n {2}- "p\/\*"/, 'packages preserved');
  assert.match(y, /"@scope\/x": true/, 'scoped name quoted');
  assert.match(y, /\n {2}a: true/);
  assert.match(y, /z-existing: false/, 'pre-existing decision preserved');
  // keys sorted: @scope/x, a, z-existing
  assert.ok(y.indexOf('"@scope/x"') < y.indexOf('  a: true'));
  assert.ok(y.indexOf('  a: true') < y.indexOf('z-existing'));
});
