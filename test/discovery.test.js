'use strict';
// Where a command looks when --path is not already a project. Ordering matters:
// the path itself, then upward like npm does, then every project underneath.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { findProjects, discoverLockfiles, nearestLockfileUp } = require('../src/lockfiles');

const LOCK = '{"lockfileVersion":3,"packages":{"":{"name":"p","version":"1.0.0"}}}';

function tree(spec) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-disc-'));
  for (const [rel, file] of Object.entries(spec)) {
    const dir = path.join(root, rel);
    fs.mkdirSync(dir, { recursive: true });
    if (file) fs.writeFileSync(path.join(dir, file), LOCK);
  }
  return root;
}

const rels = (root, r) => r.lockfiles.map((l) => path.relative(root, l.path).replace(/\\/g, '/')).sort();

test('a directory holding a lockfile resolves to itself', () => {
  const root = tree({ '.': 'package-lock.json' });
  const r = findProjects(root);
  assert.strictEqual(r.how, 'exact');
  assert.deepStrictEqual(rels(root, r), ['package-lock.json']);
});

test('a lockfile path resolves to itself, and carries its manager', () => {
  const root = tree({ '.': 'pnpm-lock.yaml' });
  const r = findProjects(path.join(root, 'pnpm-lock.yaml'));
  assert.strictEqual(r.how, 'exact');
  assert.strictEqual(r.lockfiles[0].type, 'pnpm');
});

test('a subdirectory searches upward, the way npm resolves a project', () => {
  const root = tree({ '.': 'package-lock.json', 'src/components': null });
  const r = findProjects(path.join(root, 'src', 'components'));
  assert.strictEqual(r.how, 'up');
  assert.deepStrictEqual(rels(root, r), ['package-lock.json']);
  assert.strictEqual(nearestLockfileUp(path.join(root, 'src', 'components')), path.join(root, 'package-lock.json'));
});

test('a directory of projects discovers every one underneath', () => {
  const root = tree({ app1: 'package-lock.json', 'app2/nested': 'yarn.lock' });
  const r = findProjects(root);
  assert.strictEqual(r.how, 'down');
  assert.deepStrictEqual(rels(root, r), ['app1/package-lock.json', 'app2/nested/yarn.lock']);
});

test('discovery never descends into node_modules', () => {
  const root = tree({ app: 'package-lock.json', 'app/node_modules/dep': 'package-lock.json' });
  assert.deepStrictEqual(rels(root, findProjects(root)), ['app/package-lock.json']);
  assert.strictEqual(discoverLockfiles(root).length, 1);
});

test('discovery never descends into dot directories', () => {
  const root = tree({ app: 'package-lock.json', '.cache/thing': 'package-lock.json' });
  assert.deepStrictEqual(rels(root, findProjects(root)), ['app/package-lock.json']);
});

test('upward wins over downward, so a project is never split into its children', () => {
  const root = tree({ '.': 'package-lock.json', 'packages/a': 'package-lock.json' });
  const r = findProjects(path.join(root, 'packages'));
  assert.strictEqual(r.how, 'up', 'a workspace subdir belongs to its root, not to itself');
  assert.deepStrictEqual(rels(root, r), ['package-lock.json']);
});

test('nothing anywhere is still a clean error naming the lockfiles looked for', () => {
  const root = tree({ empty: null });
  assert.throws(() => findProjects(path.join(root, 'empty')), /lockfile not found/);
});

test('a path that does not exist keeps the install hint', () => {
  assert.throws(() => findProjects(path.join(os.tmpdir(), 'lens-nope-does-not-exist')), /run npm install --package-lock-only/);
});
