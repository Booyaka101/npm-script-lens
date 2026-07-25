'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { parseSpec, computeScriptDiff, renderDiff, lineDiff } = require('../src/diff');

const pkg = (version, scripts = {}, hasGyp = false) => ({ name: 'demo', version, scripts, hasGyp });

test('parseSpec splits name and version, incl. scoped', () => {
  assert.deepStrictEqual(parseSpec('sharp@0.32.6'), { name: 'sharp', version: '0.32.6' });
  assert.deepStrictEqual(parseSpec('@scope/pkg@1.2.3'), { name: '@scope/pkg', version: '1.2.3' });
});

test('parseSpec rejects a spec with no version', () => {
  assert.throws(() => parseSpec('sharp'), /expected <package>@<version>/);
  assert.throws(() => parseSpec('@scope/pkg'), /expected <package>@<version>/);
});

test('identical scripts → all unchanged, exit 0 (changed=false)', () => {
  const r = computeScriptDiff(
    pkg('1.0.0', { install: 'node-gyp rebuild' }),
    pkg('1.0.1', { install: 'node-gyp rebuild' }),
  );
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.json.unchanged, ['install']);
  assert.deepStrictEqual(r.json.added, []);
  assert.deepStrictEqual(r.json.modified, []);
});

test('added script → changed=true, appears in added', () => {
  const r = computeScriptDiff(pkg('1.0.0'), pkg('2.0.0', { postinstall: 'node evil.js' }));
  assert.strictEqual(r.changed, true);
  assert.deepStrictEqual(r.json.added, [{ key: 'postinstall', script: 'node evil.js' }]);
});

test('removed script → not counted as changed (only add/modify are)', () => {
  const r = computeScriptDiff(pkg('1.0.0', { preinstall: 'echo hi' }), pkg('2.0.0'));
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.json.removed, ['preinstall']);
});

test('modified script → changed=true with line-level diff', () => {
  const r = computeScriptDiff(
    pkg('1.0.0', { install: 'node install/check' }),
    pkg('2.0.0', { install: 'node install/check --force' }),
  );
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.json.modified.length, 1);
  assert.strictEqual(r.json.modified[0].key, 'install');
  assert.strictEqual(r.json.modified[0].old, 'node install/check');
  assert.strictEqual(r.json.modified[0].new, 'node install/check --force');
});

test('gaining binding.gyp shows up as an implicit added node-gyp build', () => {
  const r = computeScriptDiff(pkg('1.0.0', {}, false), pkg('2.0.0', {}, true));
  assert.strictEqual(r.changed, true);
  assert.ok(r.json.added.some((e) => e.key === 'binding.gyp' && e.implicit));
  const text = renderDiff(pkg('1.0.0', {}, false), pkg('2.0.0', {}, true), r, { color: false });
  assert.ok(text.includes('ADDED: implicit node-gyp rebuild (binding.gyp)'), text);
});

test('losing binding.gyp is a removal, not a change', () => {
  const r = computeScriptDiff(pkg('1.0.0', {}, true), pkg('2.0.0', {}, false));
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.json.removed, ['binding.gyp']);
});

test('renderDiff (no color) prints the documented UNCHANGED/ADDED/MODIFIED labels', () => {
  const o = pkg('1.0.0', { install: 'a', preinstall: 'keep' });
  const n = pkg('2.0.0', { install: 'b', preinstall: 'keep', postinstall: 'c' });
  const r = computeScriptDiff(o, n);
  const text = renderDiff(o, n, r, { color: false });
  assert.ok(text.includes('UNCHANGED: preinstall'));
  assert.ok(text.includes('MODIFIED: install'));
  assert.ok(text.includes('ADDED: postinstall: c'));
});

test('renderDiff with color emits ANSI codes', () => {
  const r = computeScriptDiff(pkg('1.0.0'), pkg('2.0.0', { install: 'x' }));
  const text = renderDiff(pkg('1.0.0'), pkg('2.0.0', { install: 'x' }), r, { color: true });
  assert.ok(text.includes('\x1b['), 'expected ANSI escape');
});

test('lineDiff marks common, removed and added lines', () => {
  const d = lineDiff('a\nb\nc', 'a\nx\nc');
  assert.deepStrictEqual(d, [
    { t: ' ', line: 'a' },
    { t: '-', line: 'b' },
    { t: '+', line: 'x' },
    { t: ' ', line: 'c' },
  ]);
});
