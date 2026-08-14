'use strict';
// .npmrc round-tripping for allow-git / allow-remote: parse, read the
// committed config, and merge new values while preserving every other key,
// comment, blank line, order, and EOL style byte-for-byte.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseNpmrc, readSourceConfig, mergeNpmrc } = require('../src/npmrc');

let tmp;
before(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-npmrc-')); });
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

test('parseNpmrc: pairs, comments, blanks, and the bare-key=true ini rule', () => {
  const lines = parseNpmrc('# a comment\n; another\n\nregistry=https://r.example/\nallow-git = root\nallow-remote\n');
  assert.deepStrictEqual(lines.map((l) => l.type),
    ['comment', 'comment', 'blank', 'pair', 'pair', 'pair', 'blank']);
  assert.deepStrictEqual(lines[3], { type: 'pair', key: 'registry', value: 'https://r.example/', raw: 'registry=https://r.example/' });
  assert.strictEqual(lines[4].key, 'allow-git');
  assert.strictEqual(lines[4].value, 'root', 'whitespace around = is trimmed');
  // npm's ini reads a bare key as key=true, and for these enum keys that is an
  // INVALID value, so it must surface as 'true', not be normalized away
  assert.deepStrictEqual({ key: lines[5].key, value: lines[5].value, bare: lines[5].bare },
    { key: 'allow-remote', value: 'true', bare: true });
});

test('readSourceConfig: missing file, present keys, last occurrence wins', () => {
  const missing = readSourceConfig(path.join(tmp, 'nowhere'));
  assert.deepStrictEqual({ exists: missing.exists, git: missing.git, remote: missing.remote },
    { exists: false, git: null, remote: null });

  const dir = path.join(tmp, 'proj');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, '.npmrc'), '# team config\nallow-git=none\nregistry=https://r.example/\nallow-git=root\n');
  const cfg = readSourceConfig(dir);
  assert.strictEqual(cfg.exists, true);
  assert.strictEqual(cfg.git, 'root', 'last occurrence wins, like npm ini');
  assert.strictEqual(cfg.remote, null, 'absent key stays null');

  // an out-of-enum committed value (the =true trap) is surfaced raw for the
  // caller to reject, never coerced
  fs.writeFileSync(path.join(dir, '.npmrc'), 'allow-git=true\nallow-remote\n');
  const bad = readSourceConfig(dir);
  assert.strictEqual(bad.git, 'true');
  assert.strictEqual(bad.remote, 'true', 'bare flag line reads as =true');
});

test('mergeNpmrc: appends missing keys, preserving other content byte-for-byte', () => {
  const original = '# keep me\nregistry=https://r.example/\n\n; trailing comment\n';
  const merged = mergeNpmrc(original, { 'allow-git': 'all' });
  assert.strictEqual(merged, `${original}allow-git=all\n`,
    'everything original is byte-identical; only the new line is added');
  // no trailing newline in the source: one is inserted before appending
  assert.strictEqual(mergeNpmrc('registry=https://r.example/', { 'allow-git': 'root' }),
    'registry=https://r.example/\nallow-git=root\n');
  // empty / missing file
  assert.strictEqual(mergeNpmrc('', { 'allow-git': 'all', 'allow-remote': 'root' }),
    'allow-git=all\nallow-remote=root\n');
});

test('mergeNpmrc: replaces existing keys in place, every occurrence (ini is last-wins)', () => {
  const original = 'allow-git=none\n# comment\nallow-git=true\nregistry=https://r.example/\n';
  const merged = mergeNpmrc(original, { 'allow-git': 'root' });
  assert.strictEqual(merged, 'allow-git=root\n# comment\nallow-git=root\nregistry=https://r.example/\n',
    'a stale later duplicate would silently override the fix, both rewritten');
  // untouched keys and unknown updates: null/undefined values are ignored
  assert.strictEqual(mergeNpmrc(original, { 'allow-remote': null }), original);
});

test('mergeNpmrc: preserves CRLF line endings and bare-key lines are rewritten as pairs', () => {
  const original = '# win\r\nallow-git\r\nregistry=https://r.example/\r\n';
  const merged = mergeNpmrc(original, { 'allow-git': 'all' });
  assert.strictEqual(merged, '# win\r\nallow-git=all\r\nregistry=https://r.example/\r\n');
});
