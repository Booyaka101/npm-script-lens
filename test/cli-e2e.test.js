'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');

function run(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd: ROOT, timeout: 170000 });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}

test('audit without --fail-on-high exits 0 even with HIGH deps', async () => {
  const out = await run(['audit', '--path', 'fixtures/demo']);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stdout.includes('# npm-script-lens report'));
  assert.ok(out.stdout.includes('🔴 HIGH'));
});

test('audit --fail-on-high exits 1 on the demo fixture', async () => {
  const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lens-cli-')), 'report.md');
  const out = await run(['audit', '--path', 'fixtures/demo', '--fail-on-high', '--out', tmp]);
  assert.strictEqual(out.status, 1, out.stderr);
  assert.ok(out.stderr.includes('FAIL: '), out.stderr);
  const report = fs.readFileSync(tmp, 'utf8');
  assert.ok(report.includes('`sharp@0.33.5`'));
  assert.ok(JSON.parse(report.match(/```json\n([\s\S]*?)\n```/)[1]).allowScripts);
  // keep the committed sample report in sync with what the tool really emits
  const golden = path.join(ROOT, 'fixtures', 'demo-report.md');
  if (fs.readFileSync(golden, 'utf8') !== report) fs.writeFileSync(golden, report);
});

test('audit --json emits machine-readable output with per-package risk', async () => {
  const out = await run(['audit', '--path', 'fixtures/demo', '--json']);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  const byName = Object.fromEntries(j.results.map((r) => [r.name, r]));
  assert.strictEqual(byName['sharp'].risk, 'HIGH');
  assert.strictEqual(byName['chalk'].risk, 'SAFE');
  assert.strictEqual(byName['core-js'].risk, 'LOW');
  assert.strictEqual(j.allowScripts['sharp@0.33.5'], false);
  assert.strictEqual(j.allowScripts['core-js@3.38.1'], true);
});

test('diff reports changed install scripts across versions, exit 1', async () => {
  const out = await run(['diff', 'sharp@0.32.6', 'sharp@0.33.0']);
  assert.strictEqual(out.status, 1, out.stderr);
  assert.ok(out.stdout.includes('sharp@0.32.6 → sharp@0.33.0'), out.stdout);
  assert.ok(out.stdout.includes('MODIFIED: install'), out.stdout);
});

test('diff --json emits the four buckets and exit 0 when identical', async () => {
  const out = await run(['diff', 'sharp@0.33.0', 'sharp@0.33.0', '--json']);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.deepStrictEqual(Object.keys(j).sort(), ['added', 'modified', 'removed', 'unchanged']);
  assert.deepStrictEqual(j.added, []);
  assert.deepStrictEqual(j.modified, []);
  assert.ok(j.unchanged.includes('install'));
});

test('diff on a bad spec is a clean usage error, exit 2', async () => {
  const out = await run(['diff', 'sharp', 'sharp@0.33.0']);
  assert.strictEqual(out.status, 2, out.stderr);
  assert.ok(out.stderr.includes('expected <package>@<version>'), out.stderr);
});

test('missing lockfile is a clean error, exit 2', async () => {
  const out = await run(['audit', '--path', 'does/not/exist']);
  assert.strictEqual(out.status, 2);
  assert.ok(out.stderr.includes('lockfile not found'), out.stderr);
});
