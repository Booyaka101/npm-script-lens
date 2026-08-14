'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { runAudit } = require('../src/cli');
const { buildAllowScripts, packageRisk } = require('../src/reporter');

const ROOT = path.join(__dirname, '..');

// A dozen real, script-heavy packages (native builds, binary downloaders,
// telemetry, plus no-script controls), so every version must resolve, so this
// also guards the fixture against typos: any 404 shows up as an ERROR row.
test('native-heavy fixture: variety audit with zero fetch errors', async () => {
  const results = await runAudit(path.join(ROOT, 'fixtures', 'native-heavy'));
  const byName = Object.fromEntries(results.map((r) => [r.name, packageRisk(r)]));
  assert.strictEqual(results.filter((r) => r.error).length, 0,
    JSON.stringify(results.filter((r) => r.error)));
  assert.ok(results.filter((r) => byName[r.name] === 'HIGH').length >= 3, JSON.stringify(byName));
  assert.strictEqual(byName['nan'], 'SAFE');
  assert.strictEqual(byName['ws'], 'SAFE');
  // husky publishes no install-time scripts (its "prepare" never runs from the
  // registry), and flagging it would be exactly the false positive we avoid
  assert.strictEqual(byName['husky'], 'SAFE');
  assert.strictEqual(byName['core-js'], 'LOW');
  const allow = buildAllowScripts(results).allowScripts;
  assert.strictEqual(JSON.parse(JSON.stringify(allow))['core-js@3.38.1'], true);
  assert.strictEqual(allow['sharp@0.32.6'], false);
});

test('npm pack ships exactly the runtime files', async () => {
  const stdout = await new Promise((resolve, reject) => {
    execFile('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'],
      { cwd: ROOT, shell: process.platform === 'win32', timeout: 120000 },
      (err, out) => (err ? reject(err) : resolve(out)));
  });
  const files = JSON.parse(stdout)[0].files.map((f) => f.path);
  for (const wanted of ['src/cli.js', 'src/analyzer.js', 'src/registry.js', 'src/reporter.js',
    'src/action.js', 'action.yml', 'README.md', 'LICENSE', 'package.json']) {
    assert.ok(files.includes(wanted), `${wanted} missing from pack`);
  }
  assert.ok(!files.some((f) => f.startsWith('test/') || f.startsWith('fixtures/') || f.startsWith('node_modules/')),
    'no dev files in pack');
});
