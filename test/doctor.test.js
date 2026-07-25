'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { classifyDryRun } = require('../src/review');
const { SAMPLE_DRY_RUN } = require('../src/npm-contract');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
let tmp, npm10, npm12, npm13drift;

function runCli(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd: ROOT, timeout: 60000, env: { ...process.env, ...env } });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdin.end();
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}

const mkProj = (name) => {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  return dir;
};

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-doctor-'));
  npm10 = path.join(tmp, 'npm10.js');
  fs.writeFileSync(npm10, "if (process.argv.includes('--version')) { console.log('10.9.3'); process.exit(0); }\n");
  // v12 that speaks the recognized dialect
  npm12 = path.join(tmp, 'npm12.js');
  fs.writeFileSync(npm12, `
    if (process.argv.includes('--version')) { console.log('12.0.1'); process.exit(0); }
    console.log('add core-js 3.38.1');
    console.log(JSON.stringify({ added: 1, unreviewedScripts: [
      { name: 'core-js', version: '3.38.1', scripts: { postinstall: 'node p.js' } },
    ] }));
  `);
  // a future npm that RENAMED the key and dropped the summary — an
  // unambiguous shape doctor can flag without ground truth
  npm13drift = path.join(tmp, 'npm13.js');
  fs.writeFileSync(npm13drift, `
    if (process.argv.includes('--version')) { console.log('13.0.0'); process.exit(0); }
    console.log(JSON.stringify({ pendingScripts: [{ name: 'x', version: '1.0.0' }] }));
  `);
});

after(() => fs.rmSync(tmp, { recursive: true, force: true }));

test('classifyDryRun: recognizes pending, empty, error, and drift shapes', () => {
  // canonical samples (the doctor self-test uses these)
  assert.strictEqual(classifyDryRun(SAMPLE_DRY_RUN.pending).kind, 'pending');
  assert.strictEqual(classifyDryRun(SAMPLE_DRY_RUN.empty).kind, 'empty');
  // pending with entries, noisy human lines first
  const p = classifyDryRun('add a 1.0.0\n{"added":1,"unreviewedScripts":[{"name":"a","version":"1.0.0"}]}');
  assert.strictEqual(p.kind, 'pending');
  assert.deepStrictEqual(p.pending, [{ name: 'a', version: '1.0.0', scripts: {} }]);
  // explicit empty array, and omitted key with a summary, both = nothing pending
  assert.strictEqual(classifyDryRun('{"unreviewedScripts":[]}').kind, 'empty');
  assert.strictEqual(classifyDryRun('{"added":0,"audited":5,"removed":0}').kind, 'empty');
  // npm errored / no JSON = not an answer
  assert.strictEqual(classifyDryRun('{"error":{"code":"ENETDOWN"}}').kind, 'error');
  assert.strictEqual(classifyDryRun('npm ERR! network').kind, 'error');
  assert.strictEqual(classifyDryRun('').kind, 'error');
  // DRIFT (unambiguous): valid JSON with no recognizable key and no summary —
  // a renamed key without a summary, or the wrong type on the key we depend on
  assert.strictEqual(classifyDryRun('{"pendingScripts":[{"name":"x"}]}').kind, 'unrecognized');
  assert.strictEqual(classifyDryRun('{"unreviewedScripts":{"a":1}}').kind, 'unrecognized');
  assert.strictEqual(classifyDryRun('{"foo":1}').kind, 'unrecognized');
  // AMBIGUOUS: a rename that KEEPS the summary is byte-identical to a real
  // "nothing pending" summary — read as empty here; the canary's ground-truth
  // check (a planted scripted dep) is what catches this rename, not the parser
  assert.strictEqual(classifyDryRun('{"added":1,"pendingScripts":[{"name":"x"}]}').kind, 'empty');
});

test('doctor: clean on npm < 12 (self-test ok, live probe skipped)', async () => {
  const out = await runCli(['doctor', '--path', mkProj('d10')], { NPM_SCRIPT_LENS_NPM: `node ${npm10}` });
  assert.strictEqual(out.status, 0, out.stdout);
  assert.ok(out.stdout.includes('npm v10 detected'), out.stdout);
  assert.ok(out.stdout.includes('parser self-test'));
  assert.ok(out.stdout.includes('does not enforce allowScripts'), out.stdout);
  assert.ok(out.stdout.includes('No drift detected'));
});

test('doctor: recognizes a real-shaped npm v12 live probe', async () => {
  const out = await runCli(['doctor', '--path', mkProj('d12')], { NPM_SCRIPT_LENS_NPM: `node ${npm12}` });
  assert.strictEqual(out.status, 0, out.stdout);
  assert.ok(out.stdout.includes('enforces allowScripts'), out.stdout);
  assert.ok(/live dry-run probe.*output recognized.*1 package/.test(out.stdout), out.stdout);
  assert.ok(out.stdout.includes('No drift detected'));
});

test('doctor: FAILS (exit 1) when a future npm renames the pending key', async () => {
  const out = await runCli(['doctor', '--path', mkProj('d13')], { NPM_SCRIPT_LENS_NPM: `node ${npm13drift}` });
  assert.strictEqual(out.status, 1, out.stdout);
  assert.ok(out.stdout.includes('not a shape this build recognizes'), out.stdout);
  assert.ok(out.stdout.includes('Drift detected'), out.stdout);
});

test('doctor --json emits a structured report', async () => {
  const out = await runCli(['doctor', '--path', mkProj('djson'), '--json'], { NPM_SCRIPT_LENS_NPM: `node ${npm12}` });
  assert.strictEqual(out.status, 0, out.stderr);
  const r = JSON.parse(out.stdout);
  assert.strictEqual(r.tool, 'npm-script-lens');
  assert.strictEqual(r.npmMajor, 12);
  assert.strictEqual(r.ok, true);
  assert.ok(Array.isArray(r.checks) && r.checks.length >= 6);
  assert.ok(r.checks.some((c) => c.name === 'live dry-run probe' && c.status === 'ok'));
});

test('doctor --no-live skips the live probe but still self-tests', async () => {
  const out = await runCli(['doctor', '--path', mkProj('dnolive'), '--no-live'], { NPM_SCRIPT_LENS_NPM: `node ${npm12}` });
  assert.strictEqual(out.status, 0, out.stdout);
  assert.ok(out.stdout.includes('live dry-run probe: skipped (--no-live)'), out.stdout);
  assert.ok(out.stdout.includes('parser self-test'));
});
