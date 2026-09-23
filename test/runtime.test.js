'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { analyzeJs, score } = require('../src/analyzer');
const { runtimeEntries, runtimeSignals, runtimePayloadFinding, gainedIocs, RUNTIME_MAX_FILES } = require('../src/runtime');
const { computeRuntimeDiff } = require('../src/diff');
const { buildReport, buildSarif, buildHtml } = require('../src/reporter');
const { start } = require('../scripts/serve-bootstrap-fixtures');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const PROJECT = path.join('fixtures', 'runtime', 'btree-project');

let mock;
before(async () => { mock = await start(); });
after(() => mock.server.close());

function run(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd: ROOT, timeout: 60000,
      env: { ...process.env, NPM_SCRIPT_LENS_REGISTRY: mock.url, NPM_SCRIPT_LENS_CACHE_DIR: path.join(os.tmpdir(), `lens-rt-${process.pid}-${args.join('_').replace(/[^a-z0-9]/gi, '')}`) },
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}
const parse = (s) => JSON.parse(s.replace(/^﻿/, ''));

const index = (paths) => new Map(paths.map((p) => [p, '']));
const signalsOf = (src, from = 'lib/index.js', files = index(['lib/worker.js', 'extended/sharedLoad.min.js', 'boot.cjs'])) => {
  const s = new Set();
  analyzeJs(src, s, new Set(), 0, { files, from });
  return [...s].filter((x) => !x.startsWith('ref: '));
};
const kinds = (sigs) => [...new Set(sigs.map((s) => s.split(':')[0]))].sort();

// --- runtimeEntries ----------------------------------------------------------

test('runtimeEntries: main, exports shapes and bin resolve to tarball paths', () => {
  const files = index(['index.js', 'lib/main.js', 'dist/index.js', 'esm/index.mjs', 'cjs/index.cjs', 'index.d.ts',
    'sub.js', 'node.js', 'browser.js', 'a.mjs', 'a.cjs', 'b.js', 'cli.js', 'bin/other.js', 'data.json', 'package.json']);
  const table = [
    [{ main: 'lib/main.js' }, ['lib/main.js']],
    [{ main: './lib/main' }, ['lib/main.js']],
    [{}, ['index.js']],
    [{ exports: './dist/index.js' }, ['dist/index.js']],
    [{ exports: { '.': { import: './esm/index.mjs', require: './cjs/index.cjs', types: './index.d.ts' } } }, ['esm/index.mjs', 'cjs/index.cjs']],
    [{ exports: { '.': './dist/index.js', './sub': './sub.js', './package.json': './package.json', './feature/*': './dist/feature/*.js', './internal': null } },
      ['dist/index.js', 'sub.js']],
    [{ exports: { node: './node.js', default: './browser.js' } }, ['node.js', 'browser.js']],
    [{ exports: { '.': { node: { import: './a.mjs', require: './a.cjs' }, default: './b.js' } } }, ['a.mjs', 'a.cjs', 'b.js']],
    [{ exports: { '.': ['./dist/index.js'] } }, ['dist/index.js']],
    [{ main: 'dist/index.js', exports: './dist/index.js' }, ['dist/index.js']],
    [{ main: 'data.json' }, []],
    [{ exports: { './': './', './sub.js.map': './sub.js.map' } }, []],
    [{ types: 'index.d.ts', exports: { types: './index.d.ts' } }, []],
    [{ bin: 'cli.js' }, ['index.js', 'cli.js']],
    [{ main: 'lib/main.js', bin: { one: './cli.js', two: 'bin/other.js' } }, ['lib/main.js', 'cli.js', 'bin/other.js']],
  ];
  for (const [manifest, want] of table) {
    assert.deepStrictEqual(runtimeEntries(manifest, files).entries, want, JSON.stringify(manifest));
  }
});

test('runtimeEntries: a bin-only package with no index.js walks just its bin', () => {
  const { entries, missing } = runtimeEntries({ bin: { tool: 'bin/tool.js' } }, index(['bin/tool.js', 'package.json']));
  assert.deepStrictEqual(entries, ['bin/tool.js']);
  assert.deepStrictEqual(missing, []);
});

test('runtimeEntries: a declared main missing from the tarball is noted, not thrown', () => {
  const { entries, missing } = runtimeEntries({ main: 'lib/gone.js', bin: 'cli.js' }, index(['cli.js']));
  assert.deepStrictEqual(entries, ['cli.js']);
  assert.deepStrictEqual(missing, ['main: lib/gone.js (not in the package)']);
});

test('runtimeEntries: a missing main falls back to index.js, as Node does, unless exports is set', () => {
  const files = index(['index.js', 'dist/esm.mjs']);
  assert.deepStrictEqual(runtimeEntries({ main: 'lib/gone.js' }, files).entries, ['index.js']);
  assert.deepStrictEqual(runtimeEntries({ main: '' }, files).entries, ['index.js']);
  assert.deepStrictEqual(runtimeEntries({ main: 'lib/gone.js', exports: './dist/esm.mjs' }, files).entries, ['dist/esm.mjs']);
});

test('runtimeEntries: an entry the index left out says why', () => {
  const { missing } = runtimeEntries({ main: 'dist/huge.js', bin: 'cli.js' }, new Map(), { skipped: ['dist/huge.js'] });
  assert.deepStrictEqual(missing, ['main: dist/huge.js (over 2 MB, not read)', 'bin: cli.js (not in the package)']);
  assert.deepStrictEqual(runtimeEntries({ exports: { import: './gone.js', require: './gone.js' } }, new Map()).missing,
    ['exports: ./gone.js (not in the package)']);
  assert.deepStrictEqual(runtimeEntries({ main: 'a.js' }, new Map(), { capped: true }).missing,
    ['main: a.js (past the offline file limit, not read)']);
});

test('runtimeEntries: an extensionless bin resolves once the index keeps it', () => {
  assert.deepStrictEqual(runtimeEntries({ bin: { tool: 'bin/tool' } }, index(['bin/tool'])).entries, ['bin/tool']);
});

test('runtimeSignals: more entry points than the budget is partial, not empty', () => {
  const n = RUNTIME_MAX_FILES + 5;
  const files = new Map([['package.json', JSON.stringify({
    exports: Object.fromEntries(Array.from({ length: n }, (_, i) => [`./m${i}`, `./m${i}.js`])),
  })]]);
  for (let i = 0; i < n; i++) files.set(`m${i}.js`, i === 0 ? "require('https').get('https://x.dev');" : '');
  const rt = runtimeSignals({ files });
  assert.strictEqual(rt.partial, true);
  assert.ok(rt.signals.some((s) => s.startsWith('net: ')), 'the entries that fit are still analyzed');
});

test('runtimeSignals: the requires of main are read before forty exports subpaths spend the budget', () => {
  const files = new Map([['package.json', JSON.stringify({
    main: 'index.js',
    exports: Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`./m${i}`, `./m${i}.js`])),
  })], ['index.js', "require('./lib/core');"],
  ['lib/core.js', "module.exports = 'https://api.telegram.org/bot0:x/sendMessage';"]]);
  for (let i = 0; i < 40; i++) files.set(`m${i}.js`, '');
  const rt = runtimeSignals({ files });
  assert.deepStrictEqual(rt.signals, ['exfil: api.telegram.org/bot']);
  assert.strictEqual(rt.partial, false);
});

test('runtimeSignals: a payload eight requires below main is read, only the file budget cuts a walk', () => {
  const files = new Map([['package.json', '{"main":"l0.js"}']]);
  for (let i = 0; i < 8; i++) files.set(`l${i}.js`, `require('./l${i + 1}')`);
  files.set('l8.js', "module.exports = 'https://api.telegram.org/bot0:x/sendMessage';");
  const rt = runtimeSignals({ files });
  assert.deepStrictEqual(rt.signals, ['exfil: api.telegram.org/bot']);
  assert.strictEqual(rt.partial, false);
});

test('runtimeSignals: an ESM-only package is followed through import, per-file signals kept', () => {
  const files = new Map([
    ['package.json', JSON.stringify({ type: 'module', exports: { '.': { import: './index.mjs' } } })],
    ['index.mjs', "export * from './lib/send.mjs';"],
    ['lib/send.mjs', "export const hook = 'https://discord.com/api/webhooks/1/x';"],
  ]);
  const rt = runtimeSignals({ files });
  assert.deepStrictEqual(rt.signals, ['exfil: discord.com/api/webhooks']);
  assert.deepStrictEqual([...rt.byFile.keys()], ['lib/send.mjs']);
});

test('runtimeSignals: no package.json and no index.js is an empty result', () => {
  const rt = runtimeSignals({ files: new Map() });
  assert.deepStrictEqual([rt.signals, rt.entries, rt.missing, rt.partial], [[], [], [], false]);
});

// --- detectors ---------------------------------------------------------------

test('exec-local: process.execPath or node on a file the package ships', () => {
  const hits = {
    "require('child_process').spawn(process.execPath, [require('path').join(__dirname, 'worker.js')], { detached: true });":
      'exec-local: process.execPath lib/worker.js (detached)',
    "const cp = require('child_process'); cp.spawn(process.execPath, [`${__dirname}/worker.js`]);":
      'exec-local: process.execPath lib/worker.js',
    "import { spawn } from 'node:child_process'; import { fileURLToPath } from 'node:url'; spawn(process.execPath, [fileURLToPath(new URL('./worker.js', import.meta.url))]);":
      'exec-local: process.execPath lib/worker.js',
    // the btree loader's own shape: the "node" literal, the path held in a variable
    "const path = require('path'); const { spawn } = require('child_process'); const loadPath = path.join(__dirname, '..', 'extended', 'sharedLoad.min.js'); spawn('node', [loadPath, String(k)]);":
      'exec-local: node extended/sharedLoad.min.js',
    "require('child_process').spawn(process.execPath, ['boot.cjs']);": 'exec-local: process.execPath boot.cjs',
    '"use strict";var a=require("child_process"),b=require("path");function c(d){d===100&&a.spawn(process.execPath,[b.join(__dirname,"worker.js")],{detached:!0})}module.exports=c;':
      'exec-local: process.execPath lib/worker.js (detached)',
  };
  for (const [src, want] of Object.entries(hits)) assert.ok(signalsOf(src).includes(want), `${src}\n${signalsOf(src)}`);
});

test('exec-local: other binaries, eval flags, unshipped literals and fork do not fire', () => {
  for (const src of [
    "require('child_process').spawn('git', ['status']);",
    "require('child_process').spawn(process.execPath, ['-e', '1']);",
    "require('child_process').spawn(process.execPath, ['nothere.js']);",
    "require('child_process').fork(require('path').join(__dirname, 'worker.js'));",
    "const re = /a/; re.exec('x'); const m = new Map(); m.get('k');",
    // the user's file, not one the package ships
    "const path = require('path'); require('child_process').spawn(process.execPath, [path.resolve(process.cwd(), file)]);",
    "const path = require('path'); require('child_process').spawn('node', [path.join(process.cwd(), 'scripts', 'build.js')]);",
  ]) assert.ok(!kinds(signalsOf(src)).includes('exec-local'), src);
});

test('exec-local: a name bound twice or as a parameter is not followed', () => {
  for (const src of [
    "const path = require('path'); const worker = path.join(__dirname, 'worker.js'); function run(worker) { require('child_process').spawn('node', [worker]); }",
    "const path = require('path'); let f = path.join(__dirname, 'worker.js'); f = process.argv[2]; require('child_process').spawn('node', [f]);",
    "const path = require('path'); function a() { const f = path.join(__dirname, 'worker.js'); return f; } function b(x) { const f = x; require('child_process').spawn('node', [f]); }",
  ]) assert.ok(!kinds(signalsOf(src)).includes('exec-local'), src);
});

test('concatenation: a long literal chain folds, a partly literal chain still yields its literal run', () => {
  const long = `const u = ${Array.from({ length: 500 }, () => "'a'").join(' + ')} + 'https://hooks.slack.com/services/x';`;
  assert.ok(signalsOf(long).includes('exfil: hooks.slack.com/services'));
  assert.ok(signalsOf("const u = ('https://hooks.sla' + 'ck.com/services/') + id;").includes('exfil: hooks.slack.com/services'));
});

test('c2: RPC hosts, eth_call, and a contract only next to an RPC host', () => {
  const cases = [
    ["const r = 'https://eth-sepolia.g.alchemy.com/v2/';", ['c2: eth-sepolia.g.alchemy.com']],
    ['const r = `https://sepolia.infura.io/v3/${key}`;', ['c2: sepolia.infura.io']],
    ["const r = 'https://rpc.ankr.com/eth_sepolia';", ['c2: rpc.ankr.com']],
    ["const r = 'https://ethereum-sepolia-rpc.publicnode.com';", ['c2: ethereum-sepolia-rpc.publicnode.com']],
    ["const body = { method: 'eth_call' };", ['c2: eth_call']],
    [`const r = 'https://holesky.example.dev', to = '0x${'ab'.repeat(20)}';`, [`c2: contract 0x${'ab'.repeat(20)}`, 'c2: holesky.example.dev']],
  ];
  for (const [src, want] of cases) assert.deepStrictEqual(signalsOf(src).filter((s) => s.startsWith('c2: ')).sort(), want, src);
  for (const src of [
    "module.exports = { chains: ['sepolia', 'mainnet'] };",
    "const d = 'https://docs.alchemy.com/reference'; const i = 'https://docs.infura.io/api';",
    "const r = 'https://www.ankr.com/rpc/';",
    `const token = '0x${'ab'.repeat(20)}';`,
    '// RPC: https://eth-sepolia.g.alchemy.com/v2/\nmodule.exports = 1;',
  ]) assert.deepStrictEqual(signalsOf(src).filter((s) => s.startsWith('c2: ')), [], src);
});

test('exfil: bot and webhook endpoints, including concatenated ones; comments and docs do not fire', () => {
  const cases = [
    ["fetch('https://api.telegram.org/bot' + token + '/sendMessage');", 'exfil: api.telegram.org/bot'],
    ["const t = 'https://api.tele' + 'gram.org/bot' + token;", 'exfil: api.telegram.org/bot'],
    ['fetch(`https://hooks.slack.com/services/${a}/${b}`);', 'exfil: hooks.slack.com/services'],
    ["post('https://slack.com/api/chat.postMessage');", 'exfil: slack.com/api/chat.postMessage'],
    ["fetch('https://discord.com/api/webhooks/1/x');", 'exfil: discord.com/api/webhooks'],
  ];
  for (const [src, want] of cases) assert.ok(signalsOf(src).includes(want), src);
  for (const src of [
    '// Bot API docs: https://api.telegram.org/bot<token>/getMe\nmodule.exports = 1;',
    "const docs = 'https://core.telegram.org/bots/api';",
    "const help = 'https://api.slack.com/messaging/webhooks';",
  ]) assert.deepStrictEqual(kinds(signalsOf(src)).filter((k) => k === 'exfil'), [], src);
});

test('obf: the string-array rotation prelude fires where the literals are encoded; a round-robin does not', () => {
  // The prelude javascript-obfuscator emits, names shortened. The encoded
  // strings in the array are what hide any c2 or exfil literal.
  const prelude = "(function(g,t){const d=_0x1,a=g();while(!![]){try{const c=-parseInt(d(0x1e0,'aB'))/0x1+parseInt(d(0x1e1,'cD'))/0x2;" +
    "if(c===t)break;else a['push'](a['shift']());}catch(e){a['push'](a['shift']());}}}(_0x2,0x5f1a3));";
  assert.ok(signalsOf(prelude).includes('obf: string-array rotation (obfuscator.io)'));
  for (const src of [
    'const q = []; while (q.length) { const job = q.shift(); if (!run(job)) q.push(job); }',
    'for (let i = 0; i < n; i++) { peers.push(peers.shift()); }',
    "while (x) { a.push(b.shift()); parseInt('1'); }",
  ]) assert.deepStrictEqual(kinds(signalsOf(src)).filter((k) => k === 'obf'), [], src);
});

test('score: c2 and exfil rank HIGH everywhere, exec-local only in runtime mode', () => {
  assert.strictEqual(score(['c2: sepolia.infura.io']), 'HIGH');
  assert.strictEqual(score(['exfil: api.telegram.org/bot']), 'HIGH');
  assert.strictEqual(score(['exec-local: process.execPath worker.js']), 'SAFE');
  assert.strictEqual(score(['exec-local: process.execPath worker.js'], { runtime: true }), 'HIGH');
  assert.strictEqual(score(['net: fetch()'], { runtime: true }), 'MEDIUM');
});

test('runtimePayloadFinding: only IOC kinds, MEDIUM alone, HIGH for exfil or two kinds', () => {
  const rt = (signals) => ({ signals, byFile: new Map([['index.js', signals]]), partial: false });
  assert.strictEqual(runtimePayloadFinding(rt(['exec: git', 'net: fetch()', 'fs: writeFileSync()'])), null);
  assert.strictEqual(runtimePayloadFinding(rt(['c2: mainnet.infura.io', 'net: fetch()'])).risk, 'MEDIUM');
  assert.strictEqual(runtimePayloadFinding(rt(['exec-local: node worker.js'])).risk, 'MEDIUM');
  assert.strictEqual(runtimePayloadFinding(rt(['exfil: hooks.slack.com/services'])).risk, 'HIGH');
  assert.strictEqual(runtimePayloadFinding(rt(['obf: eval()', 'obf: atob() base64 decode'])), null);
  // the real btree second stage: its endpoints encoded, only the loader and the prelude left to see
  const encoded = runtimePayloadFinding(rt(['exec-local: node extended/sharedLoad.min.js (detached)',
    'obf: string-array rotation (obfuscator.io)', 'net: fetch()']));
  assert.deepStrictEqual([encoded.risk, encoded.hits.length], ['HIGH', 2]);
  const both = runtimePayloadFinding(rt(['c2: eth_call', 'exec-local: node x.js', 'exec: node']));
  assert.strictEqual(both.risk, 'HIGH');
  assert.deepStrictEqual(both.hits, [
    { signal: 'c2: eth_call', files: ['index.js'] },
    { signal: 'exec-local: node x.js', files: ['index.js'] },
  ]);
});

test('computeRuntimeDiff: moved signals are not gained; gaining only net does not gate', () => {
  const side = (byFile) => {
    const signals = [...new Set(Object.values(byFile).flat())].sort();
    return { signals, byFile: new Map(Object.entries(byFile)), entries: ['index.js'], missing: [], partial: false };
  };
  const moved = computeRuntimeDiff(side({ 'a.js': ['exec: git'] }), side({ 'b.js': ['exec: git'] }));
  assert.deepStrictEqual([moved.gained, moved.lost, moved.changed], [[], [], false]);
  const net = computeRuntimeDiff(side({}), side({ 'a.js': ['net: fetch()'] }));
  assert.deepStrictEqual([net.gained.length, net.changed], [1, false]);
  const lost = computeRuntimeDiff(side({ 'a.js': ['exec: git'] }), side({}));
  assert.deepStrictEqual([lost.lost.map((l) => l.signal), lost.changed], [['exec: git'], false]);
  // a bundler's content hash changing on every release is not a new spawn
  const hashed = computeRuntimeDiff(side({ 'a.js': ['exec-local: process.execPath dist/worker.3f9a1c2b.js'] }),
    side({ 'a.js': ['exec-local: process.execPath dist/worker.8e41d0aa.js'] }));
  assert.deepStrictEqual([hashed.gained, hashed.lost, hashed.changed], [[], [], false]);
  const renamed = computeRuntimeDiff(side({ 'a.js': ['exec-local: node dist/worker.js'] }),
    side({ 'a.js': ['exec-local: node dist/loader.js'] }));
  assert.strictEqual(renamed.changed, true, 'a different file name is still a change');
});

test('gainedIocs: payload-shaped signals the base did not have, content hashes aside', () => {
  const rt = (signals) => ({ signals });
  assert.deepStrictEqual(gainedIocs(rt(['c2: eth_call', 'net: fetch()']), rt(['c2: eth_call', 'exfil: api.telegram.org/bot', 'exec: git'])),
    ['exfil: api.telegram.org/bot']);
  assert.deepStrictEqual(gainedIocs(rt(['exec-local: node w.1a2b3c4d.js']), rt(['exec-local: node w.9f8e7d6c.js'])), []);
});

// --- the btree worked example, end to end through the mock registry ------------

test('diff --runtime: btree-good 1.0.0 -> 1.0.1 gains exec-local, c2 and exfil and exits 1', async () => {
  const r = await run(['diff', 'btree-good@1.0.0', 'btree-good@1.0.1', '--runtime']);
  assert.strictEqual(r.status, 1, r.stderr);
  assert.match(r.stdout, /GAINED: exec-local \(index\.js\) process\.execPath extended\/sharedLoad\.min\.js \(detached\)/);
  assert.match(r.stdout, /GAINED: c2 \(extended\/sharedLoad\.min\.js\) eth-sepolia\.g\.alchemy\.com/);
  assert.match(r.stdout, /GAINED: exfil \(extended\/sharedLoad\.min\.js\) api\.telegram\.org\/bot/);
});

test('diff --runtime --json carries a runtime block', async () => {
  const r = await run(['diff', 'btree-good@1.0.0', 'btree-good@1.0.1', '--runtime', '--json']);
  assert.strictEqual(r.status, 1, r.stderr);
  const rt = parse(r.stdout).runtime;
  assert.strictEqual(rt.changed, true);
  assert.deepStrictEqual(rt.new.entries, ['index.js']);
  const gained = new Set(rt.gained.filter((g) => g.risk === 'HIGH').map((g) => g.kind));
  for (const k of ['exec-local', 'c2', 'exfil']) assert.ok(gained.has(k), k);
  assert.deepStrictEqual(rt.lost, []);
});

test('diff without --runtime cannot see it: no script changed, exit 0', async () => {
  const r = await run(['diff', 'btree-good@1.0.0', 'btree-good@1.0.1']);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /GAINED/);
});

test('diff --runtime of a version against itself reports no change', async () => {
  const r = await run(['diff', 'btree-good@1.0.1', 'btree-good@1.0.1', '--runtime']);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.match(r.stdout, /no runtime capability changes/);
});

test('audit --runtime reports only IOC kinds, as RUNTIME_PAYLOAD, in every output', async () => {
  const sarif = path.join(os.tmpdir(), `lens-rt-${process.pid}.sarif`);
  const r = await run(['audit', '--path', PROJECT, '--runtime', '--no-trust', '--json', '--sarif', sarif]);
  assert.strictEqual(r.status, 0, r.stderr);
  const results = parse(r.stdout).results;
  const byName = Object.fromEntries(results.map((x) => [x.name, x.runtimePayload || null]));
  assert.strictEqual(byName['btree-good'].risk, 'HIGH');
  assert.deepStrictEqual(kinds(byName['btree-good'].hits.map((h) => h.signal)), ['c2', 'exec-local', 'exfil']);
  assert.strictEqual(byName['rpc-wallet'].risk, 'MEDIUM');
  assert.strictEqual(byName['git-helper'], null, 'plain exec + net is not a payload');
  assert.strictEqual(byName['pool-lib'], null, 'forking a bundled worker is not a payload');

  const doc = JSON.parse(fs.readFileSync(sarif, 'utf8'));
  fs.rmSync(sarif, { force: true });
  const hits = doc.runs[0].results.filter((x) => x.ruleId === 'runtime-payload');
  assert.deepStrictEqual(hits.map((x) => x.level).sort(), ['error', 'warning']);
  assert.ok(doc.runs[0].tool.driver.rules.some((x) => x.id === 'runtime-payload'));

  const md = buildReport(results);
  assert.match(md, /## 🔴 Runtime payload \(2\)/);
  assert.match(md, /`btree-good@1\.0\.1` 🔴 HIGH \*\*RUNTIME_PAYLOAD\*\*/);
  assert.doesNotMatch(md, /git-helper@2\.0\.0` .*RUNTIME_PAYLOAD/);
  assert.match(buildHtml(results), /Runtime payload<\/h2>/);
  assert.strictEqual(buildSarif(results).runs[0].results.filter((x) => x.ruleId === 'runtime-payload').length, 2);
});

test('audit --fail-on-runtime-payload exits 1 on a HIGH payload and implies --runtime', async () => {
  const r = await run(['audit', '--path', PROJECT, '--no-trust', '--fail-on-runtime-payload']);
  assert.strictEqual(r.status, 1);
  assert.match(r.stderr, /FAIL: 1 package\(s\) carry a HIGH runtime payload/);
});

test('audit without --runtime does not read runtime code', async () => {
  const r = await run(['audit', '--path', PROJECT, '--no-trust', '--json']);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.ok(parse(r.stdout).results.every((x) => !x.runtimePayload));
});

test('audit --runtime: a package whose tarball cannot be fetched is named, not dropped', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-rt-missing-'));
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({
    name: 'x', version: '1.0.0', lockfileVersion: 3,
    packages: { '': { name: 'x', version: '1.0.0' }, 'node_modules/not-on-registry': { version: '9.9.9' } },
  }));
  const r = await run(['audit', '--path', dir, '--runtime', '--no-trust']);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(r.stdout, /not-on-registry@9\.9\.9/);
});

test('audit --runtime --diff: an upgrade names the hits its base version did not have', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-rt-diff-'));
  const lock = (btree, wallet) => JSON.stringify({
    name: 'x', version: '1.0.0', lockfileVersion: 3,
    packages: { '': { name: 'x', version: '1.0.0' }, 'node_modules/btree-good': { version: btree }, 'node_modules/rpc-wallet': { version: wallet } },
  });
  fs.writeFileSync(path.join(dir, 'package-lock.json'), lock('1.0.1', '3.0.0'));
  fs.writeFileSync(path.join(dir, 'base.json'), lock('1.0.0', '2.0.0'));
  const r = await run(['audit', '--path', dir, '--diff', path.join(dir, 'base.json'), '--runtime', '--no-trust', '--json']);
  const md = await run(['audit', '--path', dir, '--diff', path.join(dir, 'base.json'), '--runtime', '--no-trust']);
  fs.rmSync(dir, { recursive: true, force: true });
  const byName = Object.fromEntries(parse(r.stdout).results.map((x) => [x.name, x.runtimePayload]));
  assert.strictEqual(byName['btree-good'].base.version, '1.0.0');
  assert.deepStrictEqual(kinds(byName['btree-good'].base.gained), ['c2', 'exec-local', 'exfil']);
  assert.deepStrictEqual(byName['rpc-wallet'].base, { version: '2.0.0', gained: null }, 'a base the registry lacks is not compared');
  assert.match(md.stdout, /api\.telegram\.org\/bot` \(extended\/sharedLoad\.min\.js\) \*\*new since 1\.0\.0\*\*/);
  assert.match(md.stdout, /rpc-wallet@3\.0\.0` .* _\(2\.0\.0 could not be read to compare\)_/);
});

test('reporter: runtime payloads count in the summary, and unread runtime code is named', () => {
  const results = [
    { name: 'a', version: '1.0.0', rows: [], runtimePayload: { risk: 'HIGH', hits: [{ signal: 'exfil: api.telegram.org/bot', files: ['i.js'] }], partial: false } },
    { name: 'b', version: '1.0.0', rows: [], runtimeUnread: { partial: false, missing: ['main: dist/huge.js (over 2 MB, not read)'] } },
    { name: 'c', version: '1.0.0', rows: [] },
    { name: 'd', version: '1.0.0', rows: [], runtimeUnread: { partial: true, missing: [] } },
  ];
  const md = buildReport(results);
  assert.match(md, /\*\*4\*\* with no risky install-time behavior; \*\*1\*\* with a runtime payload\./);
  assert.match(md, /Runtime code only partly read for 2 package\(s\).*`b@1\.0\.0` \(main: dist\/huge\.js \(over 2 MB, not read\)\), `d@1\.0\.0` \(past the 200-file budget\)/);
  const html = buildHtml(results);
  assert.match(html, />3<\/div><div class="l">clean</);
  assert.match(html, />1<\/div><div class="l">runtime payload</);
  assert.deepStrictEqual(buildReport(results.slice(2, 3)).match(/Runtime payload/), null);
});
