'use strict';
const http = require('node:http');
const zlib = require('node:zlib');
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const tar = require('tar-stream');

const ROOT = path.join(__dirname, '..');
let server, tmp, projDir, basePath, requests = [];

function makeTgz(entries) {
  return new Promise((resolve, reject) => {
    const pack = tar.pack();
    for (const [name, content] of Object.entries(entries)) pack.entry({ name }, content);
    pack.finalize();
    const gz = zlib.createGzip();
    const chunks = [];
    pack.pipe(gz);
    gz.on('data', (c) => chunks.push(c));
    gz.on('end', () => resolve(Buffer.concat(chunks)));
    gz.on('error', reject);
  });
}

before(async () => {
  const tarballs = {
    '/pkga.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'node p.js' } }),
      'package/p.js': 'require("https").get("https://x.io");',
    }),
  };
  server = http.createServer((req, res) => {
    requests.push(req.url);
    const port = server.address().port;
    if (tarballs[req.url]) return res.writeHead(200).end(tarballs[req.url]);
    const doc = {
      '/pkga/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node p.js' },
        dist: { tarball: `http://127.0.0.1:${port}/pkga.tgz` } },
      '/pkgb/2.0.0': { version: '2.0.0', scripts: {}, dist: { tarball: `http://127.0.0.1:${port}/none.tgz` } },
    }[req.url];
    if (!doc) return res.writeHead(404).end('{}');
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(doc));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  process.env.NPM_SCRIPT_LENS_REGISTRY = `http://127.0.0.1:${server.address().port}`;
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-feat-'));
  process.env.NPM_SCRIPT_LENS_CACHE_DIR = path.join(tmp, 'cache');
  projDir = path.join(tmp, 'proj');
  fs.mkdirSync(projDir);
  fs.writeFileSync(path.join(projDir, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'proj', version: '1.0.0' },
      'node_modules/pkga': { version: '1.0.0' },
      'node_modules/pkgb': { version: '2.0.0' },
    },
  }, null, 2));
  basePath = path.join(tmp, 'base-lock.json');
  fs.writeFileSync(basePath, JSON.stringify({
    lockfileVersion: 3,
    packages: { '': {}, 'node_modules/pkgb': { version: '2.0.0' } },
  }));
});

after(() => server.close());

test('cache: second audit serves from disk with zero registry requests', async () => {
  const { runAudit } = require('../src/cli');
  const first = await runAudit(projDir);
  assert.strictEqual(first.length, 2);
  assert.ok(requests.length > 0, 'first run hits the registry');
  const firstRows = first.map((r) => ({ name: r.name, rows: r.rows }));

  requests = [];
  const second = await runAudit(projDir);
  assert.strictEqual(requests.length, 0, `cached run must not fetch: ${requests}`);
  assert.ok(second.every((r) => r.cached), 'results marked as cached');
  assert.deepStrictEqual(second.map((r) => ({ name: r.name, rows: r.rows })), firstRows);

  requests = [];
  await runAudit(projDir, { cache: false });
  assert.ok(requests.length > 0, 'cache:false goes back to the registry');
});

test('diff mode audits only packages missing from the base lockfile', async () => {
  const { runAudit } = require('../src/cli');
  const results = await runAudit(projDir, { diffBase: basePath, cache: false });
  assert.deepStrictEqual(results.map((r) => r.name), ['pkga']);
});

test('buildSarif: levels, rules, lockfile line anchors, note in report', () => {
  const { buildSarif, buildReport } = require('../src/reporter');
  const results = [
    { name: 'pkga', version: '1.0.0', rows: [{ script: 'postinstall', command: 'node p.js', risk: 'MEDIUM', signals: ['net: https.get'] }] },
    { name: 'bad', version: '3.0.0', rows: [{ script: 'install', command: 'x', risk: 'HIGH', signals: ['exec: node-gyp rebuild'] }] },
    { name: 'meh', version: '4.0.0', rows: [{ script: 'postinstall', command: 'y', risk: 'LOW', signals: ['fs: writeFileSync'] }] },
    { name: 'clean', version: '5.0.0', rows: [] },
    { name: 'ghost', version: '6.0.0', rows: [], error: 'HTTP 404' },
  ];
  const lockText = fs.readFileSync(path.join(projDir, 'package-lock.json'), 'utf8');
  const sarif = buildSarif(results, { lockPath: 'package-lock.json', lockText });
  assert.strictEqual(sarif.version, '2.1.0');
  const run = sarif.runs[0];
  assert.strictEqual(run.tool.driver.name, 'npm-script-lens');
  assert.ok(run.tool.driver.rules.length >= 4);
  const byName = Object.fromEntries(run.results.map((r) => [r.message.text.split('@')[0], r]));
  assert.strictEqual(byName.bad.level, 'error');
  assert.strictEqual(byName.bad.ruleId, 'high-risk-install-script');
  assert.strictEqual(byName.pkga.level, 'warning');
  assert.strictEqual(byName.meh.level, 'note');
  assert.strictEqual(byName.ghost.ruleId, 'audit-error');
  assert.ok(!byName.clean, 'SAFE packages emit no SARIF result');
  assert.ok(byName.pkga.locations[0].physicalLocation.region.startLine > 1, 'pkga anchored to its lockfile line');
  assert.strictEqual(byName.pkga.locations[0].physicalLocation.artifactLocation.uri, 'package-lock.json');
  JSON.parse(JSON.stringify(sarif));

  const md = buildReport(results, { note: '_Diff mode: subset audited._' });
  assert.ok(md.includes('_Diff mode: subset audited._'));
});

test('cli e2e: --diff --sarif --json --no-cache work together', async () => {
  const sarifOut = path.join(tmp, 'audit.sarif');
  const out = await new Promise((resolve) => {
    const child = spawn(process.execPath, [
      path.join(ROOT, 'src', 'cli.js'), 'audit',
      '--path', projDir, '--diff', basePath, '--sarif', sarifOut, '--json', '--no-cache',
    ], { cwd: ROOT, timeout: 60000, env: { ...process.env } });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stderr.includes('added/upgraded'), out.stderr);
  const j = JSON.parse(out.stdout);
  assert.deepStrictEqual(j.results.map((r) => r.name), ['pkga']);
  assert.strictEqual(j.results[0].risk, 'MEDIUM');
  const sarif = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
  assert.strictEqual(sarif.runs[0].results.length, 1);
  assert.strictEqual(sarif.runs[0].results[0].level, 'warning');
});
