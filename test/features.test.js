'use strict';
const http = require('node:http');
const zlib = require('node:zlib');
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const tar = require('tar-stream');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
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

const writeLock = (file, packages) => fs.writeFileSync(file, JSON.stringify({
  lockfileVersion: 3,
  packages: { '': { name: 'proj', version: '1.0.0' }, ...packages },
}, null, 2));

const writeProj = (name, packages, pkgJson = { name: 'proj', version: '1.0.0' }) => {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  writeLock(path.join(dir, 'package-lock.json'), packages);
  fs.writeFileSync(path.join(dir, 'package.json'), `${JSON.stringify(pkgJson, null, 2)}\n`);
  return dir;
};

function runCli(args, { input } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd: ROOT, timeout: 60000, env: { ...process.env } });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    if (input !== undefined) child.stdin.write(input);
    child.stdin.end();
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}

before(async () => {
  const netScript = { 'package/package.json': JSON.stringify({ scripts: { postinstall: 'node p.js' } }),
    'package/p.js': 'require("https").get("https://x.io");' };
  const tarballs = {
    '/pkga.tgz': await makeTgz(netScript),
    '/pkgc1.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'node p.js' } }),
      'package/p.js': 'const v = process.env.FOO;',
    }),
    '/pkgc2.tgz': await makeTgz(netScript),
    '/toolpkg.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ name: 'toolpkg', bin: { toolpkg: './cli.js' } }),
      'package/cli.js': 'require("fs").writeFileSync("marker", "1");',
    }),
    '/userpkg.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'toolpkg install' } }),
    }),
    '/helper.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ name: 'helper', main: 'index.js' }),
      'package/index.js': 'require("https").get("https://dl.example");',
    }),
    '/usehelper.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'node u.js' } }),
      'package/u.js': 'require("helper");',
    }),
  };
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      requests.push(req.url);
      const port = server.address().port;
      if (tarballs[req.url]) return res.writeHead(200).end(tarballs[req.url]);
      if (req.url === '/v1/querybatch') {
        const queries = JSON.parse(body).queries;
        return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
          results: queries.map((q) => (q.package.name === 'pkga' && q.version === '1.0.0'
            ? { vulns: [{ id: 'MAL-2026-0001' }, { id: 'GHSA-not-mal' }] } : {})),
        }));
      }
      if (req.url === '/downloads/point/last-week/pkga') {
        return res.writeHead(200, { 'content-type': 'application/json' }).end('{"downloads":42}');
      }
      const scriptedDoc = (v, tgz) => ({ version: v, scripts: { postinstall: 'node p.js' },
        dist: { tarball: `http://127.0.0.1:${port}${tgz}` } });
      const doc = {
        '/pkga/1.0.0': scriptedDoc('1.0.0', '/pkga.tgz'),
        '/pkga/0.9.0': scriptedDoc('0.9.0', '/pkga.tgz'),
        '/pkgb/2.0.0': { version: '2.0.0', scripts: {}, dist: { tarball: `http://127.0.0.1:${port}/none.tgz` } },
        '/pkgc/1.0.0': scriptedDoc('1.0.0', '/pkgc1.tgz'),
        '/pkgc/2.0.0': scriptedDoc('2.0.0', '/pkgc2.tgz'),
        '/toolpkg/1.0.0': { version: '1.0.0', scripts: {}, bin: { toolpkg: './cli.js' },
          dist: { tarball: `http://127.0.0.1:${port}/toolpkg.tgz` } },
        '/userpkg/1.0.0': { version: '1.0.0', scripts: { postinstall: 'toolpkg install' },
          dist: { tarball: `http://127.0.0.1:${port}/userpkg.tgz` } },
        '/helper/1.0.0': { version: '1.0.0', scripts: {}, main: 'index.js',
          dist: { tarball: `http://127.0.0.1:${port}/helper.tgz` } },
        '/usehelper/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node u.js' },
          dist: { tarball: `http://127.0.0.1:${port}/usehelper.tgz` } },
        '/pkga': {
          time: { '1.0.0': '2026-07-01T00:00:00.000Z' },
          maintainers: [{ name: 'solo' }],
          versions: { '1.0.0': { dist: { attestations: { url: 'sigstore' } } } },
        },
      }[req.url];
      if (!doc) return res.writeHead(404).end('{}');
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(doc));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  process.env.NPM_SCRIPT_LENS_REGISTRY = base;
  process.env.NPM_SCRIPT_LENS_OSV_API = base;
  process.env.NPM_SCRIPT_LENS_DL_API = base;
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-feat-'));
  process.env.NPM_SCRIPT_LENS_CACHE_DIR = path.join(tmp, 'cache');
  projDir = writeProj('proj', {
    'node_modules/pkga': { version: '1.0.0', dependencies: { pkgb: '^2.0.0' } },
    'node_modules/pkgb': { version: '2.0.0' },
  });
  basePath = path.join(tmp, 'base-lock.json');
  writeLock(basePath, { 'node_modules/pkgb': { version: '2.0.0' } });
});

after(() => server.close());

test('cache: second audit serves from disk with zero registry requests', async () => {
  const { runAudit } = require('../src/cli');
  const first = await runAudit(projDir, { trust: false });
  assert.strictEqual(first.length, 2);
  assert.ok(requests.length > 0, 'first run hits the registry');
  const firstRows = first.map((r) => ({ name: r.name, rows: r.rows }));

  requests = [];
  const second = await runAudit(projDir, { trust: false });
  assert.strictEqual(requests.length, 0, `cached run must not fetch: ${requests}`);
  assert.ok(second.every((r) => r.cached), 'results marked as cached');
  assert.deepStrictEqual(second.map((r) => ({ name: r.name, rows: r.rows })), firstRows);

  requests = [];
  await runAudit(projDir, { cache: false, trust: false });
  assert.ok(requests.length > 0, 'cache:false goes back to the registry');
});

test('via chains come from lockfile dependency edges', async () => {
  const { runAudit } = require('../src/cli');
  const results = await runAudit(projDir, { trust: false });
  const byName = Object.fromEntries(results.map((r) => [r.name, r]));
  assert.deepStrictEqual(byName.pkgb.via, ['pkga']);
  assert.strictEqual(byName.pkga.via, undefined, 'top-level package has no via chain');
});

test('diff mode audits only new packages and reports gained capabilities on upgrades', async () => {
  const { runAudit } = require('../src/cli');
  const upgProj = writeProj('upgproj', { 'node_modules/pkgc': { version: '2.0.0' } });
  const upgBase = path.join(tmp, 'upg-base-lock.json');
  writeLock(upgBase, { 'node_modules/pkgc': { version: '1.0.0' }, 'node_modules/pkgb': { version: '2.0.0' } });
  const results = await runAudit(upgProj, { diffBase: upgBase, cache: false, trust: false });
  assert.deepStrictEqual(results.map((r) => r.name), ['pkgc']);
  assert.strictEqual(results[0].base.version, '1.0.0');
  assert.ok(results[0].base.gained.some((s) => s.startsWith('net: ')), JSON.stringify(results[0].base));
  // added (not upgraded) packages carry no base comparison
  const addResults = await runAudit(projDir, { diffBase: basePath, cache: false, trust: false });
  assert.deepStrictEqual(addResults.map((r) => r.name), ['pkga']);
  assert.strictEqual(addResults[0].base, undefined);
});

test('trust: OSV MAL advisory flags package, forces allowScripts false, renders badge', async () => {
  const { runAudit } = require('../src/cli');
  const { buildReport, buildAllowScripts, buildSarif } = require('../src/reporter');
  const results = await runAudit(projDir, { cache: false });
  const pkga = results.find((r) => r.name === 'pkga');
  assert.strictEqual(pkga.malicious, true);
  assert.deepStrictEqual(pkga.advisories, ['MAL-2026-0001'], 'GHSA ids are not malware flags');
  assert.deepStrictEqual(pkga.trust, {
    publishedAt: '2026-07-01T00:00:00.000Z',
    ageDays: pkga.trust.ageDays,
    weeklyDownloads: 42,
    maintainers: 1,
    provenance: true,
  });
  assert.ok(typeof pkga.trust.ageDays === 'number' && pkga.trust.ageDays >= 0);
  assert.strictEqual(buildAllowScripts(results).allowScripts['pkga@1.0.0'], false);
  const md = buildReport(results);
  assert.ok(md.includes('⛔ MALICIOUS'), md.split('\n')[2]);
  assert.ok(md.includes('KNOWN MALICIOUS'));
  assert.ok(md.includes('42 dl/wk'));
  assert.ok(md.includes('provenance ✓'));
  const sarif = buildSarif(results);
  const mal = sarif.runs[0].results.find((r) => r.ruleId === 'known-malicious-package');
  assert.strictEqual(mal.level, 'error');
});

test('offline mode analyzes node_modules without touching the registry', async () => {
  const { runAudit } = require('../src/cli');
  const dir = writeProj('offproj', { 'node_modules/pkgx': { version: '1.0.0' } });
  const nm = path.join(dir, 'node_modules', 'pkgx');
  fs.mkdirSync(nm, { recursive: true });
  fs.writeFileSync(path.join(nm, 'package.json'),
    JSON.stringify({ name: 'pkgx', version: '1.0.0', scripts: { postinstall: 'node x.js' } }));
  fs.writeFileSync(path.join(nm, 'x.js'), 'require("child_process").execSync("id");');
  requests = [];
  const results = await runAudit(dir, { offline: true, cache: false });
  assert.strictEqual(requests.length, 0, 'offline audit must not fetch');
  assert.strictEqual(results[0].rows[0].risk, 'HIGH');
  // missing from node_modules -> clean per-package error, not a crash
  const dir2 = writeProj('offproj2', { 'node_modules/ghostpkg': { version: '3.0.0' } });
  const missing = await runAudit(dir2, { offline: true, cache: false });
  assert.ok(missing[0].error.includes('offline'), missing[0].error);
});

test('sync: preserves decisions across no-gain upgrades, drops stale, adds new', async () => {
  const dir = writeProj('syncproj', {
    'node_modules/pkga': { version: '1.0.0' },
    'node_modules/pkgc': { version: '2.0.0' },
  }, { name: 'proj', version: '1.0.0', allowScripts: { 'pkga@0.9.0': true, 'gone@1.0.0': false } });
  const out = await runCli(['sync', '--path', dir, '--no-trust', '--no-cache', '--write']);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stdout.includes('decision **preserved**'), out.stdout);
  assert.ok(out.stdout.includes('`gone@1.0.0`'), 'stale entry reported');
  assert.ok(out.stdout.includes('new: `pkgc@2.0.0`'), out.stdout);
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  assert.deepStrictEqual(pkg.allowScripts, { 'pkga@1.0.0': true, 'pkgc@2.0.0': false });
  // now in sync: --check exits 0
  const check = await runCli(['sync', '--path', dir, '--no-trust', '--no-cache', '--check']);
  assert.strictEqual(check.status, 0, check.stdout + check.stderr);
});

test('sync --check exits 1 on drift', async () => {
  const dir = writeProj('syncdrift', { 'node_modules/pkga': { version: '1.0.0' } });
  const out = await runCli(['sync', '--path', dir, '--no-trust', '--no-cache', '--check']);
  assert.strictEqual(out.status, 1, out.stdout);
  assert.ok(out.stderr.includes('out of sync'), out.stderr);
});

test('approve: interactive decisions are written to package.json', async () => {
  const dir = writeProj('approveproj', { 'node_modules/pkga': { version: '1.0.0' } });
  const out = await runCli(['approve', '--path', dir, '--no-trust', '--no-cache'], { input: 'y\n' });
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stdout.includes("net: require('https')"), 'evidence shown before the prompt');
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  assert.deepStrictEqual(pkg.allowScripts, { 'pkga@1.0.0': true });
});

test('mcp: initialize, tools/list, audit_package over stdio', async () => {
  const lines = [
    JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } }),
    JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
    JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'audit_package', arguments: { name: 'pkga', version: '1.0.0' } } }),
  ].join('\n') + '\n';
  const out = await runCli(['mcp'], { input: lines });
  const responses = out.stdout.trim().split('\n').map((l) => JSON.parse(l));
  assert.strictEqual(responses.length, 3, out.stdout);
  assert.strictEqual(responses[0].result.serverInfo.name, 'npm-script-lens');
  assert.ok(responses[1].result.tools.map((t) => t.name).includes('audit_package'));
  assert.ok(responses[1].result.tools.map((t) => t.name).includes('audit_lockfile'));
  assert.ok(responses[1].result.tools.map((t) => t.name).includes('classify_allowscripts'));
  const payload = JSON.parse(responses[2].result.content[0].text);
  assert.strictEqual(payload.risk, 'MEDIUM');
  assert.strictEqual(payload.malicious, true);
  assert.ok(payload.verdict.startsWith('DO NOT INSTALL'), payload.verdict);
});

test('audit --since <git-ref>: audits only packages changed vs the lockfile at a ref', async () => {
  const dir = path.join(tmp, 'sinceproj');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"proj","version":"1.0.0"}\n');
  writeLock(path.join(dir, 'package-lock.json'), { 'node_modules/pkgb': { version: '2.0.0' } });
  const id = ['-c', 'user.email=t@t.io', '-c', 'user.name=t', '-c', 'commit.gpgsign=false'];
  const git = (args) => execFileSync('git', ['-C', dir, ...args], { stdio: 'ignore' });
  git(['init', '-q']);
  git([...id, 'add', '-A']);
  git([...id, 'commit', '-qm', 'base']);
  // working tree now adds pkga on top of the committed pkgb-only lockfile
  writeLock(path.join(dir, 'package-lock.json'), {
    'node_modules/pkga': { version: '1.0.0' },
    'node_modules/pkgb': { version: '2.0.0' },
  });
  const out = await runCli(['audit', '--since', 'HEAD', '--json', '--no-trust', '--path', dir]);
  assert.strictEqual(out.status, 0, out.stderr);
  const parsed = JSON.parse(out.stdout);
  assert.deepStrictEqual(parsed.results.map((r) => r.name), ['pkga'], 'only the added package is audited');
});

test('init --hook installs a git pre-commit hook when .git is present', async () => {
  const dir = path.join(tmp, 'hookproj');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  execFileSync('git', ['-C', dir, 'init', '-q'], { stdio: 'ignore' });
  const out = await runCli(['init', '--path', dir, '--hook']);
  assert.strictEqual(out.status, 0, out.stderr);
  const hook = path.join(dir, '.git', 'hooks', 'pre-commit');
  assert.ok(fs.existsSync(hook), 'pre-commit hook written');
  assert.ok(fs.readFileSync(hook, 'utf8').includes('sync --check'), 'hook runs sync --check');
  assert.ok(out.stdout.includes('git pre-commit hook'), out.stdout);
});

test('audit --html writes a self-contained shareable report', async () => {
  const htmlOut = path.join(tmp, 'report.html');
  const out = await runCli(['audit', '--path', projDir, '--no-trust', '--html', htmlOut]);
  assert.strictEqual(out.status, 0, out.stderr);
  const html = fs.readFileSync(htmlOut, 'utf8');
  assert.ok(html.startsWith('<!doctype html>'), 'valid doctype');
  assert.ok(html.includes('pkga'), 'lists audited packages');
  assert.ok(html.includes('Suggested allowScripts'), 'includes the allowlist block');
  assert.ok(html.trimEnd().endsWith('</html>'), 'well-formed close');
  assert.ok(!html.includes('<script'), 'no scripts — safe to open/share');
});

test('mcp: classify_allowscripts splits packages into allowScripts + _review', async () => {
  const dir = writeProj('mcpallow', {
    'node_modules/pkgc': { version: '1.0.0' }, // LOW (env read) → auto-approve
    'node_modules/pkga': { version: '1.0.0' }, // malicious per OSV → _review
  });
  const lines = [
    JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } }),
    JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'classify_allowscripts', arguments: { path: dir } } }),
  ].join('\n') + '\n';
  const out = await runCli(['mcp'], { input: lines });
  const responses = out.stdout.trim().split('\n').map((l) => JSON.parse(l));
  const payload = JSON.parse(responses[1].result.content[0].text);
  assert.strictEqual(payload.allowScripts['pkgc@1.0.0'], true, JSON.stringify(payload));
  assert.ok(!('pkga@1.0.0' in payload.allowScripts), 'malicious never auto-approved');
  assert.ok(payload._review.includes('pkga@1.0.0'), JSON.stringify(payload._review));
  assert.ok(payload.summary.includes('1 package(s) auto-approved'), payload.summary);
});

test('unresolved binaries are resolved against their lockfile owner and re-scored', async () => {
  const { runAudit } = require('../src/cli');
  const dir = writeProj('binproj', {
    'node_modules/userpkg': { version: '1.0.0' },
    'node_modules/toolpkg': { version: '1.0.0' },
  });
  const results = await runAudit(dir, { trust: false, cache: false });
  const user = results.find((r) => r.name === 'userpkg');
  const row = user.rows[0];
  assert.strictEqual(row.risk, 'LOW', JSON.stringify(row));
  assert.ok(row.signals.includes('bin: toolpkg install → toolpkg@1.0.0'), JSON.stringify(row.signals));
  assert.ok(row.signals.some((s) => s.startsWith('fs: ')), 'judged by the bin script\'s real behavior');
  assert.ok(!row.signals.some((s) => s.includes('unresolved binary')));
  // a bin with no owning package in the lockfile stays conservatively HIGH
  const lone = writeProj('binlone', { 'node_modules/userpkg': { version: '1.0.0' } });
  const loneRows = await runAudit(lone, { trust: false, cache: false });
  assert.strictEqual(loneRows[0].rows[0].risk, 'HIGH');
  assert.ok(loneRows[0].rows[0].signals.some((s) => s.includes('unresolved binary')));
});

test('--deep follows bare requires into lockfile packages; refs never leak', async () => {
  const { runAudit } = require('../src/cli');
  const dir = writeProj('deepproj', {
    'node_modules/usehelper': { version: '1.0.0' },
    'node_modules/helper': { version: '1.0.0' },
  });
  const shallow = await runAudit(dir, { trust: false, cache: false });
  const sRow = shallow.find((r) => r.name === 'usehelper').rows[0];
  assert.strictEqual(sRow.risk, 'SAFE');
  assert.ok(!sRow.signals.some((s) => s.startsWith('ref: ')), 'ref breadcrumbs are internal');
  const deep = await runAudit(dir, { trust: false, cache: false, deep: true });
  const dRow = deep.find((r) => r.name === 'usehelper').rows[0];
  assert.strictEqual(dRow.risk, 'MEDIUM', JSON.stringify(dRow));
  assert.ok(dRow.signals.includes("net: require('https') (via helper)"), JSON.stringify(dRow.signals));
});

test('manifest: stable behavior receipt, --check passes clean and fails with a diff on drift', async () => {
  const { buildManifest, serializeManifest, diffManifests } = require('../src/reporter');
  const dir = writeProj('manproj', { 'node_modules/pkga': { version: '1.0.0' } });

  // write
  const write = await runCli(['manifest', '--path', dir, '--write', '--no-cache']);
  assert.strictEqual(write.status, 0, write.stderr);
  const file = path.join(dir, 'script-lens.json');
  const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.strictEqual(manifest.tool, 'npm-script-lens');
  assert.deepStrictEqual(manifest.packages['pkga@1.0.0'], { risk: 'MEDIUM', capabilities: ['net'] });
  assert.ok(!('deep' in manifest), 'deep flag omitted when off');
  // trust data must never leak into the receipt
  assert.ok(!JSON.stringify(manifest).includes('dl/wk') && !('malicious' in (manifest.packages['pkga@1.0.0'])));

  // check: clean
  const clean = await runCli(['manifest', '--path', dir, '--check', '--no-cache']);
  assert.strictEqual(clean.status, 0, clean.stderr);
  assert.ok(clean.stderr.includes('up to date'), clean.stderr);

  // check: drift — tamper the committed capabilities, expect exit 1 + a diff line
  const tampered = JSON.parse(fs.readFileSync(file, 'utf8'));
  tampered.packages['pkga@1.0.0'].capabilities = ['fs'];
  tampered.packages['pkga@1.0.0'].risk = 'LOW';
  fs.writeFileSync(file, serializeManifest(tampered));
  const drift = await runCli(['manifest', '--path', dir, '--check', '--no-cache']);
  assert.strictEqual(drift.status, 1, drift.stderr);
  assert.ok(drift.stderr.includes('out of date'), drift.stderr);
  assert.ok(/~ pkga@1\.0\.0\s+LOW \[fs\] → MEDIUM \[net\]/.test(drift.stderr), drift.stderr);

  // check: missing file
  fs.unlinkSync(file);
  const missing = await runCli(['manifest', '--path', dir, '--check', '--no-cache']);
  assert.strictEqual(missing.status, 1);
  assert.ok(missing.stderr.includes('manifest --write'), missing.stderr);

  // unit: added/removed lines and deterministic serialization
  const base = buildManifest([
    { name: 'a', version: '1.0.0', rows: [{ signals: ['exec: x'] }] },
    { name: 'b', version: '1.0.0', rows: [{ signals: ['fs: y', 'ref: internal'] }] },
  ]).manifest;
  assert.deepStrictEqual(Object.keys(base.packages), ['a@1.0.0', 'b@1.0.0']);
  assert.deepStrictEqual(base.packages['b@1.0.0'].capabilities, ['fs'], 'ref: breadcrumbs excluded');
  assert.strictEqual(serializeManifest(base), serializeManifest(base), 'stable');
  const next = buildManifest([{ name: 'a', version: '2.0.0', rows: [{ signals: ['exec: x', 'net: z'] }] }]).manifest;
  const lines = diffManifests(base, next);
  assert.ok(lines.some((l) => l.startsWith('+ a@2.0.0')));
  assert.ok(lines.some((l) => l.startsWith('- a@1.0.0')));
  assert.ok(lines.some((l) => l.startsWith('- b@1.0.0')));
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
  assert.ok(run.tool.driver.rules.length >= 5);
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

test('cli e2e: --diff --sarif --json --no-cache --no-trust work together', async () => {
  const sarifOut = path.join(tmp, 'audit.sarif');
  const out = await runCli(['audit', '--path', projDir, '--diff', basePath,
    '--sarif', sarifOut, '--json', '--no-cache', '--no-trust']);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stderr.includes('added/upgraded'), out.stderr);
  const j = JSON.parse(out.stdout);
  assert.deepStrictEqual(j.results.map((r) => r.name), ['pkga']);
  assert.strictEqual(j.results[0].risk, 'MEDIUM');
  const sarif = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
  assert.strictEqual(sarif.runs[0].results.length, 1);
  assert.strictEqual(sarif.runs[0].results[0].level, 'warning');
});
