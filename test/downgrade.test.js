'use strict';
// Trust-downgrade check (1.14.0, npm/cli#9242). Network-free: the mock
// registry serves the committed fixtures/trust packuments, captured live and
// documented in fixtures/trust/README.md.
const http = require('node:http');
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const FIX = (f) => JSON.parse(fs.readFileSync(path.join(ROOT, 'fixtures', 'trust', f), 'utf8'));

const { versionTier, assess, renderTrustReport } = require('../src/downgrade');

let server, registryUrl, cacheDir;

const versionDoc = (name, version) => ({
  name, version, scripts: {}, dist: { tarball: `${registryUrl}/${name}/-/${name}-${version}.tgz` },
});

before(async () => {
  cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-trust-cache-'));
  server = http.createServer((req, res) => {
    const routes = {
      '/axios': () => FIX('axios-downgrade-reconstructed.json'),
      '/axios-consistent': () => {
        // the real axios packument under a name whose resolved version (1.19.0,
        // the newest ever published) matches its historical max
        const doc = FIX('axios-packument.json');
        return doc;
      },
      '/commander': () => FIX('commander-packument.json'),
      '/sigstore': () => FIX('sigstore-packument.json'),
      '/axios/1.14.1': () => versionDoc('axios', '1.14.1'),
      '/commander/13.1.0': () => versionDoc('commander', '13.1.0'),
      '/sigstore/3.1.0': () => versionDoc('sigstore', '3.1.0'),
    };
    const route = decodeURIComponent(req.url);
    if (!Object.hasOwn(routes, route)) { res.statusCode = 404; return res.end('{"error":"Not found"}'); }
    const hit = routes[route];
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(hit()));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  registryUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  fs.rmSync(cacheDir, { recursive: true, force: true });
});

function runCli(args, cwd) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd: cwd || ROOT,
      timeout: 60000,
      env: { ...process.env, NPM_SCRIPT_LENS_REGISTRY: registryUrl, NPM_SCRIPT_LENS_CACHE_DIR: cacheDir },
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdin.end();
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}

const lockfileFor = (deps) => JSON.stringify({
  name: 'trust-fixture', version: '1.0.0', lockfileVersion: 3,
  packages: {
    '': { name: 'trust-fixture', version: '1.0.0', dependencies: Object.fromEntries(Object.entries(deps).map(([n, v]) => [n, v])) },
    ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [
      `node_modules/${n}`, { version: v, resolved: `${registryUrl}/${n}/-/${n}-${v}.tgz` },
    ])),
  },
}, null, 2);

function tmpProject(deps, extraFiles = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-trust-'));
  fs.writeFileSync(path.join(dir, 'package-lock.json'), lockfileFor(deps));
  for (const [name, body] of Object.entries(extraFiles)) fs.writeFileSync(path.join(dir, name), body);
  return dir;
}

// --- tier resolution ------------------------------------------------------

test('versionTier: absent attestations is none', () => {
  assert.strictEqual(versionTier({ dist: { tarball: 'x' } }), 0);
  assert.strictEqual(versionTier({}), 0);
  assert.strictEqual(versionTier(null), 0);
});

test('versionTier: dist.attestations is provenance, whatever the predicate era', () => {
  assert.strictEqual(versionTier({ dist: { attestations: { url: 'x', provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } }), 1);
  assert.strictEqual(versionTier({ dist: { attestations: { url: 'x' } } }), 1);
});

test('versionTier: _npmUser.trustedPublisher is trusted-publisher, and deprecation does not change a tier', () => {
  assert.strictEqual(versionTier({ _npmUser: { name: 'GitHub Actions', trustedPublisher: { id: 'github' } }, dist: { attestations: { url: 'x' } } }), 2);
  assert.strictEqual(versionTier({ _npmUser: { name: 'GitHub Actions', trustedPublisher: { id: 'github' } }, dist: {} }), 2);
  assert.strictEqual(versionTier({ _npmUser: { name: 'jane' }, dist: { attestations: { url: 'x' } }, deprecated: 'use v2' }), 1);
});

// --- historical-max comparison --------------------------------------------

const hist = (entries) => ({
  versions: Object.fromEntries(entries.map(([v, tier, t]) => [v, {
    tier, publishedAt: new Date(t).toISOString(),
  }])),
});

const T0 = Date.parse('2025-01-01T00:00:00Z');
const DAY = 86400000;

test('assess: a downgrade against the highest earlier tier, exemplar is the latest prior at that tier', () => {
  const h = hist([['1.0.0', 1, T0], ['1.1.0', 1, T0 + DAY], ['1.2.0', 0, T0 + 2 * DAY]]);
  const a = assess(h, '1.2.0');
  assert.strictEqual(a.status, 'downgrade');
  assert.strictEqual(a.from, 'provenance');
  assert.strictEqual(a.to, 'none');
  assert.strictEqual(a.priorVersion, '1.1.0');
});

test('assess: versions published AFTER the resolved one never count toward the max', () => {
  const h = hist([['1.0.0', 0, T0], ['1.1.0', 0, T0 + DAY], ['2.0.0', 1, T0 + 2 * DAY]]);
  assert.strictEqual(assess(h, '1.1.0').status, 'ok');
});

test('assess: the newest version ever published still compares against all older ones', () => {
  const h = hist([['1.0.0', 2, T0], ['2.0.0', 1, T0 + DAY]]);
  const a = assess(h, '2.0.0');
  assert.strictEqual(a.status, 'downgrade');
  assert.strictEqual(a.from, 'trusted-publisher');
  assert.strictEqual(a.to, 'provenance');
});

test('assess: a package with exactly one published version can never downgrade', () => {
  assert.strictEqual(assess(hist([['1.0.0', 0, T0]]), '1.0.0').status, 'first');
});

test('assess: an unpublished gap compares against what remains, and an unlisted resolved version is not a finding', () => {
  // 1.1.0 was unpublished: absent from versions even though the attack window
  // sits between 1.0.0 (provenance) and 1.2.0 (none)
  const h = hist([['1.0.0', 1, T0], ['1.2.0', 0, T0 + 2 * DAY]]);
  const a = assess(h, '1.2.0');
  assert.strictEqual(a.status, 'downgrade');
  assert.strictEqual(a.priorVersion, '1.0.0');
  assert.strictEqual(assess(h, '1.1.0').status, 'unlisted');
});

test('assess: trust-policy-ignore-after retires stale prior evidence', () => {
  const now = T0 + 10 * DAY;
  const h = hist([['1.0.0', 1, T0], ['1.1.0', 0, T0 + 2 * DAY]]);
  assert.strictEqual(assess(h, '1.1.0', { now, ignoreAfter: 5 * 24 * 60 }).status, 'ignored');
  assert.strictEqual(assess(h, '1.1.0', { now, ignoreAfter: 15 * 24 * 60 }).status, 'downgrade');
});

test('renderTrustReport: the trusted-publisher-to-provenance detail line names the missing publisher', () => {
  const out = renderTrustReport({
    downgrades: [{ name: 'p', version: '2.0.0', from: 'trusted-publisher', to: 'provenance', priorVersion: '1.0.0', priorPublishedAt: '2025-01-01T00:00:00Z' }],
    checked: 1, skipped: [], excluded: [], ignored: [], unreachable: [], unlisted: [],
  });
  assert.match(out, /resolved version has provenance but was not published by a trusted publisher/);
});

// --- CLI e2e over the mock registry ---------------------------------------

const WORKED_EXAMPLE = [
  'TRUST DOWNGRADE (1)',
  '  axios@1.14.1  provenance -> none',
  '    highest prior trust: provenance (axios@1.13.2, published 2025-11-04)',
  '    resolved version has no attestations',
  '    pnpm >= 10.21 would refuse this install under trust-policy=no-downgrade',
].join('\n');

test('trust: the reconstructed axios attack produces the worked example, and --fail-on-downgrade flips the exit code', async () => {
  const dir = tmpProject({ axios: '1.14.1' });
  const plain = await runCli(['trust', '--path', dir]);
  assert.strictEqual(plain.status, 0);
  assert.ok(plain.stdout.includes(WORKED_EXAMPLE), `missing worked example in:\n${plain.stdout}`);
  const gated = await runCli(['trust', '--path', dir, '--fail-on-downgrade']);
  assert.strictEqual(gated.status, 1);
  assert.match(gated.stderr, /FAIL: 1 package\(s\) resolve below the highest trust/);
});

test('trust: never-attested and consistently-attested packages produce no finding', async () => {
  const dir = tmpProject({ commander: '13.1.0', sigstore: '3.1.0' });
  const r = await runCli(['trust', '--path', dir, '--fail-on-downgrade']);
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /checked 2 registry package\(s\)/);
  assert.match(r.stdout, /🟢 no trust downgrade/);
});

test('trust: the newest-ever real axios version matches its historical max', async () => {
  const latest = Object.entries(FIX('axios-packument.json').time)
    .filter(([v]) => !['created', 'modified'].includes(v))
    .sort((a, b) => Date.parse(a[1]) - Date.parse(b[1])).pop()[0];
  const dir = tmpProject({ 'axios-consistent': latest });
  const r = await runCli(['trust', '--path', dir, '--fail-on-downgrade']);
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /🟢 no trust downgrade/);
});

test('trust: an unreachable package warns once and never fails, even under --fail-on-downgrade', async () => {
  const dir = tmpProject({ 'no-such-package-xyz': '1.0.0' });
  const r = await runCli(['trust', '--path', dir, '--fail-on-downgrade']);
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /1 unreachable \(never treated as a downgrade\)/);
  assert.match(r.stderr, /registry unreachable for 1 package\(s\)/);
});

test('trust: --exclude and policy trustPolicyExclude both retire a finding', async () => {
  const viaFlag = await runCli(['trust', '--path', tmpProject({ axios: '1.14.1' }), '--fail-on-downgrade', '--exclude', 'axios@1.14.1']);
  assert.strictEqual(viaFlag.status, 0);
  assert.match(viaFlag.stdout, /1 excluded by trustPolicyExclude/);
  const dir = tmpProject({ axios: '1.14.1' }, {
    'script-lens.policy.json': JSON.stringify({ trustPolicy: 'no-downgrade', trustPolicyExclude: ['axios@1.14.1'] }),
  });
  const viaPolicy = await runCli(['trust', '--path', dir, '--fail-on-downgrade']);
  assert.strictEqual(viaPolicy.status, 0, viaPolicy.stderr);
});

test('trust: --ignore-after in minutes maps to trust-policy-ignore-after', async () => {
  const dir = tmpProject({ axios: '1.14.1' });
  // the fixture's prior evidence (1.13.2, 2025-11-04) is far older than an hour
  const r = await runCli(['trust', '--path', dir, '--fail-on-downgrade', '--ignore-after', '60']);
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /1 ignored \(prior trust older than trustPolicyIgnoreAfter\)/);
  const bad = await runCli(['trust', '--path', dir, '--ignore-after', 'soon']);
  assert.strictEqual(bad.status, 2);
});

test('trust: an invalid trustPolicy value in the policy file is refused', async () => {
  const dir = tmpProject({ axios: '1.14.1' }, { 'script-lens.policy.json': JSON.stringify({ trustPolicy: 'strict' }) });
  const r = await runCli(['trust', '--path', dir]);
  assert.strictEqual(r.status, 2);
  assert.match(r.stderr, /trustPolicy must be 'no-downgrade' or 'off'/);
});

test('trust: --json round-trips the structured result', async () => {
  const dir = tmpProject({ axios: '1.14.1', commander: '13.1.0' });
  const r = await runCli(['trust', '--path', dir, '--json']);
  assert.strictEqual(r.status, 0);
  const doc = JSON.parse(r.stdout);
  assert.strictEqual(doc.checked, 2);
  assert.strictEqual(doc.downgrades.length, 1);
  assert.deepStrictEqual({ name: doc.downgrades[0].name, version: doc.downgrades[0].version, from: doc.downgrades[0].from, to: doc.downgrades[0].to, priorVersion: doc.downgrades[0].priorVersion },
    { name: 'axios', version: '1.14.1', from: 'provenance', to: 'none', priorVersion: '1.13.2' });
});

test('trust: --sarif writes the trust-downgrade rule anchored to the lockfile', async () => {
  const dir = tmpProject({ axios: '1.14.1' });
  const file = path.join(dir, 'trust.sarif');
  const r = await runCli(['trust', '--path', dir, '--sarif', file], dir);
  assert.strictEqual(r.status, 0);
  const sarif = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.ok(sarif.runs[0].tool.driver.rules.some((rule) => rule.id === 'trust-downgrade'));
  const hit = sarif.runs[0].results.find((x) => x.ruleId === 'trust-downgrade');
  assert.strictEqual(hit.level, 'error');
  assert.match(hit.message.text, /provenance -> none/);
  assert.ok(hit.locations[0].physicalLocation.region.startLine > 1);
});

// --- audit integration -----------------------------------------------------

test('audit: --fail-on-downgrade attaches the finding, renders the section and flips the exit code', async () => {
  const dir = tmpProject({ axios: '1.14.1' });
  const json = await runCli(['audit', '--path', dir, '--no-trust', '--json', '--fail-on-downgrade']);
  assert.strictEqual(json.status, 1, json.stderr);
  const doc = JSON.parse(json.stdout);
  const axios = doc.results.find((x) => x.name === 'axios');
  assert.strictEqual(axios.trustDowngrade.from, 'provenance');
  assert.strictEqual(axios.trustDowngrade.priorVersion, '1.13.2');
  const report = await runCli(['audit', '--path', dir, '--no-trust', '--fail-on-downgrade']);
  assert.strictEqual(report.status, 1);
  assert.match(report.stdout, /## ⛔ Trust downgrade \(1\)/);
  assert.match(report.stdout, /`axios@1.14.1` provenance -> none/);
});

test('audit: policy trustPolicy no-downgrade runs the check without changing the exit code', async () => {
  const dir = tmpProject({ axios: '1.14.1' }, {
    'script-lens.policy.json': JSON.stringify({ trustPolicy: 'no-downgrade' }),
  });
  const r = await runCli(['audit', '--path', dir, '--no-trust']);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.match(r.stdout, /## ⛔ Trust downgrade \(1\)/);
});

test('audit: without opting in, no downgrade check runs and no registry packument is fetched for it', async () => {
  const dir = tmpProject({ axios: '1.14.1' });
  const r = await runCli(['audit', '--path', dir, '--no-trust']);
  assert.strictEqual(r.status, 0);
  assert.ok(!r.stdout.includes('Trust downgrade'), r.stdout);
});

test('audit: --sarif carries the downgrade as a trust-downgrade result', async () => {
  const dir = tmpProject({ axios: '1.14.1' });
  const file = path.join(dir, 'audit.sarif');
  await runCli(['audit', '--path', dir, '--no-trust', '--fail-on-downgrade', '--sarif', file], dir);
  const sarif = JSON.parse(fs.readFileSync(file, 'utf8'));
  const hit = sarif.runs[0].results.find((x) => x.ruleId === 'trust-downgrade');
  assert.strictEqual(hit.level, 'error');
  assert.match(hit.message.text, /axios/);
});
