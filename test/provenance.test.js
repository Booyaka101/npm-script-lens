'use strict';
// Provenance identity (1.11.0). Network-free: the mock registry serves
// /-/npm/v1/attestations/<spec> in the shape registry.npmjs.org does,
// verified live against sigstore@3.1.0.
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
const CLI = path.join(ROOT, 'src', 'cli.js');
let server, tmp;
const requests = [];

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

// A registry-shaped SLSA attestation entry: the DSSE payload is base64 JSON
// whose predicate carries the workflow identity, exactly the field paths the
// live endpoint serves.
const slsaEntry = ({ repository, workflowPath, ref, commit }) => ({
  predicateType: 'https://slsa.dev/provenance/v1',
  bundle: {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
    dsseEnvelope: {
      payloadType: 'application/vnd.in-toto+json',
      payload: Buffer.from(JSON.stringify({
        predicate: {
          buildDefinition: {
            externalParameters: { workflow: { repository, ref, path: workflowPath } },
            resolvedDependencies: [{ uri: `git+${repository}@${ref}`, digest: { gitCommit: commit } }],
          },
          runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' } },
        },
      })).toString('base64'),
      signatures: [{ sig: 'x', keyid: '' }],
    },
  },
});

const publishEntry = () => ({
  predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1',
  bundle: { dsseEnvelope: { payload: Buffer.from('{}').toString('base64') } },
});

const IDENTITY = {
  repository: 'https://github.com/acme/widget',
  workflowPath: '.github/workflows/release.yml',
  ref: 'refs/heads/main',
  commit: '4a91c0e2f66cf2a9c8d6de189aa119b1b1a90a01',
};

before(async () => {
  const highTgz = await makeTgz({
    'package/package.json': JSON.stringify({ scripts: { postinstall: 'node h.js' } }),
    'package/h.js': "require('child_process').exec('echo build');\n",
  });
  const packument = (name, repoUrl, versions = ['1.0.0']) => ({
    name,
    time: Object.fromEntries(versions.map((v) => [v, '2020-01-01T00:00:00.000Z'])),
    maintainers: [{ name: 'a' }],
    repository: repoUrl ? { type: 'git', url: repoUrl } : undefined,
    versions: Object.fromEntries(versions.map((v) => [v, { dist: { attestations: { url: 'sig', provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } }])),
  });
  const att = (entries) => ({ attestations: entries });
  const routes = {
    '/provpkg': packument('provpkg', 'git+https://github.com/acme/widget.git', ['1.0.0', '1.1.0']),
    '/driftpkg': packument('driftpkg', 'git+https://github.com/acme/widget.git'),
    '/monopkg': packument('monopkg', 'https://github.com/acme/mono/tree/main/packages/widget'),
    '/pubonly': packument('pubonly', 'git+https://github.com/acme/widget.git'),
    '/badb64': packument('badb64', 'git+https://github.com/acme/widget.git'),
    '/-/npm/v1/attestations/provpkg@1.0.0': att([publishEntry(), slsaEntry(IDENTITY)]),
    '/-/npm/v1/attestations/provpkg@1.1.0': att([publishEntry(), slsaEntry({
      ...IDENTITY, workflowPath: '.github/workflows/hotfix.yml', ref: 'refs/tags/v1.1.0', commit: 'b7c9d0e2f66cf2a9c8d6de189aa119b1b1a90a02',
    })]),
    '/-/npm/v1/attestations/driftpkg@1.0.0': att([slsaEntry({ ...IDENTITY, repository: 'https://github.com/acme-labs/widget' })]),
    '/-/npm/v1/attestations/monopkg@1.0.0': att([slsaEntry({ ...IDENTITY, repository: 'https://github.com/acme/mono' })]),
    '/-/npm/v1/attestations/pubonly@1.0.0': att([publishEntry()]),
    '/-/npm/v1/attestations/badb64@1.0.0': {
      attestations: [{ predicateType: 'https://slsa.dev/provenance/v1', bundle: { dsseEnvelope: { payload: '!!!not-base64!!!' } } }],
    },
    // diff e2e: widget@1.2.0 built from release.yml@tag, 1.3.0 from hotfix.yml@main
    '/-/npm/v1/attestations/widget@1.2.0': att([slsaEntry({ ...IDENTITY, ref: 'refs/tags/v1.2.0' })]),
    '/-/npm/v1/attestations/widget@1.3.0': att([slsaEntry({
      ...IDENTITY, workflowPath: '.github/workflows/hotfix.yml', ref: 'refs/heads/main',
    })]),
  };
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      requests.push(req.url);
      const port = server.address().port;
      if (req.url === '/high.tgz') return res.writeHead(200).end(highTgz);
      if (req.url === '/v1/querybatch') {
        return res.writeHead(200, { 'content-type': 'application/json' })
          .end(JSON.stringify({ results: JSON.parse(body).queries.map(() => ({})) }));
      }
      if (req.url.startsWith('/downloads/point/last-week/')) {
        return res.writeHead(200, { 'content-type': 'application/json' }).end('{"downloads":1000}');
      }
      const verDoc = req.url.match(/^\/([^/]+)\/(\d[^/]*)$/);
      if (verDoc) {
        return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
          version: verDoc[2], scripts: { postinstall: 'node h.js' }, dist: { tarball: `http://127.0.0.1:${port}/high.tgz` },
        }));
      }
      if (routes[req.url]) {
        return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(routes[req.url]));
      }
      res.writeHead(404).end('{}');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  process.env.NPM_SCRIPT_LENS_REGISTRY = base;
  process.env.NPM_SCRIPT_LENS_OSV_API = base;
  process.env.NPM_SCRIPT_LENS_DL_API = base;
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-prov-'));
  process.env.NPM_SCRIPT_LENS_CACHE_DIR = path.join(tmp, 'cache');
});

after(() => {
  server.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const writeProj = (name, mods) => {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  const packages = { '': { name: 'proj', version: '1.0.0' } };
  for (const [mod, ver] of Object.entries(mods)) packages[`node_modules/${mod}`] = { version: ver };
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }, null, 2));
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"proj","version":"1.0.0"}\n');
  return dir;
};

test('normalizeRepo: scheme/git+/.git/subpath/scp forms all collapse to host/owner/repo', () => {
  const { normalizeRepo } = require('../src/trust');
  assert.strictEqual(normalizeRepo('git+https://github.com/acme/widget.git'), 'github.com/acme/widget');
  assert.strictEqual(normalizeRepo('https://github.com/acme/widget'), 'github.com/acme/widget');
  assert.strictEqual(normalizeRepo('https://github.com/acme/mono/tree/main/packages/widget'), 'github.com/acme/mono');
  assert.strictEqual(normalizeRepo('git@github.com:acme/widget.git'), 'github.com/acme/widget');
  assert.strictEqual(normalizeRepo('ssh://git@github.com/acme/widget.git'), 'github.com/acme/widget');
  assert.strictEqual(normalizeRepo({ url: 'git+https://github.com/acme/widget.git' }), 'github.com/acme/widget');
  assert.strictEqual(normalizeRepo('not-a-repo'), null);
  assert.strictEqual(normalizeRepo(null), null);
});

test('resolveProvenance: SLSA identity resolved with the exact live field paths', async () => {
  const { resolveProvenance } = require('../src/trust');
  const p = await resolveProvenance('provpkg', '1.0.0');
  assert.deepStrictEqual(p, {
    present: true,
    repository: 'github.com/acme/widget',
    workflow: '.github/workflows/release.yml',
    ref: 'refs/heads/main',
    commit: '4a91c0e2f66cf2a9c8d6de189aa119b1b1a90a01',
    builder: 'https://github.com/actions/runner/github-hosted',
  });
});

test('resolveProvenance: 404 = no attestations = { present: false }, never an error', async () => {
  const { resolveProvenance } = require('../src/trust');
  assert.deepStrictEqual(await resolveProvenance('ghost', '9.9.9'), { present: false });
});

test('resolveProvenance: publish-only bundle and malformed base64 both degrade to identity-unavailable', async () => {
  const { resolveProvenance } = require('../src/trust');
  assert.deepStrictEqual(await resolveProvenance('pubonly', '1.0.0'), { present: true });
  assert.deepStrictEqual(await resolveProvenance('badb64', '1.0.0'), { present: true });
});

test('fetchTrust carries the identity, declaredRepository and provenanceOk; trustLabel prints it', async () => {
  const { fetchTrust, trustLabel } = require('../src/trust');
  const t = await fetchTrust('provpkg', '1.0.0');
  assert.strictEqual(t.provenanceOk, true);
  assert.strictEqual(t.provenance.repository, 'github.com/acme/widget');
  assert.strictEqual(t.declaredRepository, 'github.com/acme/widget');
  const label = trustLabel(t);
  assert.ok(label.endsWith('provenance ✓ github.com/acme/widget .github/workflows/release.yml@refs/heads/main 4a91c0e'), label);
});

test('trustLabel: identity unavailable and legacy boolean shapes', () => {
  const { trustLabel } = require('../src/trust');
  const base = { publishedAt: null, ageDays: null, weeklyDownloads: null, maintainers: null };
  assert.strictEqual(trustLabel({ ...base, provenance: { present: true }, provenanceOk: true }),
    'provenance ✓ (identity unavailable)');
  assert.strictEqual(trustLabel({ ...base, provenance: { present: false }, provenanceOk: false }), 'no provenance');
  // pre-1.11.0 cached shape
  assert.strictEqual(trustLabel({ ...base, provenance: true }), 'provenance ✓ (identity unavailable)');
  assert.strictEqual(trustLabel({ ...base, provenance: false }), 'no provenance');
});

test('repo drift: different owner/repo notes both values; a monorepo subpath does NOT drift', async () => {
  const { fetchTrust, driftNote } = require('../src/trust');
  const drifted = await fetchTrust('driftpkg', '1.0.0');
  assert.strictEqual(driftNote(drifted),
    'provenance repo drift: package declares github.com/acme/widget, attestation names github.com/acme-labs/widget, likely a repo rename or transfer');
  const mono = await fetchTrust('monopkg', '1.0.0');
  assert.strictEqual(mono.declaredRepository, 'github.com/acme/mono');
  assert.strictEqual(driftNote(mono), null, 'one repo publishing many packages is normal');
});

test('identityChanges: workflow/ref moves, appear/disappear, and every not-comparable side', () => {
  const { identityChanges } = require('../src/trust');
  const a = { present: true, repository: 'github.com/acme/widget', workflow: 'w.yml', ref: 'refs/tags/v1', commit: 'aaa' };
  const b = { ...a, workflow: 'hotfix.yml', ref: 'refs/heads/main', commit: 'bbb' };
  assert.deepStrictEqual(identityChanges(a, b), [
    { field: 'workflow', from: 'w.yml', to: 'hotfix.yml' },
    { field: 'ref', from: 'refs/tags/v1', to: 'refs/heads/main' },
  ]);
  assert.deepStrictEqual(identityChanges(a, { ...a, commit: 'ccc' }), [], 'a new commit alone is a release, not an identity move');
  assert.deepStrictEqual(identityChanges({ present: false }, a), [{ field: 'provenance', from: 'absent', to: 'present' }]);
  assert.deepStrictEqual(identityChanges(a, { present: false }), [{ field: 'provenance', from: 'present', to: 'absent' }]);
  assert.deepStrictEqual(identityChanges(null, a), [], 'unreachable endpoint is not comparable');
  assert.deepStrictEqual(identityChanges(a, { present: true }), [], 'unresolved identity is not comparable');
  assert.deepStrictEqual(identityChanges(true, a), [], 'legacy boolean cache entry is not comparable');
});

test('policy expectProvenance: match approves, mismatch and unresolvable never auto-approve, absent expectation unaffected', () => {
  const { evaluate, DEFAULT_POLICY } = require('../src/policy');
  const { packageRisk } = require('../src/reporter');
  const NOW = Date.UTC(2026, 7, 14);
  const pol = (expect) => ({
    autoApprove: { ...DEFAULT_POLICY.autoApprove, expectProvenance: expect },
    waivers: {},
  });
  const R = (trust) => ({
    name: 'keyv', version: '6.0.0', rows: [{ risk: 'LOW', signals: ['env: x'] }], trust,
  });
  const good = {
    provenanceOk: true,
    provenance: { present: true, repository: 'github.com/jaredwray/keyv', workflow: '.github/workflows/release.yml', ref: 'refs/heads/main', commit: 'abc' },
  };
  assert.strictEqual(evaluate(R(good), pol({ keyv: 'jaredwray/keyv' }), packageRisk, NOW).allow, true);
  assert.strictEqual(evaluate(R(good), pol({ keyv: 'jaredwray/keyv:.github/workflows/release.yml' }), packageRisk, NOW).allow, true);
  const wrongRepo = evaluate(R(good), pol({ keyv: 'acme/keyv' }), packageRisk, NOW);
  assert.strictEqual(wrongRepo.allow, false);
  assert.ok(wrongRepo.reason.includes('acme/keyv') && wrongRepo.reason.includes('github.com/jaredwray/keyv'), wrongRepo.reason);
  const wrongWf = evaluate(R(good), pol({ keyv: 'jaredwray/keyv:.github/workflows/other.yml' }), packageRisk, NOW);
  assert.strictEqual(wrongWf.allow, false);
  assert.ok(wrongWf.reason.includes('.github/workflows/other.yml') && wrongWf.reason.includes('.github/workflows/release.yml'), wrongWf.reason);
  const unresolved = evaluate(R({ provenanceOk: true, provenance: { present: true } }), pol({ keyv: 'jaredwray/keyv' }), packageRisk, NOW);
  assert.strictEqual(unresolved.allow, false, 'an expectation the tool cannot confirm fails closed');
  assert.strictEqual(evaluate(R({ provenanceOk: false, provenance: { present: false } }), pol({ keyv: 'jaredwray/keyv' }), packageRisk, NOW).allow, false);
  assert.strictEqual(evaluate(R(undefined), pol({ other: 'acme/other' }), packageRisk, NOW).allow, true, 'no expectation for this package: unaffected');
});

test('repo drift never changes an auto-approval decision', async () => {
  const { fetchTrust } = require('../src/trust');
  const { evaluate, DEFAULT_POLICY } = require('../src/policy');
  const { packageRisk } = require('../src/reporter');
  const pol = { autoApprove: { ...DEFAULT_POLICY.autoApprove }, waivers: {} };
  const R = (trust) => ({ name: 'p', version: '1.0.0', rows: [{ risk: 'LOW', signals: ['env: x'] }], trust });
  const drifted = evaluate(R(await fetchTrust('driftpkg', '1.0.0')), pol, packageRisk, Date.now());
  const clean = evaluate(R(await fetchTrust('provpkg', '1.0.0')), pol, packageRisk, Date.now());
  assert.deepStrictEqual(drifted, clean, 'drift is informational, byte-identical decision');
});

test('computeScriptDiff + renderDiff: the brief\'s worked example, and unchanged identity prints green', () => {
  const { computeScriptDiff, renderDiff } = require('../src/diff');
  const mk = (version, provenance) => ({ name: 'widget', version, scripts: { install: 'node x' }, gypText: null, gypFindings: [], provenance });
  const base = { present: true, repository: 'github.com/acme/widget', workflow: '.github/workflows/release.yml', ref: 'refs/tags/v1.2.0', commit: 'aaa' };
  const next = { present: true, repository: 'github.com/acme/widget', workflow: '.github/workflows/hotfix.yml', ref: 'refs/heads/main', commit: 'bbb' };
  const r = computeScriptDiff(mk('1.2.0', base), mk('1.3.0', next));
  assert.strictEqual(r.changed, true, 'identity move gates like an added/modified script');
  const text = renderDiff(mk('1.2.0', base), mk('1.3.0', next), r, { color: false });
  assert.ok(text.includes('PROVENANCE IDENTITY CHANGED  workflow .github/workflows/release.yml → .github/workflows/hotfix.yml, ref refs/tags/v1.2.0 → refs/heads/main'), text);
  const same = computeScriptDiff(mk('1.2.0', base), mk('1.2.1', base));
  assert.strictEqual(same.changed, false);
  const sameText = renderDiff(mk('1.2.0', base), mk('1.2.1', base), same, { color: false });
  assert.ok(sameText.includes('UNCHANGED: provenance identity github.com/acme/widget .github/workflows/release.yml@refs/tags/v1.2.0'), sameText);
  // no provenance supplied on either side: json shape and behavior of 1.10.0
  const legacy = computeScriptDiff(mk('1.0.0', undefined), mk('1.0.1', undefined));
  assert.ok(!('provenance' in legacy.json));
});

test('diff CLI e2e: changed workflow/ref exits 1 with the PROVENANCE IDENTITY CHANGED line', async () => {
  const out = await runCli(['diff', 'widget@1.2.0', 'widget@1.3.0']);
  assert.strictEqual(out.status, 1, out.stderr);
  assert.ok(out.stdout.includes('PROVENANCE IDENTITY CHANGED  workflow .github/workflows/release.yml → .github/workflows/hotfix.yml, ref refs/tags/v1.2.0 → refs/heads/main'), out.stdout);
  const json = await runCli(['diff', 'widget@1.2.0', 'widget@1.3.0', '--json']);
  assert.strictEqual(json.status, 1);
  const j = JSON.parse(json.stdout);
  assert.strictEqual(j.provenance.changed, true);
  assert.deepStrictEqual(j.provenance.changes.map((c) => c.field), ['workflow', 'ref']);
});

test('audit --json carries the identity object for a trust-enriched package', async () => {
  const dir = writeProj('audit-id', { provpkg: '1.0.0' });
  const out = await runCli(['audit', '--path', dir, '--no-cache', '--json']);
  assert.strictEqual(out.status, 0, out.stderr);
  const r = JSON.parse(out.stdout).results.find((x) => x.name === 'provpkg');
  assert.strictEqual(r.risk, 'HIGH', 'HIGH so trust enrichment runs by default');
  assert.deepStrictEqual(r.trust.provenance, {
    present: true,
    repository: 'github.com/acme/widget',
    workflow: '.github/workflows/release.yml',
    ref: 'refs/heads/main',
    commit: '4a91c0e2f66cf2a9c8d6de189aa119b1b1a90a01',
    builder: 'https://github.com/actions/runner/github-hosted',
  });
});

test('audit --diff reports the identity move next to the gained-capabilities block', async () => {
  const dir = writeProj('audit-diff', { provpkg: '1.1.0' });
  const baseLock = path.join(tmp, 'prov-base-lock.json');
  fs.writeFileSync(baseLock, JSON.stringify({
    lockfileVersion: 3,
    packages: { '': { name: 'proj', version: '1.0.0' }, 'node_modules/provpkg': { version: '1.0.0' } },
  }));
  const out = await runCli(['audit', '--path', dir, '--diff', baseLock, '--no-cache', '--json']);
  assert.strictEqual(out.status, 0, out.stderr);
  const r = JSON.parse(out.stdout).results.find((x) => x.name === 'provpkg');
  assert.strictEqual(r.provenanceChange.baseVersion, '1.0.0');
  assert.deepStrictEqual(r.provenanceChange.changes, [
    { field: 'workflow', from: '.github/workflows/release.yml', to: '.github/workflows/hotfix.yml' },
    { field: 'ref', from: 'refs/heads/main', to: 'refs/tags/v1.1.0' },
  ]);
  const md = await runCli(['audit', '--path', dir, '--diff', baseLock, '--no-cache']);
  assert.strictEqual(md.status, 0, 'the audit-path note is informational, exit unchanged');
  assert.ok(md.stdout.includes('provenance identity changed vs 1.0.0'), md.stdout);
});

test('SARIF: identity change is warning, repo drift is note, both rules declared', () => {
  const { buildSarif } = require('../src/reporter');
  const results = [{
    name: 'provpkg',
    version: '1.1.0',
    rows: [{ script: 'postinstall', command: 'node h.js', risk: 'HIGH', signals: ['exec: child_process'] }],
    trust: {
      provenanceOk: true,
      provenance: { present: true, repository: 'github.com/acme-labs/widget', workflow: 'w.yml', ref: 'r', commit: 'c' },
      declaredRepository: 'github.com/acme/widget',
    },
    provenanceChange: { baseVersion: '1.0.0', changes: [{ field: 'workflow', from: 'a.yml', to: 'b.yml' }] },
  }];
  const sarif = buildSarif(results);
  const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.ok(ruleIds.includes('provenance-identity-changed') && ruleIds.includes('provenance-repo-drift'), ruleIds.join(','));
  const changed = sarif.runs[0].results.find((r) => r.ruleId === 'provenance-identity-changed');
  assert.strictEqual(changed.level, 'warning');
  assert.ok(changed.message.text.includes('workflow a.yml → b.yml'), changed.message.text);
  const drift = sarif.runs[0].results.find((r) => r.ruleId === 'provenance-repo-drift');
  assert.strictEqual(drift.level, 'note', 'drift must never be warning-or-worse');
});

test('--offline issues zero requests; --no-trust never touches the attestation endpoint', async () => {
  // offline: package must exist in node_modules
  const dir = writeProj('offline-prov', { provpkg: '1.0.0' });
  const mod = path.join(dir, 'node_modules', 'provpkg');
  fs.mkdirSync(mod, { recursive: true });
  fs.writeFileSync(path.join(mod, 'package.json'), JSON.stringify({ name: 'provpkg', version: '1.0.0', scripts: { postinstall: 'node h.js' } }));
  fs.writeFileSync(path.join(mod, 'h.js'), "require('child_process').exec('echo build');\n");
  const countBefore = requests.length;
  const off = await runCli(['audit', '--path', dir, '--offline', '--no-cache', '--json']);
  assert.strictEqual(off.status, 0, off.stderr);
  assert.strictEqual(requests.length, countBefore, '--offline made zero network requests');
  const noTrust = await runCli(['audit', '--path', dir, '--no-trust', '--no-cache', '--json']);
  assert.strictEqual(noTrust.status, 0, noTrust.stderr);
  const made = requests.slice(countBefore);
  assert.ok(made.length > 0, 'the scan itself still fetches the tarball');
  assert.ok(!made.some((u) => u.includes('/-/npm/v1/attestations/')), `no attestation requests under --no-trust: ${made.join(', ')}`);
  assert.ok(!made.some((u) => u.includes('/downloads/') || u.includes('/v1/querybatch')), 'no trust requests at all');
});
