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
const CLI = path.join(ROOT, 'src', 'cli.js');
const ACTION = path.join(ROOT, 'src', 'action.js');
let server, tmp, npm12, npm10;

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

// Build a project dir with a v3 lockfile listing the given node_modules
// packages, plus package.json (defaults to no allowScripts).
const writeProj = (name, mods, pkgJson = { name: 'proj', version: '1.0.0' }) => {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  const packages = { '': { name: 'proj', version: '1.0.0' } };
  for (const [mod, ver] of Object.entries(mods)) packages[`node_modules/${mod}`] = { version: ver };
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }, null, 2));
  fs.writeFileSync(path.join(dir, 'package.json'), `${JSON.stringify(pkgJson, null, 2)}\n`);
  return dir;
};

function runAction(mode, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [ACTION, mode], { cwd: ROOT, timeout: 60000, env: { ...process.env, ...env } });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}

// a pnpm project: package.json + a minimal v9 pnpm-lock.yaml listing packages
const writePnpm = (name, pkgs, extra = {}) => {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), `${JSON.stringify({ name: 'proj', version: '1.0.0', ...extra }, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, 'pnpm-lock.yaml'), `lockfileVersion: '9.0'\npackages:\n${pkgs.map((p) => `  ${p}: {}`).join('\n')}\n`);
  return dir;
};

const writeWorkflow = (dir, body) => {
  const wf = path.join(dir, '.github', 'workflows');
  fs.mkdirSync(wf, { recursive: true });
  fs.writeFileSync(path.join(wf, 'ci.yml'), body);
};

before(async () => {
  // env-read only -> LOW; child_process.exec -> HIGH; base64/atob -> HIGH (obf)
  const tarballs = {
    '/low.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'node l.js' } }),
      'package/l.js': 'const home = process.env.HOME;\n',
    }),
    '/high.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'node h.js' } }),
      'package/h.js': "require('child_process').exec('echo pwned');\n",
    }),
    '/mal.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'node m.js' } }),
      'package/m.js': 'const home = process.env.HOME;\n', // LOW behavior, but OSV flags it
    }),
  };
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const port = server.address().port;
      if (tarballs[req.url]) return res.writeHead(200).end(tarballs[req.url]);
      if (req.url === '/v1/querybatch') {
        const queries = JSON.parse(body).queries;
        return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
          results: queries.map((q) => (q.package.name === 'malpkg' ? { vulns: [{ id: 'MAL-2026-0001' }] } : {})),
        }));
      }
      // trust enrichment: packument (age/maintainers/provenance) + downloads.
      // low1 is old and provenanced so an age/provenance policy can approve it.
      if (req.url === '/low1') {
        return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
          time: { '1.0.0': '2020-01-01T00:00:00.000Z' },
          maintainers: [{ name: 'a' }, { name: 'b' }],
          versions: { '1.0.0': { dist: { attestations: { url: 'sigstore' } } } },
        }));
      }
      if (req.url.startsWith('/downloads/point/last-week/')) {
        return res.writeHead(200, { 'content-type': 'application/json' }).end('{"downloads":5000}');
      }
      const doc = {
        '/low1/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node l.js' }, dist: { tarball: `http://127.0.0.1:${port}/low.tgz` } },
        '/low2/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node l.js' }, dist: { tarball: `http://127.0.0.1:${port}/low.tgz` } },
        '/low3/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node l.js' }, dist: { tarball: `http://127.0.0.1:${port}/low.tgz` } },
        '/highpkg/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node h.js' }, dist: { tarball: `http://127.0.0.1:${port}/high.tgz` } },
        '/malpkg/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node m.js' }, dist: { tarball: `http://127.0.0.1:${port}/mal.tgz` } },
        '/cleanpkg/1.0.0': { version: '1.0.0', scripts: {} },
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
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-allow-'));
  process.env.NPM_SCRIPT_LENS_CACHE_DIR = path.join(tmp, 'cache');
  // stub npms: one reports v12, one reports v10 (for --ci-check gating)
  npm12 = path.join(tmp, 'npm12.js');
  fs.writeFileSync(npm12, "if (process.argv.includes('--version')) { console.log('12.0.1'); }\n");
  npm10 = path.join(tmp, 'npm10.js');
  fs.writeFileSync(npm10, "if (process.argv.includes('--version')) { console.log('10.9.3'); }\n");
});

after(() => server.close());

test('acceptance: 3 low-risk + 1 high-risk -> 3 allowScripts entries, 1 _review', async () => {
  const dir = writeProj('accept', { low1: '1.0.0', low2: '1.0.0', low3: '1.0.0', highpkg: '1.0.0' });
  const out = await runCli(['allow', '--path', dir]);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.strictEqual(Object.keys(j.allowScripts).length, 3, out.stdout);
  assert.strictEqual(j._review.length, 1, out.stdout);
  assert.strictEqual(j.allowScripts['low1@1.0.0'], true);
  assert.strictEqual(j.allowScripts['low2@1.0.0'], true);
  assert.strictEqual(j.allowScripts['low3@1.0.0'], true);
  assert.deepStrictEqual(j._review, ['highpkg@1.0.0']);
  // human summary on stderr
  assert.ok(out.stderr.includes('3 packages auto-approved, 1 need manual review.'), out.stderr);
});

test('output is valid JSON with exactly allowScripts + _review keys', async () => {
  const dir = writeProj('shape', { low1: '1.0.0', highpkg: '1.0.0', cleanpkg: '1.0.0' });
  const out = await runCli(['allow', '--path', dir]);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout); // JSON.parse succeeds == acceptance
  assert.deepStrictEqual(Object.keys(j).sort(), ['_review', 'allowScripts']);
  // clean package with no install scripts is omitted from both
  assert.ok(!('cleanpkg@1.0.0' in j.allowScripts));
  assert.ok(!j._review.includes('cleanpkg@1.0.0'));
});

test('known-malicious LOW-behavior package is held for review, not auto-approved', async () => {
  const dir = writeProj('mal', { low1: '1.0.0', malpkg: '1.0.0' });
  const out = await runCli(['allow', '--path', dir]);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.strictEqual(j.allowScripts['low1@1.0.0'], true);
  assert.ok(!('malpkg@1.0.0' in j.allowScripts), 'malicious never auto-approved');
  assert.ok(j._review.includes('malpkg@1.0.0'), out.stdout);
});

test('--input classifies a saved `audit --json` result without a fresh scan', async () => {
  const dir = writeProj('viainput', { low1: '1.0.0', highpkg: '1.0.0' });
  const audit = await runCli(['audit', '--path', dir, '--json']);
  assert.strictEqual(audit.status, 0, audit.stderr);
  const file = path.join(tmp, 'audit.json');
  fs.writeFileSync(file, audit.stdout);
  // point --input at the file; registry is unreachable-proof because no scan runs
  const out = await runCli(['allow', '--input', file], { NPM_SCRIPT_LENS_REGISTRY: 'http://127.0.0.1:1' });
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.strictEqual(j.allowScripts['low1@1.0.0'], true);
  assert.deepStrictEqual(j._review, ['highpkg@1.0.0']);
});

test('allow auto-detects pnpm from pnpm-lock.yaml and emits an allowBuilds block', async () => {
  const dir = path.join(tmp, 'pnpmdetect');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  fs.writeFileSync(path.join(dir, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\npackages:\n  low1@1.0.0: {}\n  highpkg@1.0.0: {}\n");
  const out = await runCli(['allow', '--path', dir, '--no-trust']);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.strictEqual(j.allowBuilds.low1, true, out.stdout);
  assert.ok(!('allowScripts' in j), 'pnpm output uses allowBuilds, not allowScripts');
  assert.ok(j._review.includes('highpkg@1.0.0'));
  assert.ok(out.stderr.includes('pnpm, allowlist in pnpm-workspace.yaml'), out.stderr);
});

test('allow --manager bun overrides detection and emits trustedDependencies', async () => {
  const dir = writeProj('mgroverride', { low1: '1.0.0', highpkg: '1.0.0' }); // npm lockfile
  const out = await runCli(['allow', '--path', dir, '--no-trust', '--manager', 'bun']);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.deepStrictEqual(j.trustedDependencies, ['low1'], out.stdout);
  assert.ok(out.stderr.includes('bun'), out.stderr);
  assert.ok(/REPLACES/i.test(out.stderr), 'warns about bun replacing its default trusted list');
});

test('allow --manager rejects an unknown package manager', async () => {
  const dir = writeProj('mgrbad', { low1: '1.0.0' });
  const out = await runCli(['allow', '--path', dir, '--no-trust', '--manager', 'cargo']);
  assert.strictEqual(out.status, 2, out.stderr);
  assert.ok(out.stderr.includes('unknown package manager'), out.stderr);
});

test('--write merges only the auto-approved entries into package.json, preserving existing', async () => {
  const dir = writeProj('writeauto', { low1: '1.0.0', highpkg: '1.0.0' },
    { name: 'proj', version: '1.0.0', allowScripts: { 'keepme@2.0.0': true } });
  const out = await runCli(['allow', '--path', dir, '--write']);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stderr.includes('wrote 1 auto-approved entry'), out.stderr);
  assert.ok(out.stderr.includes('1 still need manual review'), out.stderr);
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  assert.strictEqual(pkg.allowScripts['keepme@2.0.0'], true, 'existing entry preserved');
  assert.strictEqual(pkg.allowScripts['low1@1.0.0'], true, 'auto-approved LOW written true');
  assert.ok(!('highpkg@1.0.0' in pkg.allowScripts), 'HIGH left out for manual review, not written');
});

test('--write with nothing auto-approvable leaves package.json untouched', async () => {
  const dir = writeProj('writenone', { highpkg: '1.0.0' });
  const before = fs.readFileSync(path.join(dir, 'package.json'), 'utf8');
  const out = await runCli(['allow', '--path', dir, '--write']);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stderr.includes('nothing auto-approved'), out.stderr);
  assert.strictEqual(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'), before, 'file unchanged');
});

test('--ci-check exits 1: GitHub Actions npm install + no allowScripts + npm v12', async () => {
  const dir = writeProj('cibreak', { low1: '1.0.0' });
  writeWorkflow(dir, 'jobs:\n  build:\n    steps:\n      - run: npm install\n');
  const out = await runCli(['allow', '--path', dir, '--ci-check'], { NPM_SCRIPT_LENS_NPM: `node ${npm12}` });
  assert.strictEqual(out.status, 1, out.stderr);
  assert.ok(out.stderr.includes('CI will break on npm v12: run lens allow to generate allowScripts block.'), out.stderr);
});

test('--ci-check passes when package.json already has an allowScripts block', async () => {
  const dir = writeProj('ciok', { low1: '1.0.0' }, { name: 'proj', version: '1.0.0', allowScripts: { 'low1@1.0.0': true } });
  writeWorkflow(dir, 'jobs:\n  build:\n    steps:\n      - run: npm ci\n');
  const out = await runCli(['allow', '--path', dir, '--ci-check'], { NPM_SCRIPT_LENS_NPM: `node ${npm12}` });
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stderr.includes('ci-check passed'), out.stderr);
});

test('--ci-check passes on npm < 12 even with a workflow install and no allowScripts', async () => {
  const dir = writeProj('ciold', { low1: '1.0.0' });
  writeWorkflow(dir, 'jobs:\n  build:\n    steps:\n      - run: npm install\n');
  const out = await runCli(['allow', '--path', dir, '--ci-check'], { NPM_SCRIPT_LENS_NPM: `node ${npm10}` });
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stderr.includes('v10'), out.stderr);
});

test('--ci-check passes when no workflow runs npm install', async () => {
  const dir = writeProj('cinoinstall', { low1: '1.0.0' });
  writeWorkflow(dir, 'jobs:\n  build:\n    steps:\n      - run: echo hello\n');
  const out = await runCli(['allow', '--path', dir, '--ci-check'], { NPM_SCRIPT_LENS_NPM: `node ${npm12}` });
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stderr.includes('no workflow runs npm install'), out.stderr);
});

test('completion prints a sourceable script per shell; rejects unknown', async () => {
  const bash = await runCli(['completion', 'bash']);
  assert.strictEqual(bash.status, 0, bash.stderr);
  assert.ok(bash.stdout.includes('complete -F _npm_script_lens'), bash.stdout);
  assert.ok(bash.stdout.includes('audit') && bash.stdout.includes('allow'));
  const fish = await runCli(['completion', 'fish']);
  assert.ok(fish.stdout.includes('complete -c npm-script-lens'), fish.stdout);
  const bad = await runCli(['completion', 'tcsh']);
  assert.strictEqual(bad.status, 2, bad.stdout);
  assert.ok(bad.stderr.includes('unsupported shell'), bad.stderr);
});

test('init scaffolds a policy + CI workflow, skips existing, --force overwrites', async () => {
  const dir = path.join(tmp, 'initproj');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  const out = await runCli(['init', '--path', dir]);
  assert.strictEqual(out.status, 0, out.stderr);
  const pol = path.join(dir, 'script-lens.policy.json');
  const wf = path.join(dir, '.github', 'workflows', 'script-lens.yml');
  assert.ok(fs.existsSync(pol) && fs.existsSync(wf), out.stdout);
  assert.strictEqual(JSON.parse(fs.readFileSync(pol, 'utf8')).autoApprove.maxRisk, 'LOW');
  assert.ok(fs.readFileSync(wf, 'utf8').includes("ci-check: 'true'"), 'workflow gates with ci-check');
  // second run without --force skips
  fs.writeFileSync(pol, '{"marker":1}');
  const again = await runCli(['init', '--path', dir]);
  assert.ok(again.stdout.includes('skipped (exists)'), again.stdout);
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(pol, 'utf8')), { marker: 1 }, 'not overwritten');
  // --force overwrites
  const forced = await runCli(['init', '--path', dir, '--force']);
  assert.ok(forced.stdout.includes('wrote governance policy'), forced.stdout);
  assert.strictEqual(JSON.parse(fs.readFileSync(pol, 'utf8')).autoApprove.maxRisk, 'LOW');
  // --auto-fix adds the bot workflow
  const af = await runCli(['init', '--path', dir, '--auto-fix', '--force']);
  assert.ok(af.stdout.includes('auto-fix workflow'), af.stdout);
  const afWf = fs.readFileSync(path.join(dir, '.github', 'workflows', 'script-lens-autofix.yml'), 'utf8');
  assert.ok(afWf.includes('sync --write') && afWf.includes('renovate/**'), 'auto-fix reconciles on bot branches');
});

test('allow honors a policy file: maxRisk HIGH auto-approves a HIGH package', async () => {
  const dir = writeProj('policyproj', { low1: '1.0.0', highpkg: '1.0.0' });
  fs.writeFileSync(path.join(dir, 'script-lens.policy.json'), JSON.stringify({ autoApprove: { maxRisk: 'HIGH' } }));
  const out = await runCli(['allow', '--path', dir, '--no-trust']);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.strictEqual(j.allowScripts['low1@1.0.0'], true);
  assert.strictEqual(j.allowScripts['highpkg@1.0.0'], true, 'HIGH auto-approved under policy');
  assert.ok(out.stderr.includes('using policy'), out.stderr);
});

test('policy trust-all: minAgeDays + requireProvenance approve an old, provenanced LOW package', async () => {
  const dir = writeProj('trustall', { low1: '1.0.0' });
  fs.writeFileSync(path.join(dir, 'script-lens.policy.json'), JSON.stringify({ autoApprove: { maxRisk: 'LOW', minAgeDays: 30, requireProvenance: true } }));
  const out = await runCli(['allow', '--path', dir]); // trust ON: policy triggers trust-all for the LOW pkg
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.strictEqual(j.allowScripts['low1@1.0.0'], true, 'trust was fetched for a LOW package, and it met the age/provenance policy');
});

test('policy age with --no-trust fails closed (no trust data to verify against)', async () => {
  const dir = writeProj('trustnone', { low1: '1.0.0' });
  fs.writeFileSync(path.join(dir, 'script-lens.policy.json'), JSON.stringify({ autoApprove: { maxRisk: 'LOW', minAgeDays: 30 } }));
  const out = await runCli(['allow', '--path', dir, '--no-trust']);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.ok(!('low1@1.0.0' in j.allowScripts), 'age unknown → not auto-approved');
  assert.ok(j._review.includes('low1@1.0.0'));
});

test('allow honors a policy waiver denying an otherwise-safe package', async () => {
  const dir = writeProj('policywaiver', { low1: '1.0.0' });
  fs.writeFileSync(path.join(dir, 'script-lens.policy.json'), JSON.stringify({ waivers: { low1: { allow: false, reason: 'blocked internally' } } }));
  const out = await runCli(['allow', '--path', dir, '--no-trust']);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.ok(!('low1@1.0.0' in j.allowScripts), 'waiver denied the LOW package');
  assert.ok(j._review.includes('low1@1.0.0'));
});

test('review on a pnpm project emits an allowBuilds decision block', async () => {
  const dir = writePnpm('pnpmreview', ['low1@1.0.0', 'highpkg@1.0.0']);
  const out = await runCli(['review', '--path', dir, '--no-trust', '--json']);
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.strictEqual(j.manager, 'pnpm');
  assert.ok('allowBuilds' in j && !('allowScripts' in j), out.stdout);
  assert.strictEqual(j.allowBuilds.low1, true, 'LOW → true');
  assert.strictEqual(j.allowBuilds.highpkg, false, 'HIGH → false');
});

test('review --output-allowscripts writes allowBuilds to pnpm-workspace.yaml', async () => {
  const dir = writePnpm('pnpmrevwrite', ['low1@1.0.0']);
  const out = await runCli(['review', '--path', dir, '--no-trust', '--output-allowscripts']);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stderr.includes('wrote 1 allowBuilds entry'), out.stderr);
  assert.match(fs.readFileSync(path.join(dir, 'pnpm-workspace.yaml'), 'utf8'), /allowBuilds:\n {2}low1: true/);
});

test('sync --write reconciles pnpm allowBuilds: keeps scripted, drops stale', async () => {
  const dir = writePnpm('pnpmsync', ['low1@1.0.0']);
  fs.writeFileSync(path.join(dir, 'pnpm-workspace.yaml'), 'allowBuilds:\n  gonepkg: true\n  low1: true\n');
  const out = await runCli(['sync', '--path', dir, '--no-trust', '--write']);
  assert.strictEqual(out.status, 0, out.stderr);
  const y = fs.readFileSync(path.join(dir, 'pnpm-workspace.yaml'), 'utf8');
  assert.match(y, /low1: true/, 'still-scripted entry kept');
  assert.ok(!y.includes('gonepkg'), 'entry for a package no longer in the lockfile is dropped');
});

test('sync --check exits 1 on drift, 0 when the allowlist covers the lockfile (pnpm)', async () => {
  const dir = writePnpm('synccheck', ['low1@1.0.0']);
  // no allowBuilds yet → low1 is scripted and uncovered → drift
  let out = await runCli(['sync', '--check', '--path', dir, '--no-trust']);
  assert.strictEqual(out.status, 1, out.stderr);
  assert.ok(out.stderr.includes('out of sync'), out.stderr);
  // cover it → in sync
  fs.writeFileSync(path.join(dir, 'pnpm-workspace.yaml'), 'allowBuilds:\n  low1: true\n');
  out = await runCli(['sync', '--check', '--path', dir, '--no-trust']);
  assert.strictEqual(out.status, 0, out.stderr);
});

test('sync --manager bun writes trustedDependencies (trusts only true decisions)', async () => {
  const dir = writePnpm('bunsync', ['low1@1.0.0', 'highpkg@1.0.0']);
  const out = await runCli(['sync', '--path', dir, '--no-trust', '--manager', 'bun', '--write']);
  assert.strictEqual(out.status, 0, out.stderr);
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  assert.deepStrictEqual(pkg.trustedDependencies, ['low1'], 'HIGH omitted (bun can only express trust)');
});

test('action ci-check: fails the job (::error + summary) on the npm v12 break combo', async () => {
  const dir = writeProj('actionbreak', { low1: '1.0.0' });
  writeWorkflow(dir, 'jobs:\n  build:\n    steps:\n      - run: npm install\n');
  const summary = path.join(dir, 'summary.md');
  fs.writeFileSync(summary, '');
  const out = await runAction('ci-check', {
    INPUT_PATH: dir, GITHUB_STEP_SUMMARY: summary, NPM_SCRIPT_LENS_NPM: `node ${npm12}`,
  });
  assert.strictEqual(out.status, 1, out.stdout);
  assert.ok(out.stdout.includes('::error::CI will break on npm v12'), out.stdout);
  assert.ok(out.stdout.includes('allow --write'), out.stdout);
  assert.ok(fs.readFileSync(summary, 'utf8').includes('❌ npm v12 allowScripts check'), 'job summary written');
});

test('action ci-check: passes (exit 0 + ✅ summary) when allowScripts already present', async () => {
  const dir = writeProj('actionpass', { low1: '1.0.0' }, { name: 'proj', version: '1.0.0', allowScripts: { 'low1@1.0.0': true } });
  writeWorkflow(dir, 'jobs:\n  build:\n    steps:\n      - run: npm ci\n');
  const summary = path.join(dir, 'summary.md');
  fs.writeFileSync(summary, '');
  const out = await runAction('ci-check', {
    INPUT_PATH: dir, GITHUB_STEP_SUMMARY: summary, NPM_SCRIPT_LENS_NPM: `node ${npm12}`,
  });
  assert.strictEqual(out.status, 0, out.stdout);
  assert.ok(out.stdout.includes('allowScripts check passed'), out.stdout);
  assert.ok(fs.readFileSync(summary, 'utf8').includes('✅ npm v12 allowScripts check'), out.stdout);
});
