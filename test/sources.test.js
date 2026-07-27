'use strict';
// npm v12's allow-git / allow-remote coverage: collectNonRegistryDeps across
// all four lockfile dialects, analyzeSources classification (root vs
// transitive, workspace-conservative, mixed occurrences), the `sources` CLI
// (exact worked-example stdout, --json shape, --write preservation, both
// --check failure directions, the invalid =true trap), the ci-check
// extension, doctor's new fields, and the Action's sources-check mode.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { collectNonRegistryDeps, classifySourceSpec } = require('../src/lockfiles');
const { analyzeSources, checkSourceConfig, versionGte } = require('../src/sources');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const TRANSITIVE_FIXTURE = path.join(ROOT, 'fixtures', 'v12-git-transitive');
const GIT_ROOT_FIXTURE = path.join(ROOT, 'fixtures', 'v12-git-root');
const REMOTE_FIXTURE = path.join(ROOT, 'fixtures', 'v12-remote-tarball');
let tmp, npm12;

function run(args, env = {}, entry = CLI) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [entry, ...args], { cwd: ROOT, timeout: 60000, env: { ...process.env, ...env } });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdin.end();
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}

// a scratch project dir seeded from a fixture, plus optional extra files
function mkProj(name, fromFixture, files = {}) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  if (fromFixture) {
    for (const f of fs.readdirSync(fromFixture)) fs.copyFileSync(path.join(fromFixture, f), path.join(dir, f));
  }
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return dir;
}

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-sources-'));
  npm12 = path.join(tmp, 'npm12.js');
  fs.writeFileSync(npm12, "if (process.argv.includes('--version')) { console.log('12.0.1'); process.exit(0); }\n");
});

after(() => fs.rmSync(tmp, { recursive: true, force: true }));

// --- classifier + collectors, all four dialects ----------------------------

test('classifySourceSpec: git protocols and shorthands vs remote tarballs vs registry', () => {
  for (const s of ['git+ssh://git@github.com/a/b.git', 'git+https://github.com/a/b.git', 'git://github.com/a/b.git',
    'github:a/b', 'gitlab:a/b', 'bitbucket:a/b', 'github.com/a/b/0f2ab0d',
    'https://github.com/a/b.git#commit=0f2ab0d']) {
    assert.strictEqual(classifySourceSpec(s), 'git', s);
  }
  assert.strictEqual(classifySourceSpec('https://example.com/x-1.0.0.tgz'), 'remote');
  assert.strictEqual(classifySourceSpec('http://example.com/x.tgz'), 'remote');
  for (const s of ['^1.2.3', '1.0.0', 'npm:real@^2', 'file:../local', 'workspace:*', null, '']) {
    assert.strictEqual(classifySourceSpec(s), null, String(s));
  }
});

test('collectNonRegistryDeps: package-lock v3 — specs, resolved, parents', () => {
  const lock = fs.readFileSync(path.join(TRANSITIVE_FIXTURE, 'package-lock.json'), 'utf8');
  const deps = collectNonRegistryDeps(lock, 'npm');
  assert.deepStrictEqual(deps, [
    {
      name: 'left-pad', spec: 'github:left-pad/left-pad', kind: 'git',
      resolved: 'git+ssh://git@github.com/left-pad/left-pad.git#7aeb61ff2af04913b3f2c6784b5eb267157dd28d', parents: [],
    },
    {
      name: 'some-pkg', spec: 'git+ssh://git@github.com/a/b.git', kind: 'git',
      resolved: 'git+ssh://git@github.com/a/b.git#0f2ab0d70d3e919a5a5583eba7259b4b97b8b0cd', parents: ['my-lib'],
    },
  ]);
  // registry deps (my-lib, and every https registry tarball) never appear
  assert.ok(!deps.some((d) => d.name === 'my-lib'));
});

test('collectNonRegistryDeps: package-lock v1 fallback (version carries the URL)', () => {
  const lock = JSON.stringify({
    lockfileVersion: 1,
    dependencies: {
      'left-pad': { version: 'github:left-pad/left-pad', from: 'github:left-pad/left-pad' },
      'my-lib': {
        version: '1.0.0',
        resolved: 'https://registry.npmjs.org/my-lib/-/my-lib-1.0.0.tgz',
        requires: { 'some-pkg': 'git+ssh://git@github.com/a/b.git' },
        dependencies: { 'some-pkg': { version: 'git+ssh://git@github.com/a/b.git#0f2ab0d' } },
      },
    },
  });
  const deps = collectNonRegistryDeps(lock, 'npm');
  assert.deepStrictEqual(deps.map((d) => [d.name, d.kind, d.parents]),
    [['left-pad', 'git', []], ['some-pkg', 'git', ['my-lib']]]);
});

const YARN_CLASSIC = `# yarn lockfile v1


"left-pad@github:left-pad/left-pad":
  version "1.3.0"
  resolved "https://codeload.github.com/left-pad/left-pad/tar.gz/7aeb61ff"

my-lib@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/my-lib/-/my-lib-1.0.0.tgz#abc"
  dependencies:
    some-pkg "git+ssh://git@github.com/a/b.git"

"some-pkg@git+ssh://git@github.com/a/b.git":
  version "0.0.1"
  resolved "git+ssh://git@github.com/a/b.git#0f2ab0d"

"tarpkg@https://example.com/tarpkg-1.0.0.tgz":
  version "1.0.0"
  resolved "https://example.com/tarpkg-1.0.0.tgz#deadbeef"
`;

test('collectNonRegistryDeps: yarn classic — selector ranges classify, deps give parents', () => {
  const deps = collectNonRegistryDeps(YARN_CLASSIC, 'yarn');
  assert.deepStrictEqual(deps.map((d) => [d.name, d.kind, d.parents]),
    [['left-pad', 'git', []], ['some-pkg', 'git', ['my-lib']], ['tarpkg', 'remote', []]]);
  assert.strictEqual(deps[0].spec, 'github:left-pad/left-pad');
  assert.strictEqual(deps[0].resolved, 'https://codeload.github.com/left-pad/left-pad/tar.gz/7aeb61ff');
});

const YARN_BERRY = `# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10c0

"left-pad@github:left-pad/left-pad":
  version: 1.3.0
  resolution: "left-pad@https://github.com/left-pad/left-pad.git#commit=7aeb61ff"
  languageName: node
  linkType: hard

"my-lib@npm:^1.0.0":
  version: 1.0.0
  resolution: "my-lib@npm:1.0.0"
  dependencies:
    some-pkg: "git+ssh://git@github.com/a/b.git"
  languageName: node
  linkType: hard

"some-pkg@git+ssh://git@github.com/a/b.git":
  version: 0.0.1
  resolution: "some-pkg@https://github.com/a/b.git#commit=0f2ab0d"
  languageName: node
  linkType: hard
`;

test('collectNonRegistryDeps: yarn berry — a .git#commit= resolution is still a git dep', () => {
  const deps = collectNonRegistryDeps(YARN_BERRY, 'yarn');
  assert.deepStrictEqual(deps.map((d) => [d.name, d.kind, d.parents]),
    [['left-pad', 'git', []], ['some-pkg', 'git', ['my-lib']]]);
  assert.strictEqual(deps[0].resolved, 'https://github.com/left-pad/left-pad.git#commit=7aeb61ff',
    'the name@ prefix of berry resolutions is stripped');
});

const PNPM_V9 = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      left-pad:
        specifier: github:left-pad/left-pad
        version: https://codeload.github.com/left-pad/left-pad/tar.gz/7aeb61ff
      my-lib:
        specifier: ^1.0.0
        version: 1.0.0

packages:

  left-pad@https://codeload.github.com/left-pad/left-pad/tar.gz/7aeb61ff:
    resolution: {tarball: https://codeload.github.com/left-pad/left-pad/tar.gz/7aeb61ff}
    version: 1.3.0

  my-lib@1.0.0:
    resolution: {integrity: sha512-x}

  some-pkg@git+ssh://git@github.com/a/b.git#0f2ab0d:
    resolution: {commit: 0f2ab0d, repo: git@github.com/a/b.git, type: git}
    version: 0.0.1

snapshots:

  left-pad@https://codeload.github.com/left-pad/left-pad/tar.gz/7aeb61ff: {}

  my-lib@1.0.0:
    dependencies:
      some-pkg: git+ssh://git@github.com/a/b.git#0f2ab0d

  some-pkg@git+ssh://git@github.com/a/b.git#0f2ab0d: {}
`;

test('collectNonRegistryDeps: pnpm v9 — importer specifiers + snapshot deps', () => {
  const deps = collectNonRegistryDeps(PNPM_V9, 'pnpm');
  assert.deepStrictEqual(deps.map((d) => [d.name, d.kind, d.parents]),
    [['left-pad', 'git', []], ['some-pkg', 'git', ['my-lib']]]);
  assert.strictEqual(deps[0].spec, 'github:left-pad/left-pad', 'the importer specifier is what the user wrote');
});

const BUN_LOCK = `{
  // bun.lock is JSONC
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "bun-fixture",
      "dependencies": {
        "left-pad": "github:left-pad/left-pad",
        "my-lib": "^1.0.0",
      },
    },
  },
  "packages": {
    "left-pad": ["left-pad@github:left-pad/left-pad", {}, "7aeb61ff"],
    "my-lib": ["my-lib@1.0.0", "", { "dependencies": { "some-pkg": "git+ssh://git@github.com/a/b.git" } }, "sha512-x"],
    "some-pkg": ["some-pkg@git+ssh://git@github.com/a/b.git", {}, "0f2ab0d"],
  },
}
`;

test('collectNonRegistryDeps: bun.lock — workspace specs + package locators', () => {
  const deps = collectNonRegistryDeps(BUN_LOCK, 'bun');
  assert.deepStrictEqual(deps.map((d) => [d.name, d.kind, d.parents]),
    [['left-pad', 'git', []], ['some-pkg', 'git', ['my-lib']]]);
  assert.strictEqual(deps[0].spec, 'github:left-pad/left-pad');
});

// --- analyzeSources classification ----------------------------------------

test('analyzeSources: root vs transitive, minimal none/root/all, forcing chains', async () => {
  const a = await analyzeSources(TRANSITIVE_FIXTURE, { probeNpm: false });
  assert.strictEqual(a.git.minimal, 'all');
  assert.deepStrictEqual(a.git.deps.map((d) => [d.name, d.root]), [['left-pad', true], ['some-pkg', false]]);
  assert.deepStrictEqual(a.git.forcing, [{ name: 'some-pkg', via: ['my-lib', 'some-pkg'] }]);
  assert.strictEqual(a.remote.minimal, 'none');

  const b = await analyzeSources(GIT_ROOT_FIXTURE, { probeNpm: false });
  assert.strictEqual(b.git.minimal, 'root');
  assert.deepStrictEqual(b.git.forcing, []);

  const c = await analyzeSources(REMOTE_FIXTURE, { probeNpm: false });
  assert.strictEqual(c.git.minimal, 'none');
  assert.strictEqual(c.remote.minimal, 'root');
  assert.deepStrictEqual(c.remote.deps.map((d) => [d.name, d.root]), [['tarpkg', true]]);

  const d = await analyzeSources(path.join(ROOT, 'fixtures', 'demo'), { probeNpm: false });
  assert.strictEqual(d.git.minimal, 'none');
  assert.strictEqual(d.remote.minimal, 'none');
});

test('analyzeSources: a dep declared only in a workspace package.json is NOT root', async () => {
  const dir = mkProj('ws', null, {
    'package.json': JSON.stringify({ name: 'ws-root', version: '1.0.0', workspaces: ['packages/ws'] }),
    'package-lock.json': JSON.stringify({
      name: 'ws-root',
      lockfileVersion: 3,
      packages: {
        '': { name: 'ws-root', version: '1.0.0' },
        'packages/ws': { name: 'ws-pkg', version: '1.0.0', dependencies: { gitdep: 'github:a/b' } },
        'node_modules/ws-pkg': { resolved: 'packages/ws', link: true },
        'node_modules/gitdep': { version: '1.0.0', resolved: 'git+ssh://git@github.com/a/b.git#0f2ab0d' },
      },
    }),
  });
  const a = await analyzeSources(dir, { probeNpm: false });
  assert.strictEqual(a.git.minimal, 'all', 'allow-git=root only honors the ROOT package.json — conservative');
  assert.deepStrictEqual(a.git.deps.map((d) => [d.name, d.root]), [['gitdep', false]]);
});

test('analyzeSources: root-declared AND transitively declared counts as root only if every occurrence is root', async () => {
  const dir = mkProj('mixed', null, {
    'package.json': JSON.stringify({ name: 'mixed', version: '1.0.0', dependencies: { gitdep: 'github:a/b', 'other-lib': '1.0.0' } }),
    'package-lock.json': JSON.stringify({
      name: 'mixed',
      lockfileVersion: 3,
      packages: {
        '': { name: 'mixed', version: '1.0.0', dependencies: { gitdep: 'github:a/b', 'other-lib': '1.0.0' } },
        'node_modules/gitdep': { version: '1.0.0', resolved: 'git+ssh://git@github.com/a/b.git#0f2ab0d' },
        'node_modules/other-lib': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/other-lib/-/other-lib-1.0.0.tgz',
          dependencies: { gitdep: 'github:a/b' },
        },
      },
    }),
  });
  const a = await analyzeSources(dir, { probeNpm: false });
  assert.deepStrictEqual(a.git.deps.map((d) => [d.name, d.root]), [['gitdep', false]],
    'one transitive occurrence forces all even though the name is also root-declared');
  assert.strictEqual(a.git.minimal, 'all');
});

test('checkSourceConfig + versionGte units', async () => {
  const analysis = await analyzeSources(GIT_ROOT_FIXTURE, { probeNpm: false });
  const cfg = (git, remote = null) => ({ file: '.npmrc', exists: true, git, remote });
  assert.strictEqual(checkSourceConfig(analysis, cfg('root')).ok, true);
  assert.strictEqual(checkSourceConfig(analysis, cfg(null)).failures[0].kind, 'insufficient');
  assert.strictEqual(checkSourceConfig(analysis, cfg('all')).failures[0].kind, 'over-permissive');
  assert.strictEqual(checkSourceConfig(analysis, cfg('true')).failures[0].kind, 'invalid');
  assert.strictEqual(checkSourceConfig(analysis, cfg('root', 'root')).failures[0].kind, 'over-permissive',
    'allow-remote=root with zero remote deps is over-permission too');
  assert.ok(versionGte('11.16.1', '11.10.0'));
  assert.ok(versionGte('12.0.0', '11.15.0'));
  assert.ok(!versionGte('11.9.9', '11.10.0'));
  assert.ok(versionGte('11.10.0', '11.10.0'));
});

// --- CLI e2e ---------------------------------------------------------------

test('cli e2e: sources reproduces the worked example byte-for-byte', async () => {
  const { status, stdout } = await run(['sources', '--path', TRANSITIVE_FIXTURE]);
  assert.strictEqual(status, 0);
  assert.strictEqual(stdout, [
    'git dependencies (2)',
    '  ROOT        left-pad @ github:left-pad/left-pad',
    '  TRANSITIVE  some-pkg @ git+ssh://git@github.com/a/b.git   via my-lib -> some-pkg',
    'remote dependencies (0)',
    '',
    'minimal correct .npmrc:',
    '  allow-git=all',
    '',
    'allow-git=all is required because 1 git dependency is transitive; allow-git=root would otherwise suffice.',
    'Re-point or drop `some-pkg` (via my-lib) to tighten this to allow-git=root.',
    '',
  ].join('\n'));
});

test('cli e2e: sources --json emits the { git, remote, npmrc } shape', async () => {
  const { status, stdout } = await run(['sources', '--json', '--path', TRANSITIVE_FIXTURE]);
  assert.strictEqual(status, 0);
  const parsed = JSON.parse(stdout);
  assert.deepStrictEqual(Object.keys(parsed), ['git', 'remote', 'npmrc']);
  assert.strictEqual(parsed.git.minimal, 'all');
  assert.deepStrictEqual(parsed.git.forcing, [{ name: 'some-pkg', via: ['my-lib', 'some-pkg'] }]);
  assert.deepStrictEqual(parsed.remote, { deps: [], minimal: 'none' });
  assert.strictEqual(parsed.npmrc, 'allow-git=all\n');
  // root-only project: minimal is root; no deps at all: no npmrc lines
  const rootOnly = JSON.parse((await run(['sources', '--json', '--path', GIT_ROOT_FIXTURE])).stdout);
  assert.strictEqual(rootOnly.git.minimal, 'root');
  assert.strictEqual(rootOnly.npmrc, 'allow-git=root\n');
  const none = JSON.parse((await run(['sources', '--json', '--path', path.join(ROOT, 'fixtures', 'demo')])).stdout);
  assert.strictEqual(none.npmrc, '');
});

test('cli e2e: sources on a clean project reports zero and exits 0', async () => {
  const { status, stdout } = await run(['sources', '--path', path.join(ROOT, 'fixtures', 'demo')]);
  assert.strictEqual(status, 0);
  assert.ok(stdout.includes('git dependencies (0)'));
  assert.ok(stdout.includes('allow-git not needed (no git dependencies)'));
  assert.ok(stdout.includes('allow-remote not needed (no remote dependencies)'));
});

test('cli e2e: sources --write preserves comments and unrelated keys byte-for-byte', async () => {
  const npmrc = '# team registry\nregistry=https://registry.example/\n\n; another comment\nfund=false\n';
  const dir = mkProj('write', TRANSITIVE_FIXTURE, { '.npmrc': npmrc });
  const { status, stderr } = await run(['sources', '--write', '--path', dir]);
  assert.strictEqual(status, 0);
  assert.ok(stderr.includes(`wrote allow-git=all to ${path.join(dir, '.npmrc')}`), stderr);
  assert.strictEqual(fs.readFileSync(path.join(dir, '.npmrc'), 'utf8'), `${npmrc}allow-git=all\n`,
    'original bytes intact, only the needed line appended');
  // idempotent: a second --write changes nothing
  const again = await run(['sources', '--write', '--path', dir]);
  assert.ok(again.stderr.includes('nothing to write'), again.stderr);
  assert.strictEqual(fs.readFileSync(path.join(dir, '.npmrc'), 'utf8'), `${npmrc}allow-git=all\n`);
});

test('cli e2e: sources --check fails on INSUFFICIENT config (missing .npmrc)', async () => {
  const { status, stderr } = await run(['sources', '--check', '--path', TRANSITIVE_FIXTURE]);
  assert.strictEqual(status, 1);
  assert.ok(stderr.includes('FAIL (insufficient)'), stderr);
  assert.ok(stderr.includes('allow-git=none (the npm v12 default'), stderr);
  assert.ok(stderr.includes('sources --write'), stderr);
});

test('cli e2e: sources --check fails on OVER-permission with a distinct message', async () => {
  const dir = mkProj('over', GIT_ROOT_FIXTURE, { '.npmrc': 'allow-git=all\n' });
  const { status, stderr } = await run(['sources', '--check', '--path', dir]);
  assert.strictEqual(status, 1);
  assert.ok(stderr.includes('FAIL (over-permissive)'), stderr);
  assert.ok(stderr.includes('tighten to allow-git=root'), stderr);
});

test('cli e2e: sources --check fails on an out-of-enum value, naming the valid three', async () => {
  // published migration guides recommend `allow-git=true` — npm rejects it
  const dir = mkProj('invalid', GIT_ROOT_FIXTURE, { '.npmrc': 'allow-git=true\n' });
  const { status, stderr } = await run(['sources', '--check', '--path', dir]);
  assert.strictEqual(status, 1);
  assert.ok(stderr.includes('FAIL (invalid)'), stderr);
  assert.ok(stderr.includes('all | none | root'), stderr);
});

test('cli e2e: sources --check passes on the exact minimal config', async () => {
  const dir = mkProj('exact', GIT_ROOT_FIXTURE, { '.npmrc': 'allow-git=root\n' });
  const { status, stderr } = await run(['sources', '--check', '--path', dir]);
  assert.strictEqual(status, 0, stderr);
  assert.ok(stderr.includes('sources check passed'), stderr);
});

test('cli e2e: non-npm lockfiles report deps but the .npmrc emitter is npm-only', async () => {
  const dir = mkProj('yarnproj', null, {
    'package.json': JSON.stringify({ name: 'y', version: '1.0.0', dependencies: { 'left-pad': 'github:left-pad/left-pad', 'my-lib': '^1.0.0', tarpkg: 'https://example.com/tarpkg-1.0.0.tgz' } }),
    'yarn.lock': YARN_CLASSIC,
  });
  const { status, stdout, stderr } = await run(['sources', '--write', '--path', dir]);
  assert.strictEqual(status, 0);
  assert.ok(stdout.includes('git dependencies (2)'), stdout);
  assert.ok(stdout.includes('  TRANSITIVE  some-pkg @ git+ssh://git@github.com/a/b.git   via my-lib -> some-pkg'), stdout);
  assert.ok(stdout.includes('remote dependencies (1)'), stdout);
  assert.ok(stdout.includes('the .npmrc emitter targets npm only'), stdout);
  assert.ok(stderr.includes('--write skipped'), stderr);
  assert.ok(!fs.existsSync(path.join(dir, '.npmrc')), 'no .npmrc written for a yarn project');
});

test('cli e2e: sources errors cleanly (exit 2) with no lockfile', async () => {
  const dir = mkProj('nolock', null, { 'package.json': '{"name":"x","version":"1.0.0"}' });
  const { status, stderr } = await run(['sources', '--path', dir]);
  assert.strictEqual(status, 2);
  assert.ok(stderr.includes('lockfile not found'), stderr);
});

// --- ci-check extension ----------------------------------------------------

test('allow --ci-check fails when git deps exist and the committed config is insufficient', async () => {
  // allowScripts is covered, npm is v12, a workflow installs — but the git
  // dep has no allow-git: exactly the second silent v12 CI break
  const dir = mkProj('cibreak', TRANSITIVE_FIXTURE, {
    'package.json': JSON.stringify({
      name: 'v12-git-transitive-fixture',
      version: '1.0.0',
      dependencies: { 'left-pad': 'github:left-pad/left-pad', 'my-lib': '1.0.0' },
      allowScripts: { 'core-js@3.38.1': true },
    }),
    '.github/workflows/ci.yml': 'jobs:\n  b:\n    steps:\n      - run: npm ci\n',
  });
  const { status, stderr } = await run(['allow', '--ci-check', '--path', dir], { NPM_SCRIPT_LENS_NPM: `node ${npm12}` });
  assert.strictEqual(status, 1, stderr);
  assert.ok(stderr.includes('CI will break on npm v12'), stderr);
  assert.ok(stderr.includes('allow-git'), stderr);
  assert.ok(stderr.includes('sources --write'), stderr);
});

test('allow --ci-check passes when the committed .npmrc covers the git deps', async () => {
  const dir = mkProj('cipass', GIT_ROOT_FIXTURE, {
    'package.json': JSON.stringify({
      name: 'v12-git-root-fixture',
      version: '1.0.0',
      dependencies: { 'left-pad': 'github:left-pad/left-pad', plainpkg: '1.0.0' },
      allowScripts: { 'core-js@3.38.1': true },
    }),
    '.npmrc': 'allow-git=root\n',
    '.github/workflows/ci.yml': 'jobs:\n  b:\n    steps:\n      - run: npm ci\n',
  });
  const { status, stderr } = await run(['allow', '--ci-check', '--path', dir], { NPM_SCRIPT_LENS_NPM: `node ${npm12}` });
  assert.strictEqual(status, 0, stderr);
  assert.ok(stderr.includes('ci-check passed: package.json already has an allowScripts block'), stderr);
});

// --- doctor ----------------------------------------------------------------

test('doctor --json includes the sources counts, minimal values, and support checks', async () => {
  const { status, stdout } = await run(['doctor', '--json', '--no-live', '--path', TRANSITIVE_FIXTURE]);
  assert.strictEqual(status, 0, stdout);
  const r = JSON.parse(stdout);
  assert.deepStrictEqual(r.sources.git, { count: 2, minimal: 'all', committed: null });
  assert.deepStrictEqual(r.sources.remote, { count: 0, minimal: 'none', committed: null });
  assert.ok(typeof r.npmVersion === 'string' || r.npmVersion === null);
  assert.ok(r.checks.some((c) => c.name === 'allow-git config' && c.status === 'warn'), 'uncovered git deps warn');
  assert.ok(r.checks.some((c) => c.name === 'allow-git support'));
  assert.ok(r.checks.some((c) => c.name === 'detector v12-allow-git-root'
    && c.detail.includes('npm/cli/issues/9189')), 'the #9189 detector is surfaced with its upstream status');
});

// --- Action ----------------------------------------------------------------

test('action e2e: sources-check mode fails with ::error and a ❌ summary on uncovered git deps', async () => {
  const summaryFile = path.join(tmp, 'summary-fail.md');
  fs.writeFileSync(summaryFile, '');
  const { status, stdout } = await run(['sources-check'], {
    INPUT_PATH: TRANSITIVE_FIXTURE,
    GITHUB_STEP_SUMMARY: summaryFile,
  }, path.join(ROOT, 'src', 'action.js'));
  assert.strictEqual(status, 1, stdout);
  assert.ok(stdout.includes('::error::'), stdout);
  assert.ok(stdout.includes('allow-git'), stdout);
  const summary = fs.readFileSync(summaryFile, 'utf8');
  assert.ok(summary.includes('## ❌ npm v12 git/remote dependency check'), summary);
  assert.ok(summary.includes('sources --write'), summary);
});

test('action e2e: sources-check mode passes with a job-summary line when .npmrc matches', async () => {
  const dir = mkProj('action-pass', GIT_ROOT_FIXTURE, { '.npmrc': 'allow-git=root\n' });
  const summaryFile = path.join(tmp, 'summary-pass.md');
  fs.writeFileSync(summaryFile, '');
  const { status, stdout } = await run(['sources-check'], {
    INPUT_PATH: dir,
    GITHUB_STEP_SUMMARY: summaryFile,
  }, path.join(ROOT, 'src', 'action.js'));
  assert.strictEqual(status, 0, stdout);
  assert.ok(stdout.includes('1 git dep(s) (minimal allow-git=root)'), stdout);
  assert.ok(fs.readFileSync(summaryFile, 'utf8').includes('## ✅ npm v12 git/remote dependency check'));
});
