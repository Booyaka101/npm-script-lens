'use strict';
// The January-2027 publish-token cliff: classifier units (TRUSTED / STAGED /
// TOKEN / UNKNOWN), the version-floor comparator, every publish-* fixture's
// verdict + exit code + emitted fix, the edge cases (mixed workflow, reusable
// job, write-all, no publish step), --json / --sarif surfaces, the doctor
// section, and the Action's publish-check mode. Pure fs — no network anywhere.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const {
  analyzePublish, checkPublish, classifyAuth, nodePinBelowFloor, enginesMinimum,
  detectRunPublisher, classifyRunsOn, parseYamlish, idTokenGrant, publishFindings,
} = require('../src/publish');
const { PUBLISH } = require('../src/npm-contract');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const ACTION = path.join(ROOT, 'src', 'action.js');
const FIX = (name) => path.join(ROOT, 'fixtures', name);
let tmp;

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

function mkProj(name, files) {
  const dir = path.join(tmp, name);
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return dir;
}

before(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-publish-')); });
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

// --- classifier + comparator units -----------------------------------------

test('classifyAuth: exactly one of TRUSTED/STAGED/TOKEN/UNKNOWN', () => {
  assert.strictEqual(classifyAuth({ staged: true, token: { key: 'NPM_TOKEN' } }), 'STAGED');
  assert.strictEqual(classifyAuth({ token: { key: 'NODE_AUTH_TOKEN', line: 5 } }), 'TOKEN');
  assert.strictEqual(classifyAuth({ idToken: { line: 3 } }), 'TRUSTED');
  // both present is ambiguous, neither is ambiguous — UNKNOWN, never a guess
  assert.strictEqual(classifyAuth({ token: { key: 'NPM_TOKEN' }, idToken: { line: 3 } }), 'UNKNOWN');
  assert.strictEqual(classifyAuth({}), 'UNKNOWN');
  assert.strictEqual(classifyAuth({ reusable: true }), 'UNKNOWN');
});

test('nodePinBelowFloor: numeric pins answer, floats and dynamics do not', () => {
  const floor = PUBLISH.trusted.minNode; // 22.14.0
  assert.strictEqual(nodePinBelowFloor('20', floor), true);
  assert.strictEqual(nodePinBelowFloor('18.19.0', floor), true);
  assert.strictEqual(nodePinBelowFloor('22.13.1', floor), true);
  assert.strictEqual(nodePinBelowFloor('22.14.0', floor), false);
  assert.strictEqual(nodePinBelowFloor('22.15.0', floor), false);
  assert.strictEqual(nodePinBelowFloor('24', floor), false);
  // a bare major / .x floats to the newest patch of that line
  assert.strictEqual(nodePinBelowFloor('22', floor), false);
  assert.strictEqual(nodePinBelowFloor('22.x', floor), false);
  assert.strictEqual(nodePinBelowFloor('20.x', floor), true);
  // unanswerable pins stay null — never a false warning
  assert.strictEqual(nodePinBelowFloor('lts/*', floor), null);
  assert.strictEqual(nodePinBelowFloor('${{ matrix.node }}', floor), null);
  assert.strictEqual(nodePinBelowFloor(null, floor), null);
});

test('enginesMinimum: lower bound of an engines.node range', () => {
  assert.strictEqual(enginesMinimum('>=18'), '18.0.0');
  assert.strictEqual(enginesMinimum('^20.10.0'), '20.10.0');
  assert.strictEqual(enginesMinimum('>=22.14.0'), '22.14.0');
  assert.strictEqual(enginesMinimum(null), null);
  assert.strictEqual(enginesMinimum('*'), null);
});

test('detectRunPublisher: every advertised command, longest match first', () => {
  assert.deepStrictEqual(detectRunPublisher('npm publish --access public'), { tool: 'npm publish', staged: false });
  assert.deepStrictEqual(detectRunPublisher('npm stage publish'), { tool: 'npm stage publish', staged: true });
  assert.deepStrictEqual(detectRunPublisher('pnpm publish -r'), { tool: 'pnpm publish', staged: false });
  assert.deepStrictEqual(detectRunPublisher('yarn npm publish'), { tool: 'yarn npm publish', staged: false });
  assert.deepStrictEqual(detectRunPublisher('npx semantic-release'), { tool: 'semantic-release', staged: false });
  assert.deepStrictEqual(detectRunPublisher('npx np --no-tests'), { tool: 'np', staged: false });
  assert.deepStrictEqual(detectRunPublisher('npm ci && np'), { tool: 'np', staged: false });
  // np must not fire inside npm/pnpm/other words, and installs are not publishes
  assert.strictEqual(detectRunPublisher('npm ci'), null);
  assert.strictEqual(detectRunPublisher('pnpm install'), null);
  assert.strictEqual(detectRunPublisher('echo np'), null);
});

test('classifyRunsOn: hosted vs self-hosted vs custom labels vs dynamic', () => {
  const node = (value, children = []) => ({ value, children });
  assert.strictEqual(classifyRunsOn(node('ubuntu-latest')).kind, 'github-hosted');
  assert.strictEqual(classifyRunsOn(node('windows-2022')).kind, 'github-hosted');
  assert.strictEqual(classifyRunsOn(node('self-hosted')).kind, 'self-hosted');
  assert.strictEqual(classifyRunsOn(node('[self-hosted, linux]')).kind, 'self-hosted');
  // a custom (non-GitHub-hosted) label counts as ineligible for trusted publishing
  assert.strictEqual(classifyRunsOn(node('my-org-runner')).kind, 'self-hosted');
  assert.strictEqual(classifyRunsOn(node('${{ matrix.os }}')).kind, 'dynamic');
  assert.strictEqual(classifyRunsOn(undefined).kind, 'unknown');
});

test('idTokenGrant: id-token: write and write-all both count', () => {
  const root = parseYamlish('permissions:\n  contents: read\n  id-token: write\n');
  assert.deepStrictEqual(idTokenGrant(root.children[0]), { line: 3, via: 'id-token: write' });
  const all = parseYamlish('permissions: write-all\n');
  assert.deepStrictEqual(idTokenGrant(all.children[0]), { line: 1, via: 'write-all' });
  const none = parseYamlish('permissions:\n  contents: read\n');
  assert.strictEqual(idTokenGrant(none.children[0]), null);
});

// --- fixtures: verdict, exit code, emitted fix ------------------------------

test('publish-token: TOKEN at release.yml:15, cliff + patch + floor + checklist, exit 1', async () => {
  const { status, stdout, stderr } = await run(['publish', '--check', '--path', FIX('publish-token')]);
  assert.strictEqual(status, 1);
  assert.match(stdout, /TOKEN\s+\.github\/workflows\/release\.yml:15\s+npm publish/);
  assert.match(stdout, /January 2027/);
  assert.match(stdout, /\+ permissions:\n\s+\+\s+id-token: write/);
  assert.match(stdout, /-\s+NODE_AUTH_TOKEN: \$\{\{ secrets\.NPM_TOKEN \}\}/);
  assert.match(stdout, /node-version 20 .* below the Node 22\.14\.0 floor/);
  assert.match(stdout, /GitHub organization or user: acme/);
  assert.match(stdout, /repository:\s+widget/);
  assert.match(stdout, /workflow filename:\s+release\.yml/);
  assert.match(stderr, /FAIL: \.github\/workflows\/release\.yml:15 publishes with a long-lived token/);
});

test('publish-trusted: TRUSTED (job id-token grant, no token), exit 0', async () => {
  const { status, stdout, stderr } = await run(['publish', '--check', '--path', FIX('publish-trusted')]);
  assert.strictEqual(status, 0);
  assert.match(stdout, /TRUSTED\s+\.github\/workflows\/release\.yml:19\s+npm publish/);
  assert.match(stdout, /id-token: write granted \(line 10\)/);
  assert.match(stderr, /publish check passed: every classified publish path/);
});

test('publish-staged: STAGED even with a token in the step env, exit 0', async () => {
  const { status, stdout } = await run(['publish', '--check', '--path', FIX('publish-staged')]);
  assert.strictEqual(status, 0);
  assert.match(stdout, /STAGED\s+\.github\/workflows\/release\.yml:12\s+npm stage publish/);
  assert.match(stdout, /npm stage approve <stage-id>/);
});

test('publish-selfhosted: trusted UNAVAILABLE, routed to staged publishing, exit 1', async () => {
  const { status, stdout, stderr } = await run(['publish', '--check', '--path', FIX('publish-selfhosted')]);
  assert.strictEqual(status, 1);
  assert.match(stdout, /trusted publishing is UNAVAILABLE for this job/);
  assert.match(stdout, /Self-hosted runners are not currently supported but are planned for future releases\./);
  assert.match(stdout, /replace `npm publish` with `npm stage publish`/);
  assert.match(stdout, /npm stage approve <stage-id>/);
  // the self-hosted fix routes to staged, so no npmjs.com trusted checklist
  assert.doesNotMatch(stdout, /trusted-publisher settings/);
  assert.match(stderr, /staged publishing .* trusted publishing does not support this runner/);
});

test('publish-oldnode: floor warning names both blocked fixes + engines note, exit 1', async () => {
  const { status, stdout } = await run(['publish', '--check', '--path', FIX('publish-oldnode')]);
  assert.strictEqual(status, 1);
  assert.match(stdout, /NPM_TOKEN in the publish step env/);
  assert.match(stdout, /node-version 18 .* blocks BOTH fixes: trusted publishing needs npm >= 11\.5\.1 and Node >= 22\.14\.0, staged publishing needs npm >= 11\.15\.0/);
  assert.match(stdout, /engines\.node is `>=18`/);
});

test('publish-gitlab: id_tokens with the npm audience reads TRUSTED, exit 0', async () => {
  const { status, stdout } = await run(['publish', '--check', '--path', FIX('publish-gitlab')]);
  assert.strictEqual(status, 0);
  assert.match(stdout, /TRUSTED\s+\.gitlab-ci\.yml:12\s+npm publish/);
  assert.match(stdout, /id_tokens NPM_ID_TOKEN \(aud npm:registry\.npmjs\.org\)/);
});

test('publish-circleci: TOKEN with the NPM_ID_TOKEN migration fix, exit 1', async () => {
  const { status, stdout } = await run(['publish', '--check', '--path', FIX('publish-circleci')]);
  assert.strictEqual(status, 1);
  assert.match(stdout, /TOKEN\s+\.circleci\/config\.yml:11\s+npm publish/);
  assert.match(stdout, /the OIDC token then arrives as `NPM_ID_TOKEN`/);
});

// --- edge cases -------------------------------------------------------------

test('a workflow with both a TOKEN and a TRUSTED path fails on the TOKEN one', () => {
  const dir = mkProj('mixed', {
    '.github/workflows/release.yml': [
      'jobs:',
      '  trusted:',
      '    runs-on: ubuntu-latest',
      '    permissions:',
      '      id-token: write',
      '    steps:',
      '      - run: npm publish',
      '  legacy:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: npm publish',
      '        env:',
      '          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}',
      '',
    ].join('\n'),
  });
  const analysis = analyzePublish(dir);
  assert.deepStrictEqual(analysis.counts, { TRUSTED: 1, STAGED: 0, TOKEN: 1, UNKNOWN: 0 });
  const { ok, failures } = checkPublish(analysis);
  assert.strictEqual(ok, false);
  assert.strictEqual(failures.length, 1);
  assert.match(failures[0].message, /release\.yml:11/);
});

test('reusable workflow jobs (uses:, no steps) are UNKNOWN and never fail', () => {
  const dir = mkProj('reusable', {
    '.github/workflows/release.yml': [
      'jobs:',
      '  release:',
      '    uses: acme/shared/.github/workflows/publish.yml@v1',
      '    secrets: inherit',
      '',
    ].join('\n'),
  });
  const analysis = analyzePublish(dir);
  assert.strictEqual(analysis.paths.length, 1);
  assert.strictEqual(analysis.paths[0].classification, 'UNKNOWN');
  assert.match(analysis.paths[0].reason, /reusable workflow/);
  const { ok, reason } = checkPublish(analysis);
  assert.strictEqual(ok, true);
  assert.match(reason, /UNKNOWN never fails/);
});

test('permissions: write-all counts as granting id-token', () => {
  const dir = mkProj('writeall', {
    '.github/workflows/release.yml': [
      'permissions: write-all',
      'jobs:',
      '  release:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: npm publish',
      '',
    ].join('\n'),
  });
  const analysis = analyzePublish(dir);
  assert.strictEqual(analysis.paths[0].classification, 'TRUSTED');
  assert.match(analysis.paths[0].reason, /write-all granted/);
});

test('a job-level permissions block REPLACES the workflow grant (GitHub semantics)', () => {
  const dir = mkProj('jobperm', {
    '.github/workflows/release.yml': [
      'permissions:',
      '  id-token: write',
      'jobs:',
      '  release:',
      '    runs-on: ubuntu-latest',
      '    permissions:',
      '      contents: read',
      '    steps:',
      '      - run: npm publish',
      '',
    ].join('\n'),
  });
  // workflow grants id-token, job overrides WITHOUT it → no grant, no token → UNKNOWN
  assert.strictEqual(analyzePublish(dir).paths[0].classification, 'UNKNOWN');
});

test('an .npmrc write containing _authToken is a TOKEN path', () => {
  const dir = mkProj('npmrcwrite', {
    '.github/workflows/release.yml': [
      'jobs:',
      '  release:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          echo "//registry.npmjs.org/:_authToken=${NPM_SECRET}" > .npmrc',
      '          npm publish',
      '',
    ].join('\n'),
  });
  const p = analyzePublish(dir).paths[0];
  assert.strictEqual(p.classification, 'TOKEN');
  assert.strictEqual(p.line, 7); // the `npm publish` line inside the block scalar
  assert.match(p.reason, /_authToken/);
});

test('no publish step at all passes with a one-line reason, like allow --ci-check', async () => {
  const dir = mkProj('nopublish', {
    '.github/workflows/ci.yml': 'jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n      - run: npm test\n',
  });
  const { status, stdout, stderr } = await run(['publish', '--check', '--path', dir]);
  assert.strictEqual(status, 0);
  assert.match(stdout, /publish paths \(0\)/);
  assert.match(stderr, /publish check passed: no publish steps found in CI configs/);
});

// --- output surfaces --------------------------------------------------------

test('--json emits cliff + both floors + classified paths', async () => {
  const { status, stdout } = await run(['publish', '--json', '--path', FIX('publish-token')]);
  assert.strictEqual(status, 0); // no --check → report only
  const out = JSON.parse(stdout);
  assert.strictEqual(out.cliff.date, PUBLISH.cliff.date);
  assert.deepStrictEqual(out.floors, {
    trusted: { npm: '11.5.1', node: '22.14.0' },
    staged: { npm: '11.15.0', node: '22.14.0' },
  });
  assert.deepStrictEqual(out.counts, { TRUSTED: 0, STAGED: 0, TOKEN: 1, UNKNOWN: 0 });
  const p = out.paths[0];
  assert.strictEqual(p.classification, 'TOKEN');
  assert.strictEqual(p.file, '.github/workflows/release.yml');
  assert.strictEqual(p.line, 15);
  assert.strictEqual(p.nodeVersion, '20');
  assert.strictEqual(p.nodeBelowFloor, true);
  assert.deepStrictEqual(out.repo, { owner: 'acme', repo: 'widget' });
});

test('--sarif writes rule publish-token-cliff anchored to the workflow line', async () => {
  const file = path.join(tmp, 'publish.sarif');
  const { status } = await run(['publish', '--sarif', file, '--path', FIX('publish-token')]);
  assert.strictEqual(status, 0);
  const sarif = JSON.parse(fs.readFileSync(file, 'utf8'));
  const run0 = sarif.runs[0];
  assert.ok(run0.tool.driver.rules.some((r) => r.id === 'publish-token-cliff'));
  const result = run0.results.find((r) => r.ruleId === 'publish-token-cliff');
  assert.ok(result, 'expected a publish-token-cliff result');
  assert.strictEqual(result.level, 'error');
  const loc = result.locations[0].physicalLocation;
  assert.strictEqual(loc.artifactLocation.uri, '.github/workflows/release.yml');
  assert.strictEqual(loc.region.startLine, 15);
});

test('publishFindings: only TOKEN paths become findings', () => {
  const trusted = analyzePublish(FIX('publish-trusted'));
  assert.deepStrictEqual(publishFindings(trusted), []);
  const token = publishFindings(analyzePublish(FIX('publish-token')));
  assert.strictEqual(token.length, 1);
  assert.strictEqual(token[0].id, 'publish-token-cliff');
  assert.strictEqual(token[0].fingerprint, 'publish-token-cliff:.github/workflows/release.yml:15');
});

// --- doctor + Action --------------------------------------------------------

test('doctor: publish-readiness section warns on TOKEN paths and reports the mix', async () => {
  const { stdout } = await run(['doctor', '--json', '--no-live', '--path', FIX('publish-token')]);
  const report = JSON.parse(stdout);
  assert.deepStrictEqual(report.publish.counts, { TRUSTED: 0, STAGED: 0, TOKEN: 1, UNKNOWN: 0 });
  const check = report.checks.find((c) => c.name === 'publish readiness');
  assert.strictEqual(check.status, 'warn');
  assert.match(check.detail, /January 2027/);
  const floor = report.checks.find((c) => c.name === 'publish node floor');
  assert.match(floor.detail, /node-version 20/);
});

test('action publish-check: ::error + ❌ summary + SARIF merge + exit 1 on TOKEN', async () => {
  const summary = path.join(tmp, 'summary.md');
  fs.writeFileSync(summary, '');
  const sarifFile = path.join(tmp, 'merged.sarif');
  // seed the SARIF the audit step would have written
  const { buildSarif } = require('../src/reporter');
  fs.writeFileSync(sarifFile, JSON.stringify(buildSarif([], { lockPath: 'package-lock.json', lockText: '' }), null, 2));
  const { status, stdout } = await run(['publish-check'], {
    INPUT_PATH: FIX('publish-token'),
    INPUT_SARIF_FILE: sarifFile,
    GITHUB_STEP_SUMMARY: summary,
  }, ACTION);
  assert.strictEqual(status, 1);
  assert.match(stdout, /::error::\.github\/workflows\/release\.yml:15 publishes with a long-lived token/);
  assert.match(fs.readFileSync(summary, 'utf8'), /## ❌ npm token-cliff publish check/);
  const merged = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
  assert.ok(merged.runs[0].results.some((r) => r.ruleId === 'publish-token-cliff'));
});

test('action publish-check: passes with ✅ summary when the path is trusted', async () => {
  const summary = path.join(tmp, 'summary-ok.md');
  fs.writeFileSync(summary, '');
  const { status, stdout } = await run(['publish-check'], {
    INPUT_PATH: FIX('publish-trusted'),
    GITHUB_STEP_SUMMARY: summary,
  }, ACTION);
  assert.strictEqual(status, 0);
  assert.match(stdout, /npm token-cliff publish check passed/);
  assert.match(fs.readFileSync(summary, 'utf8'), /## ✅ npm token-cliff publish check/);
});
