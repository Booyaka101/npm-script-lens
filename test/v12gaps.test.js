'use strict';
// npm v12 approve-scripts gap detectors (npm/cli#9562, npm/cli#9463) against
// the two committed fixtures and a mock registry. src modules are required
// lazily so NPM_SCRIPT_LENS_REGISTRY (set once the mock server has a port) is
// captured correctly at module load.
const http = require('node:http');
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const OPT_FIXTURE = path.join(ROOT, 'fixtures', 'v12-optional-gap');
const EGLOBAL_FIXTURE = path.join(ROOT, 'fixtures', 'v12-eglobal');
let server, base, tmp;
const requests = [];

const DOCS = {
  '/gap-opt/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node x.js' } },
  '/covered-opt/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node x.js' } },
  '/clean-opt/1.0.0': { version: '1.0.0', scripts: {} },
  '/toolg/latest': { version: '2.0.0', scripts: { postinstall: 'node setup.js' } },
  '/toolg/2.0.0': { version: '2.0.0', scripts: { postinstall: 'node setup.js' } },
  '/cleang/latest': { version: '1.0.0', scripts: {} },
  '/gypg/latest': { version: '1.0.0', scripts: {}, hasInstallScript: true },
};

function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd: ROOT,
      timeout: 60000,
      env: { ...process.env, NPM_SCRIPT_LENS_REGISTRY: base },
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdin.end();
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}

before(async () => {
  server = http.createServer((req, res) => {
    requests.push(req.url);
    const doc = DOCS[req.url];
    if (!doc) return res.writeHead(404).end('{}');
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(doc));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
  process.env.NPM_SCRIPT_LENS_REGISTRY = base;
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-v12-'));
});

after(() => {
  server.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('checkOptionalGap: flags uncovered optional deps with install scripts (#9562)', async () => {
  const { checkOptionalGap } = require('../src/v12gaps');
  const findings = await checkOptionalGap(OPT_FIXTURE);
  assert.deepStrictEqual(findings.map((f) => f.package), ['gap-opt', 'ghost-opt']);
  const gap = findings[0];
  assert.strictEqual(gap.id, 'v12-optional-gap');
  assert.strictEqual(gap.severity, 'warn');
  assert.strictEqual(gap.version, '1.0.0');
  assert.strictEqual(gap.script, 'postinstall');
  assert.ok(gap.fix.includes('"allowScripts": { "gap-opt": true }'), 'fix names the package');
  assert.ok(gap.fix.includes('npm/cli#9562'), 'fix cites the upstream issue');
  // registry unreachable for ghost-opt: the lockfile's hasInstallScript still warns
  assert.ok(findings[1].script.includes('registry metadata unavailable'));
  // covered-opt is in allowScripts and clean-opt has no install script:
  // neither produces a finding nor a registry request
  assert.ok(!requests.some((u) => u.startsWith('/covered-opt')), 'covered package not fetched');
  assert.ok(!requests.some((u) => u.startsWith('/clean-opt')), 'scriptless optional dep not fetched');
  assert.ok(!requests.some((u) => u.startsWith('/plainpkg')), 'non-optional package is not this check');
});

test('checkOptionalGap: bare-name allowScripts entries count as covered', async () => {
  const { checkOptionalGap } = require('../src/v12gaps');
  const dir = path.join(tmp, 'bare-name');
  fs.mkdirSync(dir, { recursive: true });
  fs.copyFileSync(path.join(OPT_FIXTURE, 'package-lock.json'), path.join(dir, 'package-lock.json'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'x', version: '1.0.0', allowScripts: { 'gap-opt': true, 'covered-opt@1.0.0': false, 'ghost-opt@1.0.0': true },
  }));
  const findings = await checkOptionalGap(dir);
  assert.deepStrictEqual(findings, [], 'name and name@version keys, true or false, all count as decisions');
});

test('checkEglobal: flags scripted global installs in workflows (#9463)', async () => {
  const { checkEglobal } = require('../src/v12gaps');
  const findings = await checkEglobal(EGLOBAL_FIXTURE);
  assert.deepStrictEqual(findings.map((f) => [f.package, f.line]),
    [['toolg', 9], ['gypg', 14], ['toolg', 16]], 'anchored to the run lines');
  assert.strictEqual(findings[1].script, 'install (implicit node-gyp rebuild)',
    'hasInstallScript with no explicit lifecycle script is the implicit gyp build');
  for (const f of [findings[0], findings[2]]) {
    assert.strictEqual(f.id, 'v12-eglobal-risk');
    assert.strictEqual(f.severity, 'warn');
    assert.strictEqual(f.file, '.github/workflows/release.yml');
    assert.strictEqual(f.script, 'postinstall');
    assert.ok(f.fix.includes('--allow-scripts=toolg'), 'fix shows the working command');
    assert.ok(f.fix.includes('npm/cli#9463'), 'fix cites the upstream issue');
  }
  // cleang has no scripts, guardedg already passes --allow-scripts, unknowng
  // is not on the registry, express line is not global
  assert.ok(!requests.some((u) => u.startsWith('/guardedg')), 'guarded install not fetched');
  assert.ok(!requests.some((u) => u.startsWith('/express')), 'non-global install ignored');
});

test('globalNpmInstalls: line parsing edge cases', () => {
  const { globalNpmInstalls, splitSpec } = require('../src/v12gaps');
  assert.deepStrictEqual(globalNpmInstalls('npm install express'), [], 'not global');
  assert.deepStrictEqual(globalNpmInstalls('  - run: npm i -g foo@1.2.3')[0].specs, ['foo@1.2.3']);
  assert.deepStrictEqual(globalNpmInstalls('npm install --global @scope/tool')[0].specs, ['@scope/tool']);
  assert.deepStrictEqual(globalNpmInstalls('npm install --location=global tool')[0].specs, ['tool']);
  assert.deepStrictEqual(globalNpmInstalls('npm install --location global tool')[0].specs, ['tool']);
  assert.strictEqual(globalNpmInstalls('npm install -g --allow-scripts=x x')[0].allowed, true);
  assert.strictEqual(globalNpmInstalls('npm install -g --ignore-scripts x')[0].allowed, true);
  const multi = globalNpmInstalls('npm ci && npm i -g a b --registry https://r.example && echo done');
  assert.deepStrictEqual(multi[0].specs, ['a', 'b'], 'shell separators end the command; --registry value skipped');
  assert.deepStrictEqual(globalNpmInstalls('npm i -g https://x.example/t.tgz ./local.tgz'), [{ specs: [], global: true, allowed: false }], 'URLs and paths have no registry metadata');
  assert.deepStrictEqual(splitSpec('@scope/tool@1.2.3'), { name: '@scope/tool', version: '1.2.3' });
  assert.deepStrictEqual(splitSpec('@scope/tool'), { name: '@scope/tool', version: null });
});

test('cli e2e: --check-v12-gaps --json emits findings only', async () => {
  const { status, stdout } = await runCli(['audit', '--check-v12-gaps', '--json', '--path', OPT_FIXTURE]);
  assert.strictEqual(status, 0, 'warn severity never fails the run');
  const parsed = JSON.parse(stdout);
  assert.deepStrictEqual(Object.keys(parsed), ['findings']);
  assert.deepStrictEqual(parsed.findings.map((f) => f.package), ['gap-opt', 'ghost-opt']);
});

test('cli e2e: --check-v12-gaps markdown report and SARIF integration', async () => {
  const sarifOut = path.join(tmp, 'v12.sarif');
  const { status, stdout } = await runCli(['audit', '--check-v12-gaps', '--sarif', sarifOut, '--path', EGLOBAL_FIXTURE]);
  assert.strictEqual(status, 0);
  assert.ok(stdout.includes('# npm v12 approve-scripts gap check'));
  assert.ok(stdout.includes('`v12-eglobal-risk`'));
  assert.ok(stdout.includes('`.github/workflows/release.yml:9`'));
  const sarif = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
  const run = sarif.runs[0];
  const ruleIds = run.tool.driver.rules.map((r) => r.id);
  assert.ok(ruleIds.includes('v12-optional-gap') && ruleIds.includes('v12-eglobal-risk'));
  assert.strictEqual(run.results.length, 3);
  for (const r of run.results) {
    assert.strictEqual(r.ruleId, 'v12-eglobal-risk');
    assert.strictEqual(r.level, 'warning');
    assert.strictEqual(r.locations[0].physicalLocation.artifactLocation.uri, '.github/workflows/release.yml');
  }
});

test('action e2e: v12-gaps mode writes summary and merges into existing SARIF', async () => {
  const projDir = path.join(tmp, 'action-proj');
  fs.mkdirSync(projDir, { recursive: true });
  for (const f of ['package.json', 'package-lock.json']) {
    fs.copyFileSync(path.join(EGLOBAL_FIXTURE, f), path.join(projDir, f));
  }
  fs.mkdirSync(path.join(projDir, '.github', 'workflows'), { recursive: true });
  fs.copyFileSync(path.join(EGLOBAL_FIXTURE, '.github', 'workflows', 'release.yml'),
    path.join(projDir, '.github', 'workflows', 'release.yml'));
  // a SARIF file "written by the audit step" for the gap step to merge into
  const sarifFile = path.join(projDir, 'lens.sarif');
  fs.writeFileSync(sarifFile, JSON.stringify({
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'npm-script-lens', rules: [] } }, results: [] }],
  }));
  const summaryFile = path.join(projDir, 'summary.md');
  fs.writeFileSync(summaryFile, '');
  const { status, stdout } = await new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(ROOT, 'src', 'action.js'), 'v12-gaps'], {
      cwd: projDir,
      timeout: 60000,
      env: {
        ...process.env,
        NPM_SCRIPT_LENS_REGISTRY: base,
        INPUT_PATH: projDir,
        INPUT_SARIF_FILE: sarifFile,
        GITHUB_STEP_SUMMARY: summaryFile,
      },
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('exit', (code) => resolve({ status: code, stdout: out }));
  });
  assert.strictEqual(status, 0, `gap findings warn, they do not fail the job: ${stdout}`);
  assert.ok(stdout.includes('::warning::v12-eglobal-risk: toolg (.github/workflows/release.yml:9)'));
  assert.ok(fs.readFileSync(summaryFile, 'utf8').includes('# npm v12 approve-scripts gap check'));
  const merged = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
  assert.strictEqual(merged.runs[0].results.length, 3, 'findings merged into the audit SARIF');
  assert.ok(merged.runs[0].tool.driver.rules.some((r) => r.id === 'v12-eglobal-risk'));
});
