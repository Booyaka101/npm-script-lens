'use strict';
// The cooldown a package manager applies on every LOCAL install, reconciled
// against the --cooldown its CI enforces. Four managers, four units, so the
// two things worth pinning hard are the classification (never a false
// UNIT-SUSPECT, never a missed one) and the write (byte-identical except for
// the managed key).
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const FIX = (name) => path.join(ROOT, 'fixtures', name);

const {
  COOLDOWN, MANAGERS, parseYarnDuration, yarnDuration, excludeForm, cooldownValue, readBunfig,
} = require('../src/pm-contract');
const {
  readCooldownConfig, classifyCooldown, findEnforcedCooldown, unitSuspicion,
  resolveYarnVersion, diffExclude, cooldownFindings, fmtHours, STATUS, renderCooldownConfig,
} = require('../src/cooldown');

// Fixtures are copied out before any --write test: the monorepo cases also
// need a parent with no lockfile above them, which nothing inside this repo
// can offer (findProjects searches upward to the filesystem root).
function copyFixture(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-cd-'));
  fs.cpSync(FIX(name), path.join(dir, name), { recursive: true });
  return path.join(dir, name);
}

function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd: ROOT, timeout: 60000 });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}

const statusIds = (report) => report.statuses.map((s) => s.id);
const read = (dir, file) => fs.readFileSync(path.join(dir, file), 'utf8');

// --- the contract table ----------------------------------------------------

test('COOLDOWN carries one row per manager with its real key, file and unit', () => {
  assert.deepStrictEqual(
    Object.fromEntries(Object.values(COOLDOWN).map((r) => [r.id, [r.file, r.key, r.excludeKey, r.unit]])),
    {
      npm: ['.npmrc', 'min-release-age', 'min-release-age-exclude', 'days'],
      pnpm: ['pnpm-workspace.yaml', 'minimumReleaseAge', 'minimumReleaseAgeExclude', 'minutes'],
      yarn: ['.yarnrc.yml', 'npmMinimalAgeGate', 'npmPreapprovedPackages', 'minutes'],
      bun: ['bunfig.toml', 'minimumReleaseAge', 'minimumReleaseAgeExcludes', 'seconds'],
    });
  assert.strictEqual(COOLDOWN.pnpm.default, 1440, 'pnpm 11 defaults to 1440 minutes');
  assert.strictEqual(COOLDOWN.yarn.default, '1d', "yarn's own default is written as a duration string");
  assert.strictEqual(COOLDOWN.bun.section, 'install', 'bun keys it under [install]');
});

test('72 hours renders in each manager\'s own unit and notation', () => {
  assert.strictEqual(cooldownValue(COOLDOWN.npm, 72), '3');
  assert.strictEqual(cooldownValue(COOLDOWN.pnpm, 72), '4320');
  assert.strictEqual(cooldownValue(COOLDOWN.yarn, 72), '3d');
  assert.strictEqual(cooldownValue(COOLDOWN.bun, 72), '259200', "bun's own documented 3-day example");
  // a Yarn that cannot parse a duration string gets the bare minute count
  assert.strictEqual(cooldownValue(COOLDOWN.yarn, 72, { duration: false }), '4320');
});

test('yarnDuration picks the largest unit that divides evenly', () => {
  assert.strictEqual(yarnDuration(168), '1w');
  assert.strictEqual(yarnDuration(72), '3d');
  assert.strictEqual(yarnDuration(36), '36h');
  assert.strictEqual(yarnDuration(1.5), '90m');
});

test("parseYarnDuration follows Yarn's own grammar and rejects the rest", () => {
  // miscUtils.parseDuration: /^(\d*\.?\d+)(ms|s|m|h|d|w)?$/, unit MINUTES
  assert.deepStrictEqual(parseYarnDuration('7d'), { minutes: 10080, bare: false });
  assert.deepStrictEqual(parseYarnDuration('4320'), { minutes: 4320, bare: true });
  assert.strictEqual(parseYarnDuration('1w').minutes, 10080);
  assert.strictEqual(parseYarnDuration('90s').minutes, 1.5);
  assert.strictEqual(parseYarnDuration('7 days'), null, 'Yarn itself throws on this');
  assert.strictEqual(parseYarnDuration('7y'), null);
});

test('excludeForm separates names, globs and version descriptors', () => {
  assert.strictEqual(excludeForm('left-pad'), 'name');
  assert.strictEqual(excludeForm('@scope/pkg'), 'name', 'a scoped name is still just a name');
  assert.strictEqual(excludeForm('@myorg/*'), 'glob');
  assert.strictEqual(excludeForm('pkg@1.2.3'), 'descriptor');
  assert.strictEqual(excludeForm('@scope/pkg@1'), 'descriptor');
  assert.strictEqual(excludeForm('a@1 || a@2'), 'descriptor');
});

// --- the unit heuristic ----------------------------------------------------

test('UNIT-SUSPECT fires only when another unit reads as a sane cooldown', () => {
  // 3 pnpm minutes gates nothing; 3 DAYS is what the author meant
  assert.deepStrictEqual(unitSuspicion(COOLDOWN.pnpm, 3).likely, { unit: 'days', hours: 72 });
  // 4320 npm DAYS is 11.8 years; 4320 minutes is the pnpm idiom for 3 days
  assert.deepStrictEqual(unitSuspicion(COOLDOWN.npm, 4320).likely, { unit: 'minutes', hours: 72 });
  assert.deepStrictEqual(unitSuspicion(COOLDOWN.bun, 3).likely, { unit: 'days', hours: 72 });
  // values already in the right unit are never second-guessed
  assert.strictEqual(unitSuspicion(COOLDOWN.pnpm, 1440), null);
  assert.strictEqual(unitSuspicion(COOLDOWN.bun, 259200), null);
  assert.strictEqual(unitSuspicion(COOLDOWN.npm, 3), null);
  // and nor is a genuinely ambiguous one: 72 pnpm minutes is 1.2h, a small but
  // deliberate gate, so guessing "they meant hours" would be a false positive
  assert.strictEqual(unitSuspicion(COOLDOWN.pnpm, 72), null);
  // 0 reads as 0 in every unit, so there is nothing to suspect
  assert.strictEqual(unitSuspicion(COOLDOWN.pnpm, 0), null);
});

test('fmtHours stays readable at both extremes', () => {
  assert.strictEqual(fmtHours(72), '72h');
  assert.strictEqual(fmtHours(0.05), '0.05h');
  assert.strictEqual(fmtHours(1 / 1200), '3s');
  assert.strictEqual(fmtHours(103680), '4320d');
  assert.strictEqual(fmtHours(null), 'unknown');
});

// --- reading each manager's real config ------------------------------------

test('npm: reads min-release-age and the repeatable exclude key', () => {
  const cfg = MANAGERS.npm.readCooldown(FIX('cooldown-npm-ok'));
  assert.strictEqual(cfg.raw, '3');
  assert.strictEqual(cfg.hours, 72, '3 DAYS is 72 hours');
  assert.deepStrictEqual(cfg.exclude, ['urgent-fix']);
  assert.strictEqual(cfg.line, 3, 'anchored to the real .npmrc line');
});

test('pnpm: reads the scalar out of pnpm-workspace.yaml', () => {
  const cfg = MANAGERS.pnpm.readCooldown(FIX('cooldown-pnpm-suspect'));
  assert.strictEqual(cfg.raw, '3');
  assert.strictEqual(cfg.hours, 0.05, '3 MINUTES');
  assert.strictEqual(cfg.line, 5);
});

test('yarn: reads a duration string, a bare number, and the per-scope gate', () => {
  const cfg = MANAGERS.yarn.readCooldown(FIX('cooldown-yarn-stale'));
  assert.strictEqual(cfg.raw, '7d');
  assert.strictEqual(cfg.hours, 168);
  assert.strictEqual(cfg.bare, false, 'a duration string, not a bare number');
  // berry#7156, Yarn 4.17.0: a gate inside an npmScopes entry
  assert.deepStrictEqual(cfg.scopes.map((s) => [s.scope, s.raw, s.hours]), [['internal', '0', 0]]);
  const current = MANAGERS.yarn.readCooldown(FIX('cooldown-yarn-ok'));
  assert.deepStrictEqual([current.raw, current.hours, current.bare], ['3d', 72, false]);
});

test('bun: reads [install] and reports an unreadable file as partial, not a crash', () => {
  const missing = MANAGERS.bun.readCooldown(FIX('cooldown-bun-missing'));
  assert.deepStrictEqual([missing.exists, missing.raw, missing.partial], [false, null, null]);

  const broken = MANAGERS.bun.readCooldown(FIX('cooldown-bun-broken'));
  assert.match(broken.partial, /bunfig\.toml:4/, 'the multi-line array cannot be round-tripped');
  assert.strictEqual(broken.raw, '259200', 'the key it COULD read is still reported');
});

test('bunfig: a [[section]] header closes [install] rather than reading as junk', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-toml-'));
  fs.writeFileSync(path.join(dir, 'bunfig.toml'),
    '[install]\nminimumReleaseAge = 259200\n\n[[install.scopes]]\nname = "internal"\n');
  const cfg = readBunfig(dir);
  assert.strictEqual(cfg.partial, null, 'TOML array-of-tables is valid, not a parse failure');
  assert.strictEqual(cfg.entries.minimumReleaseAge.raw, '259200');
  assert.strictEqual(cfg.entries.name, undefined, 'keys after the header are not [install] keys');
});

test('a config file that does not exist reads as absent, never throws', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-none-'));
  for (const id of ['npm', 'pnpm', 'yarn', 'bun']) {
    const cfg = MANAGERS[id].readCooldown(dir);
    assert.deepStrictEqual([cfg.exists, cfg.raw, cfg.hours, cfg.exclude], [false, null, null, []], id);
  }
});

// --- what CI enforces ------------------------------------------------------

test('the enforced threshold comes from the CI configs, strictest site winning', () => {
  const found = findEnforcedCooldown(FIX('cooldown-npm-ok'));
  assert.strictEqual(found.hours, 72);
  assert.deepStrictEqual(found.allow, ['urgent-fix']);
  assert.strictEqual(found.file, '.github/workflows/guards.yml');
});

test('a bare --cooldown in CI means the CLI default', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-ci-'));
  fs.mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.github', 'workflows', 'a.yml'),
    'jobs:\n  x:\n    steps:\n      - run: npm-script-lens audit --cooldown\n');
  assert.strictEqual(findEnforcedCooldown(dir).hours, 72);
  // --cooldown-allow must not be mistaken for --cooldown
  fs.writeFileSync(path.join(dir, '.github', 'workflows', 'a.yml'),
    'jobs:\n  x:\n    steps:\n      - run: npm-script-lens audit --cooldown-allow only-this\n');
  assert.strictEqual(findEnforcedCooldown(dir), null, 'an allow list alone enforces nothing');
});

test('a commented-out --cooldown enforces nothing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-ci2-'));
  fs.mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.github', 'workflows', 'a.yml'),
    'jobs:\n  x:\n    steps:\n      # - run: npm-script-lens audit --cooldown 96\n      - run: npm test\n');
  assert.strictEqual(findEnforcedCooldown(dir), null);
});

// --- classification --------------------------------------------------------

test('MISSING fires only while CI actually enforces something', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-miss-'));
  const cfg = MANAGERS.pnpm.readCooldown(dir);
  assert.deepStrictEqual(statusIds(classifyCooldown(cfg, { enforced: null })), [],
    'nothing configured and nothing enforced is not a finding');
  const enforced = { hours: 72, allow: [], file: 'ci.yml', line: 1 };
  assert.deepStrictEqual(statusIds(classifyCooldown(cfg, { enforced })), [STATUS.MISSING]);
});

test('DRIFT names the enforcing file, and an exempt-list mismatch is its own finding', () => {
  const cfg = MANAGERS.pnpm.readCooldown(FIX('cooldown-pnpm-drift'));
  const report = classifyCooldown(cfg, { enforced: { hours: 72, allow: ['urgent-fix'], file: 'ci.yml', line: 3, source: 'ci' } });
  assert.deepStrictEqual(statusIds(report), [STATUS.DRIFT, STATUS.DRIFT]);
  assert.match(report.statuses[0].message, /configured 24h < enforced 72h \(--cooldown in ci\.yml\)/);
  assert.match(report.statuses[1].message, /@myorg\/\* exempt locally but not in CI/);
  assert.match(report.statuses[1].message, /urgent-fix exempt in CI but not locally/);
});

test('a value already in the right unit is OK, with its hours spelled out', () => {
  const report = readCooldownConfig(path.join(FIX('cooldown-npm-ok'), 'package-lock.json'), 'npm');
  assert.deepStrictEqual(statusIds(report), []);
  assert.strictEqual(report.ok, true);
  assert.strictEqual(report.hours, 72);
});

test('an exemption the manager cannot express is reported, never counted as drift', () => {
  const cfg = MANAGERS.bun.readCooldown(FIX('cooldown-bun-missing'));
  const report = classifyCooldown(cfg, { enforced: { hours: 48, allow: [], file: 'ci.yml', line: 1, source: 'ci' }, allow: ['pkg@1.2.3'] });
  assert.ok(statusIds(report).includes('UNSUPPORTED'));
  assert.ok(!report.statuses.some((s) => s.id === STATUS.DRIFT),
    'bun takes names only, so a descriptor it could never hold is not a disagreement');
});

test('diffExclude is silent when both lists are empty or equal', () => {
  assert.strictEqual(diffExclude([], []), null);
  assert.strictEqual(diffExclude(['a', 'b'], ['b', 'a']), null, 'order is not drift');
  assert.match(diffExclude(['a'], []), /a exempt locally but not in CI/);
});

// --- the Yarn silent-ignore, version-bounded -------------------------------

test('an old Yarn silently gating minutes is UNIT-SUSPECT against its resolved version', () => {
  // Before Yarn 4.11.0 the setting was SettingsType.NUMBER, so parseInt('7d')
  // is 7 and the gate is seven MINUTES. That is yarnpkg/berry#6991.
  const stale = readCooldownConfig(path.join(FIX('cooldown-yarn-stale'), 'yarn.lock'), 'yarn');
  assert.deepStrictEqual(statusIds(stale), [STATUS.SUSPECT]);
  assert.match(stale.statuses[0].message, /gates 7 minutes on Yarn 4\.10\.2, not 168h/);
  assert.match(stale.statuses[0].detail, /yarnpkg\/berry#6991/);

  // On a Yarn that parses durations the same file is exact, never flagged
  const ok = readCooldownConfig(path.join(FIX('cooldown-yarn-ok'), 'yarn.lock'), 'yarn');
  assert.deepStrictEqual(statusIds(ok), [], 'duration strings are precise on current Yarn');
});

test('with no pinned Yarn the duration string is reported, not condemned', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-yv-'));
  fs.writeFileSync(path.join(dir, '.yarnrc.yml'), 'npmMinimalAgeGate: 3d\n');
  fs.writeFileSync(path.join(dir, 'yarn.lock'), '__metadata:\n  version: 8\n');
  assert.strictEqual(resolveYarnVersion(dir), null);
  const report = classifyCooldown(MANAGERS.yarn.readCooldown(dir), { enforced: null });
  assert.deepStrictEqual(statusIds(report), [STATUS.OK], 'reported, but not a failure');
  assert.strictEqual(report.ok, true);
});

test('resolveYarnVersion reads packageManager first, then yarnPath', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-yp-'));
  fs.writeFileSync(path.join(dir, '.yarnrc.yml'), 'yarnPath: .yarn/releases/yarn-4.9.1.cjs\n');
  assert.deepStrictEqual(resolveYarnVersion(dir), { version: '4.9.1', via: 'yarnPath in .yarnrc.yml' });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"packageManager":"yarn@4.18.0"}');
  assert.strictEqual(resolveYarnVersion(dir).version, '4.18.0', 'packageManager wins');
});

test('a value Yarn itself cannot parse is surfaced, not silently converted', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-ybad-'));
  fs.writeFileSync(path.join(dir, '.yarnrc.yml'), 'npmMinimalAgeGate: 7 days\n');
  const cfg = MANAGERS.yarn.readCooldown(dir);
  assert.strictEqual(cfg.unparseable, '7 days');
  assert.strictEqual(cfg.hours, null);
  assert.deepStrictEqual(statusIds(classifyCooldown(cfg, {})), [STATUS.SUSPECT]);
});

// --- writing ---------------------------------------------------------------

const MANAGED = {
  'cooldown-pnpm-suspect': ['pnpm-workspace.yaml', 'minimumReleaseAge'],
  'cooldown-npm-suspect': ['.npmrc', 'min-release-age'],
  'cooldown-yarn-stale': ['.yarnrc.yml', 'npmMinimalAgeGate'],
  'cooldown-pnpm-drift': ['pnpm-workspace.yaml', 'minimumReleaseAge'],
};

for (const [fixture, [file, key]] of Object.entries(MANAGED)) {
  test(`--write on ${fixture} changes only the ${key} line`, async () => {
    const dir = copyFixture(fixture);
    const before = read(dir, file).split(/(?<=\n)/);
    const res = await runCli(['cooldown', '--path', dir, '--write', '--cooldown', '72']);
    assert.strictEqual(res.status, 0, res.stderr);
    const after = read(dir, file).split(/(?<=\n)/);
    assert.strictEqual(after.length, before.length, 'no line added or removed');
    const changed = before.map((l, i) => (l === after[i] ? null : i)).filter((i) => i !== null);
    assert.strictEqual(changed.length, 1, `exactly one line changed, got ${JSON.stringify(changed.map((i) => [before[i], after[i]]))}`);
    assert.ok(before[changed[0]].includes(key) && after[changed[0]].includes(key));
  });
}

test('--write then --check exits 0 on every fixture it can fix', async () => {
  for (const fixture of Object.keys(MANAGED).concat('cooldown-bun-missing')) {
    const dir = copyFixture(fixture);
    assert.strictEqual((await runCli(['cooldown', '--path', dir, '--write', '--cooldown', '72'])).status, 0, fixture);
    const check = await runCli(['cooldown', '--path', dir, '--check', '--cooldown', '72']);
    assert.strictEqual(check.status, 0, `${fixture}: ${check.stdout}${check.stderr}`);
  }
});

test('--write never touches a per-scope gate (berry#7156)', async () => {
  const dir = copyFixture('cooldown-yarn-stale');
  await runCli(['cooldown', '--path', dir, '--write', '--cooldown', '72']);
  const text = read(dir, '.yarnrc.yml');
  assert.match(text, /npmScopes:\n {2}internal:\n {4}npmRegistryServer: "https:\/\/npm\.internal\.example\/"\n {4}npmMinimalAgeGate: 0\n/);
  assert.match(text, /^npmMinimalAgeGate: 4320$/m, 'a Yarn below 4.11.0 gets bare minutes, not 3d');
});

test('--write preserves CRLF and a file with no trailing newline', async () => {
  const dir = copyFixture('cooldown-pnpm-suspect');
  fs.writeFileSync(path.join(dir, 'pnpm-workspace.yaml'), '# win\r\npackages:\r\n  - "p/*"\r\nminimumReleaseAge: 3');
  await runCli(['cooldown', '--path', dir, '--write', '--cooldown', '72']);
  assert.strictEqual(read(dir, 'pnpm-workspace.yaml'), '# win\r\npackages:\r\n  - "p/*"\r\nminimumReleaseAge: 4320');
});

test('--write refuses a bunfig it cannot round-trip, leaving the file untouched', async () => {
  const dir = copyFixture('cooldown-bun-broken');
  const before = read(dir, 'bunfig.toml');
  const res = await runCli(['cooldown', '--path', dir, '--write', '--cooldown', '72']);
  assert.strictEqual(res.status, 2, 'a refused write exits 2, like every other hard error');
  assert.match(res.stderr, /Fix the file by hand/);
  assert.strictEqual(read(dir, 'bunfig.toml'), before, 'byte-identical, no partial write');
});

test('--write creates bunfig.toml with an [install] section when there is none', async () => {
  const dir = copyFixture('cooldown-bun-missing');
  await runCli(['cooldown', '--path', dir, '--write', '--cooldown', '48', '--cooldown-allow', 'urgent-fix']);
  assert.strictEqual(read(dir, 'bunfig.toml'),
    '[install]\nminimumReleaseAge = 172800\nminimumReleaseAgeExcludes = ["urgent-fix"]\n');
});

test('--write skips an exemption the manager cannot express, and says so', async () => {
  const dir = copyFixture('cooldown-bun-missing');
  const res = await runCli(['cooldown', '--path', dir, '--write', '--cooldown', '48',
    '--cooldown-allow', 'urgent-fix', 'pkg@1.2.3']);
  assert.match(res.stderr, /skipped exemption 'pkg@1\.2\.3': bun accepts package names only/);
  assert.ok(!read(dir, 'bunfig.toml').includes('pkg@1.2.3'), 'never write a gate bun would ignore');
});

// --- exit codes and surfaces -----------------------------------------------

const BAD = ['cooldown-npm-suspect', 'cooldown-pnpm-suspect', 'cooldown-pnpm-drift',
  'cooldown-yarn-stale', 'cooldown-bun-missing', 'cooldown-bun-broken'];
const GOOD = ['cooldown-npm-ok', 'cooldown-pnpm-ok', 'cooldown-yarn-ok', 'cooldown-bun-ok'];

test('--check exits 1 on every broken fixture and 0 on every good one', async () => {
  assert.deepStrictEqual([...new Set([...BAD, ...GOOD].map((f) => f.split('-')[1]))].sort(),
    ['bun', 'npm', 'pnpm', 'yarn'], 'every manager has both a passing and a failing fixture');
  for (const f of BAD) {
    assert.strictEqual((await runCli(['cooldown', '--path', FIX(f), '--check'])).status, 1, f);
  }
  for (const f of GOOD) {
    assert.strictEqual((await runCli(['cooldown', '--path', FIX(f), '--check'])).status, 0, f);
  }
});

test('the plain report never changes the exit code, however bad the config', async () => {
  for (const f of BAD) {
    assert.strictEqual((await runCli(['cooldown', '--path', FIX(f)])).status, 0, f);
  }
});

test('no lockfile at the path exits 2, the way audit does', async () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-nolock-'));
  const res = await runCli(['cooldown', '--path', path.join(empty, 'nowhere')]);
  assert.strictEqual(res.status, 2);
  assert.match(res.stderr, /lockfile not found/);
});

test('the worked example: a pnpm 3 against a CI --cooldown 72', async () => {
  const res = await runCli(['cooldown', '--path', FIX('cooldown-pnpm-suspect'), '--check']);
  assert.strictEqual(res.status, 1);
  const lines = res.stdout.split('\n');
  assert.strictEqual(lines[0], 'cooldown config — pnpm (pnpm-workspace.yaml)');
  assert.strictEqual(lines[1], '  UNIT-SUSPECT  minimumReleaseAge: 3  → 3 minutes (pnpm counts MINUTES), not 3 days');
  assert.strictEqual(lines[2], "                pnpm's own default is 1440 (1 day); 3 gates essentially nothing");
  assert.strictEqual(lines[3], '  DRIFT         configured 0.05h < enforced 72h (--cooldown in .github/workflows/ci.yml)');
  assert.ok(lines.includes('  fix:  npm-script-lens cooldown --write --cooldown 72'));
  assert.ok(lines.includes('        writes  minimumReleaseAge: 4320'));
});

test('--json emits the classification, and --sarif anchors to the real config line', async () => {
  const out = await runCli(['cooldown', '--path', FIX('cooldown-pnpm-suspect'), '--json']);
  const json = JSON.parse(out.stdout);
  assert.deepStrictEqual(
    [json.manager, json.file, json.key, json.unit, json.raw, json.hours, json.line, json.ok],
    ['pnpm', 'pnpm-workspace.yaml', 'minimumReleaseAge', 'minutes', '3', 0.05, 5, false]);
  assert.deepStrictEqual(json.statuses.map((s) => s.id), [STATUS.SUSPECT, STATUS.DRIFT]);
  assert.strictEqual(json.enforced.hours, 72);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-sarif-'));
  const file = path.join(dir, 'cooldown.sarif');
  await runCli(['cooldown', '--path', FIX('cooldown-pnpm-suspect'), '--check', '--sarif', file]);
  const sarif = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.strictEqual(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].tool.driver.rules.some((r) => r.id === 'cooldown-config'), 'rule declared');
  const results = sarif.runs[0].results.filter((r) => r.ruleId === 'cooldown-config');
  assert.deepStrictEqual(results.map((r) => r.level), ['error', 'warning'],
    'UNIT-SUSPECT is an error under --check, DRIFT stays a warning');
  for (const r of results) {
    assert.match(r.locations[0].physicalLocation.artifactLocation.uri, /pnpm-workspace\.yaml$/);
    assert.strictEqual(r.locations[0].physicalLocation.region.startLine, 5);
  }
});

test('SARIF findings drop to warning without --check', () => {
  const report = readCooldownConfig(path.join(FIX('cooldown-pnpm-suspect'), 'pnpm-lock.yaml'), 'pnpm');
  assert.deepStrictEqual(cooldownFindings([report]).map((f) => f.level), ['warning', 'warning']);
  assert.deepStrictEqual(cooldownFindings([report], { check: true }).map((f) => f.level), ['error', 'warning']);
});

// --- monorepo --------------------------------------------------------------

test('a monorepo reports per project and fails if any project fails', async () => {
  const dir = copyFixture('cooldown-monorepo');
  const res = await runCli(['cooldown', '--path', dir, '--check']);
  assert.strictEqual(res.status, 1);
  assert.match(res.stdout, /\[packages\/api\]\ncooldown config — npm/);
  assert.match(res.stdout, /\[packages\/web\]\ncooldown config — pnpm/);
  assert.match(res.stdout, /OK {12}min-release-age=3/, 'api meets the root CI threshold');
  assert.match(res.stdout, /DRIFT {9}configured 1h < enforced 72h/, 'web does not');
  assert.match(res.stderr, /FAIL \(DRIFT\) packages\/web/);
});

test('a monorepo --write fixes every project, then --check passes', async () => {
  const dir = copyFixture('cooldown-monorepo');
  assert.strictEqual((await runCli(['cooldown', '--path', dir, '--write'])).status, 0);
  assert.strictEqual((await runCli(['cooldown', '--path', dir, '--check'])).status, 0);
  assert.match(fs.readFileSync(path.join(dir, 'packages', 'web', 'pnpm-workspace.yaml'), 'utf8'),
    /^minimumReleaseAge: 4320$/m, 'the root CI threshold, in pnpm minutes');
});

test('--write refuses the whole monorepo when one target is not writable', async () => {
  const dir = copyFixture('cooldown-monorepo');
  const locked = path.join(dir, 'packages', 'api', '.npmrc');
  const before = fs.readFileSync(locked, 'utf8');
  const web = path.join(dir, 'packages', 'web', 'pnpm-workspace.yaml');
  const webBefore = fs.readFileSync(web, 'utf8');
  fs.chmodSync(locked, 0o444);
  try {
    const res = await runCli(['cooldown', '--path', dir, '--write', '--cooldown', '96']);
    // Windows honours the read-only bit for W_OK on files, POSIX honours the
    // mode. Either way the run must be all-or-nothing.
    if (res.status === 2) {
      assert.match(res.stderr, /is not writable, so nothing was written/);
      assert.strictEqual(fs.readFileSync(web, 'utf8'), webBefore, 'no project was half-written');
    } else {
      assert.strictEqual(res.status, 0, res.stderr);
    }
  } finally {
    fs.chmodSync(locked, 0o644);
    fs.writeFileSync(locked, before);
  }
});

// --- audit --cooldown-config -----------------------------------------------

test('audit --cooldown-config reconciles on stderr and fails the run', async () => {
  const res = await runCli(['audit', '--path', FIX('cooldown-pnpm-suspect'),
    '--cooldown-config', '--offline', '--no-trust', '--no-cache']);
  assert.strictEqual(res.status, 1);
  assert.match(res.stderr, /cooldown config — pnpm \(pnpm-workspace\.yaml\)/);
  assert.match(res.stderr, /UNIT-SUSPECT/);
  assert.ok(!res.stdout.includes('cooldown config'), 'the report on stdout is untouched');
});

test('audit without --cooldown-config says nothing about it', async () => {
  const res = await runCli(['audit', '--path', FIX('cooldown-pnpm-suspect'),
    '--offline', '--no-trust', '--no-cache']);
  assert.strictEqual(res.status, 0);
  assert.ok(!res.stderr.includes('cooldown config'));
});

// --- the Action gate -------------------------------------------------------

test('the cooldown-check Action mode gates like sources-check', async () => {
  const action = path.join(ROOT, 'src', 'action.js');
  const run = (dir) => new Promise((resolve) => {
    const child = spawn(process.execPath, [action, 'cooldown-check'],
      { cwd: ROOT, env: { ...process.env, INPUT_PATH: dir, GITHUB_STEP_SUMMARY: '' }, timeout: 60000 });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    child.on('exit', (status) => resolve({ status, out }));
  });
  const bad = await run(FIX('cooldown-pnpm-suspect'));
  assert.strictEqual(bad.status, 1);
  assert.match(bad.out, /::error::UNIT-SUSPECT/);
  const good = await run(FIX('cooldown-npm-ok'));
  assert.strictEqual(good.status, 0);
  assert.match(good.out, /cooldown config check passed/);
});

// --- surfaces --------------------------------------------------------------

test('doctor names the manager, file, key, raw value and converted hours', async () => {
  const res = await runCli(['doctor', '--no-live', '--json', '--path', FIX('cooldown-pnpm-suspect')]);
  const report = JSON.parse(res.stdout);
  assert.deepStrictEqual(
    [report.cooldown.manager, report.cooldown.key, report.cooldown.raw, report.cooldown.hours],
    ['pnpm', 'minimumReleaseAge', '3', 0.05]);
  const line = report.checks.find((c) => c.name === 'cooldown config');
  assert.match(line.detail, /pnpm reads minimumReleaseAge from pnpm-workspace\.yaml in minutes: 3 \(0\.05h\)/);
  assert.strictEqual(line.status, 'warn', 'project config drift warns; only npm-contract drift fails');
});

test('completion offers the command and its flags', async () => {
  const { COMMANDS, FLAGS } = require('../src/completion');
  assert.ok(COMMANDS.includes('cooldown'));
  for (const flag of ['--cooldown', '--cooldown-allow', '--cooldown-config']) {
    assert.ok(FLAGS.includes(flag), flag);
  }
  const bash = (await runCli(['completion', 'bash'])).stdout;
  assert.match(bash, /cmds=".*\bcooldown\b/);
  assert.match(bash, /--cooldown-config/);
});

// --- regressions caught in review ------------------------------------------

test('--cooldown=24 in CI parses as 24, not as a bare flag defaulting to 72', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-eq-'));
  fs.mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.github', 'workflows', 'a.yml'),
    'jobs:\n  x:\n    steps:\n      - run: npm-script-lens audit --cooldown=24 --cooldown-allow=urgent\n');
  const found = findEnforcedCooldown(dir);
  assert.strictEqual(found.hours, 24, 'commander accepts --flag=value, so the scanner must too');
  assert.deepStrictEqual(found.allow, ['urgent']);
});

test('a --cooldown 0 in CI is a gate switched off, so nothing is MISSING', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-z-'));
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{"lockfileVersion":3,"packages":{}}');
  fs.mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.github', 'workflows', 'a.yml'),
    'jobs:\n  x:\n    steps:\n      - run: npm-script-lens audit --cooldown 0\n');
  const report = readCooldownConfig(path.join(dir, 'package-lock.json'), 'npm');
  assert.strictEqual(report.enforced, null);
  assert.deepStrictEqual(statusIds(report), []);
});

test('an informational status never becomes a SARIF result', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-info-'));
  fs.writeFileSync(path.join(dir, 'yarn.lock'), '__metadata:\n  version: 8\n');
  fs.writeFileSync(path.join(dir, '.yarnrc.yml'), 'npmMinimalAgeGate: 3d\n');
  const report = readCooldownConfig(path.join(dir, 'yarn.lock'), 'yarn');
  assert.deepStrictEqual(statusIds(report), [STATUS.OK], 'the unpinned-Yarn note');
  assert.deepStrictEqual(cooldownFindings([report]), [], 'SARIF lists what to act on, not notes');
});

test('every status id the classifier emits comes from STATUS', () => {
  const known = new Set(Object.values(STATUS));
  const reports = [
    readCooldownConfig(path.join(FIX('cooldown-pnpm-suspect'), 'pnpm-lock.yaml'), 'pnpm'),
    readCooldownConfig(path.join(FIX('cooldown-yarn-stale'), 'yarn.lock'), 'yarn'),
    readCooldownConfig(path.join(FIX('cooldown-bun-broken'), 'bun.lock'), 'bun'),
    readCooldownConfig(path.join(FIX('cooldown-bun-missing'), 'bun.lock'), 'bun', { hours: 48, allow: ['pkg@1.2.3'] }),
  ];
  for (const r of reports) {
    for (const s of r.statuses) assert.ok(known.has(s.id), `${s.id} is not in STATUS`);
  }
  assert.ok(reports[3].statuses.some((s) => s.id === STATUS.UNSUPPORTED));
});

test('a pnpm setting parked in .npmrc is named, not reported as simply absent', async () => {
  // pnpm's own docs: "Only auth and registry settings are read from .npmrc
  // files. All other settings ... must be configured in pnpm-workspace.yaml".
  const dir = copyFixture('cooldown-pnpm-ok');
  fs.rmSync(path.join(dir, 'pnpm-workspace.yaml'));
  fs.writeFileSync(path.join(dir, '.npmrc'), 'minimumReleaseAge=4320\n');
  const report = readCooldownConfig(path.join(dir, 'pnpm-lock.yaml'), 'pnpm');
  assert.deepStrictEqual(statusIds(report), [STATUS.MISSING]);
  assert.match(report.statuses[0].message, /is in \.npmrc \(4320\), not pnpm-workspace\.yaml, so pnpm never reads it/);
  assert.strictEqual(report.statuses[0].line, 1, 'anchored to the dead line');
  const res = await runCli(['cooldown', '--path', dir, '--check']);
  assert.strictEqual(res.status, 1);
});

test('DRIFT compares what the manager actually gates, not what the file implies', async () => {
  // On Yarn 4.10.2 `7d` is truncated to 7 minutes, so 168h is not the number
  // to compare against the enforced threshold.
  const dir = copyFixture('cooldown-yarn-stale');
  fs.mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.github', 'workflows', 'ci.yml'),
    'jobs:\n  x:\n    steps:\n      - run: npm-script-lens audit --cooldown 72\n');
  const report = readCooldownConfig(path.join(dir, 'yarn.lock'), 'yarn');
  const drift = report.statuses.find((s) => s.id === STATUS.DRIFT);
  assert.ok(drift, 'the effective 7-minute gate is below the enforced 72h');
  assert.match(drift.message, /configured 0\.12h < enforced 72h/);
  assert.match(drift.message, /because yarn truncates 7d here/);
});

test('a non-failing status is never printed as a FAIL line', async () => {
  const dir = copyFixture('cooldown-bun-missing');
  const res = await runCli(['cooldown', '--path', dir, '--check', '--cooldown', '48',
    '--cooldown-allow', 'pkg@1.2.3']);
  assert.strictEqual(res.status, 1);
  assert.match(res.stdout, /UNSUPPORTED/, 'still reported');
  assert.ok(!res.stderr.includes('FAIL (UNSUPPORTED)'), 'but not as a failure');
  assert.match(res.stderr, /FAIL \(MISSING\)/);
});

test('--write refuses the whole run when any project cannot be round-tripped', async () => {
  const dir = copyFixture('cooldown-bun-broken');
  const before = read(dir, 'bunfig.toml');
  const res = await runCli(['cooldown', '--path', dir, '--write', '--cooldown', '72']);
  assert.strictEqual(res.status, 2);
  assert.match(res.stderr, /nothing was written/);
  assert.strictEqual(read(dir, 'bunfig.toml'), before);
});

test('a zero gate renders as 0 in every manager, including yarn', () => {
  for (const row of Object.values(COOLDOWN)) assert.strictEqual(cooldownValue(row, 0), '0', row.id);
});

test('a sub-day threshold survives the round trip into npm days', () => {
  // npm counts DAYS, so an hourly threshold is a fraction. Four decimals of a
  // day is 8.6 seconds of resolution, which is enough to visibly move a gate;
  // six is under a tenth of a second, which is not.
  for (const hours of [1, 5, 6, 12, 36]) {
    const value = cooldownValue(COOLDOWN.npm, hours);
    const drift = Math.abs(Number(value) * 24 - hours) * 3600;
    assert.ok(drift < 1, `${hours}h -> ${value} days is ${drift.toFixed(3)}s out`);
  }
});

test('a malformed TOML header is not mistaken for a section', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-toml2-'));
  fs.writeFileSync(path.join(dir, 'bunfig.toml'), '[install]\nminimumReleaseAge = 259200\n[oops]]\n');
  const cfg = readBunfig(dir);
  assert.strictEqual(cfg.entries.minimumReleaseAge.raw, '259200');
  assert.match(cfg.partial, /bunfig\.toml:3/, 'an unbalanced header is reported, not silently obeyed');
});

test('a lockfile path as --path labels the project "." , not ".."', async () => {
  // This repo's own self-audit workflow passes `path: package-lock.json`.
  const dir = copyFixture('cooldown-monorepo');
  const res = await runCli(['cooldown', '--path', path.join(dir, 'packages', 'web', 'pnpm-lock.yaml'), '--check']);
  assert.strictEqual(res.status, 1);
  assert.ok(!res.stdout.includes('[..]') && !res.stderr.includes('(..)'), res.stdout + res.stderr);
  const action = path.join(ROOT, 'src', 'action.js');
  const out = await new Promise((resolve) => {
    const child = spawn(process.execPath, [action, 'cooldown-check'], {
      cwd: ROOT, env: { ...process.env, INPUT_PATH: path.join(FIX('cooldown-npm-ok'), 'package-lock.json') }, timeout: 60000,
    });
    let s = '';
    child.stdout.on('data', (d) => { s += d; });
    child.on('exit', () => resolve(s));
  });
  assert.match(out, /passed: \.: npm min-release-age=3/);
});

test('a passing report always shows its converted hours, even alongside a note', async () => {
  const res = await runCli(['cooldown', '--path', FIX('cooldown-bun-ok'), '--check',
    '--cooldown-allow', 'urgent-fix', 'pkg@1.2.3']);
  assert.strictEqual(res.status, 0);
  assert.match(res.stdout, /OK {12}\[install\] minimumReleaseAge = 259200 {2}→ 72h/);
  assert.match(res.stdout, /UNSUPPORTED/, 'and the note is still there');
});

test('the unpinned-Yarn note is the OK line, not a second one', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-one-ok-'));
  fs.writeFileSync(path.join(dir, '.yarnrc.yml'), 'npmMinimalAgeGate: 3d\n');
  fs.writeFileSync(path.join(dir, 'yarn.lock'), '__metadata:\n  version: 8\n');
  const report = readCooldownConfig(path.join(dir, 'yarn.lock'), 'yarn');
  const text = renderCooldownConfig(report);
  assert.strictEqual(text.split('\n').filter((l) => l.includes('OK ')).length, 1, text);
});

test('doctor warns only on statuses that fail, and never says it twice', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-doc-'));
  fs.writeFileSync(path.join(dir, '.yarnrc.yml'), 'npmMinimalAgeGate: 3d\n');
  fs.writeFileSync(path.join(dir, 'yarn.lock'), '__metadata:\n  version: 8\n');
  const note = JSON.parse((await runCli(['doctor', '--no-live', '--json', '--path', dir])).stdout);
  const lines = note.checks.filter((c) => c.name === 'cooldown config');
  assert.strictEqual(lines.length, 1, 'the note IS the summary, not a second line');
  assert.strictEqual(lines[0].status, 'info', 'an unpinned Yarn is context, not a warning');

  const bad = JSON.parse((await runCli(['doctor', '--no-live', '--json', '--path', FIX('cooldown-pnpm-suspect')])).stdout);
  const badLines = bad.checks.filter((c) => c.name === 'cooldown config');
  assert.deepStrictEqual(badLines.map((c) => c.status), ['warn', 'warn']);
  assert.ok(bad.checks.some((c) => c.name === 'cooldown config fix'));
});

test('the Action emits ::error:: only for statuses the check fails on', async () => {
  const action = path.join(ROOT, 'src', 'action.js');
  const out = await new Promise((resolve) => {
    const child = spawn(process.execPath, [action, 'cooldown-check'], {
      cwd: ROOT, env: { ...process.env, INPUT_PATH: FIX('cooldown-bun-missing') }, timeout: 60000,
    });
    let s = '';
    child.stdout.on('data', (d) => { s += d; });
    child.on('exit', () => resolve(s));
  });
  const errors = out.split('\n').filter((l) => l.startsWith('::error::'));
  assert.deepStrictEqual(errors.map((l) => l.slice(9).split(' ')[0]), ['MISSING']);
});
