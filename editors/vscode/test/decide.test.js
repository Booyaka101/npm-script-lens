'use strict';
// Everything the extension does BEYOND painting a squiggle: recording one
// package's decision into four different allowlist formats, grouping the
// project for the panel, and the evidence the CLI always returned but the
// editor used to drop (the install command itself, and who published it).
//
// The writers matter most: they edit files the user owns, so each one is
// checked against what src/pm-contract.js (the CLI's writer) produces for the
// same decision. Same bytes, whichever end you drive it from.
const { test } = require('node:test');
const assert = require('node:assert');
const {
  managerFrom, decisionEdit, allowlistFileFor, MANAGER_LABEL, parseAllowBuilds,
  readDecisions, treeFor, scriptLines, trustLines, explainFor,
} = require('../src/core');

const RESULTS = [
  { name: 'sharp', version: '0.33.5', risk: 'HIGH', rows: [{ script: 'install', command: 'node-gyp rebuild', signals: ['exec: node-gyp rebuild'] }] },
  { name: 'esbuild', version: '0.17.19', risk: 'HIGH', rows: [{ signals: ['exec: node install.js'] }] },
  { name: 'chalk', version: '5.3.0', risk: 'SAFE', rows: [] }, // no install script at all
  { name: 'noop-hooks', version: '1.0.0', risk: 'SAFE', rows: [{ signals: [] }] },
  { name: 'evilpkg', version: '9.9.9', malicious: true, advisories: ['MAL-2026-1'], rows: [] },
];
const RECOMMENDED = {
  'sharp@0.33.5': false, 'esbuild@0.17.19': false, 'noop-hooks@1.0.0': true, 'evilpkg@9.9.9': false,
};
const allowing = (allowScripts) => readDecisions(JSON.stringify({ allowScripts }));

// --- which file does a decision belong in? ---------------------------------

test('managerFrom follows the CLI lockfile precedence, npm when there is none', () => {
  assert.strictEqual(managerFrom(['pnpm-lock.yaml']), 'pnpm');
  assert.strictEqual(managerFrom(['yarn.lock']), 'yarn');
  assert.strictEqual(managerFrom(['bun.lock']), 'bun');
  assert.strictEqual(managerFrom(['bun.lockb']), 'bun');
  assert.strictEqual(managerFrom(['npm-shrinkwrap.json']), 'npm');
  // lockfiles.js LOCKFILE_NAMES order decides it when a repo carries several
  assert.strictEqual(managerFrom(['pnpm-lock.yaml', 'package-lock.json']), 'npm');
  assert.strictEqual(managerFrom(['bun.lock', 'yarn.lock']), 'yarn');
  assert.strictEqual(managerFrom(['README.md']), 'npm', 'npm 12 reads the format we fall back to');
  assert.strictEqual(allowlistFileFor('pnpm'), 'pnpm-workspace.yaml');
  assert.strictEqual(allowlistFileFor('bun'), 'package.json');
  assert.ok(MANAGER_LABEL.yarn.includes('Berry'));
});

// --- writing it ------------------------------------------------------------

test('decisionEdit: npm keys by name@version and preserves the file it edits', () => {
  const before = '{\n\t"name": "app",\n\t"dependencies": {\n\t\t"sharp": "^0.33.5"\n\t}\n}\n';
  const { file, text, note } = decisionEdit({ manager: 'npm', name: 'sharp', version: '0.33.5', allow: true, pkgText: before });
  assert.strictEqual(file, 'package.json');
  assert.strictEqual(note, null);
  const after = JSON.parse(text);
  assert.deepStrictEqual(after.allowScripts, { 'sharp@0.33.5': true });
  assert.strictEqual(after.name, 'app', 'nothing else in the manifest moves');
  assert.ok(text.includes('\n\t"name"'), 'the file keeps its own indentation');
  assert.ok(text.endsWith('\n'), 'and its trailing newline');

  // a denial is a recorded decision, not a deletion: it has to survive re-audit
  const denied = JSON.parse(decisionEdit({ manager: 'npm', name: 'sharp', version: '0.33.5', allow: false, pkgText: text }).text);
  assert.deepStrictEqual(denied.allowScripts, { 'sharp@0.33.5': false });
});

test('decisionEdit: entries stay sorted, so repeated decisions do not churn the diff', () => {
  let text = '{"dependencies":{}}';
  for (const name of ['zlib-sync', 'argon2', 'sharp']) {
    text = decisionEdit({ manager: 'npm', name, version: '1.0.0', allow: true, pkgText: text }).text;
  }
  assert.deepStrictEqual(Object.keys(JSON.parse(text).allowScripts),
    ['argon2@1.0.0', 'sharp@1.0.0', 'zlib-sync@1.0.0']);
});

test('decisionEdit: pnpm splices allowBuilds and leaves the rest of the yaml alone', () => {
  const before = 'packages:\n  - "packages/*"\nallowBuilds:\n  esbuild: true\nonlyBuiltDependencies: []\n';
  const { file, text } = decisionEdit({ manager: 'pnpm', name: 'sharp', version: '0.33.5', allow: false, yamlText: before });
  assert.strictEqual(file, 'pnpm-workspace.yaml');
  assert.ok(text.includes('packages:\n  - "packages/*"'), 'untouched keys survive verbatim');
  assert.ok(text.includes('onlyBuiltDependencies: []'), 'including the ones after the block');
  assert.deepStrictEqual(parseAllowBuilds(text), { esbuild: true, sharp: false });

  // no file yet: emit one that is only the block
  const fresh = decisionEdit({ manager: 'pnpm', name: '@scope/x', version: '1', allow: true, yamlText: '' }).text;
  assert.strictEqual(fresh, 'allowBuilds:\n  "@scope/x": true\n', 'a scoped name is not a plain YAML scalar');

  // a file with no block yet gets one appended, never a second copy
  const appended = decisionEdit({ manager: 'pnpm', name: 'sharp', version: '1', allow: true, yamlText: 'packages:\n  - "."\n' }).text;
  assert.strictEqual(appended, 'packages:\n  - "."\nallowBuilds:\n  sharp: true\n');
});

test('decisionEdit: yarn writes dependenciesMeta.built and says what else it needs', () => {
  const before = '{"dependenciesMeta":{"sharp":{"optional":true}}}';
  const { text, note } = decisionEdit({ manager: 'yarn', name: 'sharp', version: '0.33.5', allow: true, pkgText: before });
  assert.deepStrictEqual(JSON.parse(text).dependenciesMeta.sharp, { optional: true, built: true },
    'other dependenciesMeta keys are preserved');
  assert.ok(note.includes('enableScripts: false'), 'dependenciesMeta is only an allowlist when scripts are off');
});

test('decisionEdit: bun can spell a trust but not a denial, and says so', () => {
  const allowed = decisionEdit({ manager: 'bun', name: 'sharp', version: '0.33.5', allow: true, pkgText: '{}' });
  assert.deepStrictEqual(JSON.parse(allowed.text).trustedDependencies, ['sharp']);
  assert.ok(allowed.note.includes('replaces bun'), 'defining the field drops bun\'s built-in trusted list');

  // adding to a list that already exists is not that cliff, so it stops warning
  const second = decisionEdit({ manager: 'bun', name: 'argon2', version: '1', allow: true, pkgText: allowed.text });
  assert.deepStrictEqual(JSON.parse(second.text).trustedDependencies, ['argon2', 'sharp']);
  assert.strictEqual(second.note, null);

  const denied = decisionEdit({ manager: 'bun', name: 'sharp', version: '0.33.5', allow: false, pkgText: second.text });
  assert.deepStrictEqual(JSON.parse(denied.text).trustedDependencies, ['argon2']);
  assert.ok(denied.note.includes('no way to record a denial'), 'the gap is stated, not papered over');
});

test('decisionEdit: an unparseable package.json fails loudly instead of writing one', () => {
  assert.throws(() => decisionEdit({ manager: 'npm', name: 'x', version: '1', allow: true, pkgText: '{ broken' }));
  // ...while pnpm never has to parse it, so a mid-edit manifest cannot block a decision
  assert.ok(decisionEdit({ manager: 'pnpm', name: 'x', version: '1', allow: true, pkgText: '{ broken' }).text);
});

// --- the panel -------------------------------------------------------------

test('treeFor groups every scripted dependency by what is left to do', () => {
  const decisions = allowing({ 'sharp@0.33.5': true, 'noop-hooks@1.0.0': true });
  const groups = treeFor(RESULTS, { recommended: RECOMMENDED, decisions });
  assert.deepStrictEqual(groups.map((g) => g.id), ['alarm', 'decide', 'override', 'settled'],
    'worst first, and chalk (no install script) is not in the list at all');
  const of = (id) => groups.find((g) => g.id === id).items.map((i) => i.key);
  assert.deepStrictEqual(of('decide'), ['esbuild@0.17.19']);
  assert.deepStrictEqual(of('override'), ['sharp@0.33.5']);
  // an install script that analyzed clean gets no squiggle, but it is still a
  // decision, and the panel is where you can see and make it
  assert.deepStrictEqual(of('settled'), ['noop-hooks@1.0.0']);

  const undecided = treeFor(RESULTS, { recommended: RECOMMENDED });
  assert.deepStrictEqual(undecided.find((g) => g.id === 'clean').items.map((i) => i.key), ['noop-hooks@1.0.0']);
  const item = undecided.find((g) => g.id === 'decide').items[0];
  assert.ok(item.detail.includes('runs other programs'), item.detail);
  assert.ok(item.explain.includes('**What to do**'));
});

test('treeFor sorts worst-first inside a group, then by name for a stable list', () => {
  const results = [
    { name: 'b-low', version: '1', risk: 'LOW', rows: [{ signals: ['fs: writeFile'] }] },
    { name: 'a-high', version: '1', risk: 'HIGH', rows: [{ signals: ['exec: sh'] }] },
    { name: 'z-high', version: '1', risk: 'HIGH', rows: [{ signals: ['exec: sh'] }] },
    { name: 'c-med', version: '1', risk: 'MEDIUM', rows: [{ signals: ['net: fetch()'] }] },
  ];
  const [group] = treeFor(results, { recommended: {} });
  assert.deepStrictEqual(group.items.map((i) => i.name), ['a-high', 'z-high', 'c-med', 'b-low']);
});

// --- evidence the CLI always had, that the editor used to drop --------------

test('scriptLines names the lifecycle script and its command, once each', () => {
  const rows = [
    { script: 'postinstall', command: 'node scripts/postinstall.js' },
    { script: 'postinstall', command: 'node scripts/postinstall.js' },
    { script: 'install', command: 'node-gyp rebuild' },
  ];
  assert.deepStrictEqual(scriptLines(rows), [
    '- `postinstall` → `node scripts/postinstall.js`',
    '- `install` → `node-gyp rebuild`',
  ]);
  assert.deepStrictEqual(scriptLines([]), []);
  assert.deepStrictEqual(scriptLines([{ signals: [] }]), [], 'a row with no script name has nothing to say');
});

test('trustLines turn the publisher fetch into something a reader can weigh', () => {
  const md = trustLines({
    ageDays: 400,
    weeklyDownloads: 61234567,
    maintainers: 3,
    provenanceOk: true,
    provenance: { present: true, repository: 'github.com/evanw/esbuild', workflow: '.github/workflows/release.yml' },
  }).join('\n');
  assert.ok(md.includes('61,234,567 downloads a week'), md);
  assert.ok(md.includes('built from `github.com/evanw/esbuild`'), md);
  assert.ok(!md.includes('cooldown'), 'a year-old version is not a freshness story');

  // the combination that actually matters: brand-new code that runs on install
  const fresh = trustLines({ ageDays: 2, provenanceOk: false }).join('\n');
  assert.ok(fresh.includes('published **2 days ago**'), fresh);
  assert.ok(fresh.includes('no provenance attestation'), fresh);
  assert.ok(fresh.includes('waiting out a cooldown'), 'and what to do about it');
  assert.ok(trustLines({ ageDays: 0 }).join('\n').includes('published **today**'));

  // never checked is not the same as checked and clean
  assert.deepStrictEqual(trustLines(null), []);
});

test('explainFor leads with the script itself when the audit reported one', () => {
  const md = explainFor({
    name: '@prisma/engines',
    version: '5.22.0',
    risk: 'HIGH',
    rows: [{ script: 'postinstall', command: 'node scripts/postinstall.js', signals: ['exec: cp.spawn()', "net: require('@prisma/fetch-engine')"] }],
    trust: { ageDays: 1, weeklyDownloads: 2000000, provenanceOk: false },
  }, 'decide', ['prisma']);
  assert.ok(md.indexOf('`node scripts/postinstall.js`') < md.indexOf('- runs other programs'),
    'the command comes before its analysis');
  assert.ok(md.includes('`postinstall` → `node scripts/postinstall.js`'), md);
  assert.ok(md.includes('published **1 day ago**'), md);
  assert.ok(md.startsWith('**@prisma/engines@5.22.0** — waiting on your decision'), md);
});
