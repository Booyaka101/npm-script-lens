'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const {
  findDepLine, findYamlKeyLine, diagnosticsForPackageJson, summarize, parseAuditJson,
} = require('../src/core');

const PKG = `{
  "name": "app",
  "version": "1.0.0",
  "dependencies": {
    "sharp": "^0.33.5",
    "chalk": "^5.3.0"
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
  { name: 'evilpkg', version: '9.9.9', malicious: true, advisories: ['MAL-2026-1'], rows: [] },
];

test('findDepLine locates a dependency across sections; -1 when absent', () => {
  assert.strictEqual(findDepLine(PKG, 'sharp'), 4);
  assert.strictEqual(findDepLine(PKG, 'esbuild'), 8);
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

test('diagnosticsForPackageJson anchors scripted/malicious packages, skips clean + absent', () => {
  const diags = diagnosticsForPackageJson(PKG, RESULTS);
  const byName = Object.fromEntries(diags.map((d) => [d.name, d]));
  assert.ok(byName.sharp && byName.sharp.line === 4 && byName.sharp.severity === 'warning');
  assert.ok(byName.sharp.message.includes('🔴 HIGH') && byName.sharp.message.includes('node-gyp'));
  assert.ok(byName.esbuild && byName.esbuild.line === 8);
  assert.ok(!byName.chalk, 'clean package produces no diagnostic');
  assert.ok(!byName.evilpkg, 'malicious package not in package.json text is skipped (no line)');
});

test('malicious package in the manifest becomes an error diagnostic', () => {
  const pkg = '{\n  "dependencies": {\n    "evilpkg": "9.9.9"\n  }\n}\n';
  const [d] = diagnosticsForPackageJson(pkg, RESULTS);
  assert.strictEqual(d.name, 'evilpkg');
  assert.strictEqual(d.severity, 'error');
  assert.ok(d.message.includes('⛔ MALICIOUS') && d.message.includes('MAL-2026-1'));
});

test('summarize rolls up the worst risk for the status bar', () => {
  assert.strictEqual(summarize(RESULTS).bad, 3, 'evilpkg malicious + sharp + esbuild HIGH');
  assert.ok(summarize(RESULTS).text.includes('malicious'), 'malicious dominates the summary');
  assert.ok(summarize([{ name: 'a', version: '1', risk: 'LOW', rows: [{ signals: ['fs: x'] }] }]).text.includes('scripted dep'));
  assert.ok(summarize([]).text.includes('clean'));
});

test('parseAuditJson tolerates leading log noise on stdout', () => {
  const out = 'auditing 5 packages\n{"results":[{"name":"a","version":"1","risk":"LOW","rows":[]}],"allowScripts":{}}';
  assert.strictEqual(parseAuditJson(out).length, 1);
  assert.strictEqual(parseAuditJson('npm ERR broke'), null);
});
