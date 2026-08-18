'use strict';
// The extension records a decision by computing the new file text itself,
// rather than shelling out to `npm-script-lens`, so that approving a package
// is an ordinary undoable editor edit instead of a file rewritten underneath
// you. That only holds up if the two writers agree byte for byte: a decision
// made in the editor and the same decision made from the CLI have to produce
// the same file, or a project ends up with two spellings of its own allowlist
// and `sync --check` starts failing CI over whitespace.
//
// So: run both, diff the bytes. This is the test that catches pm-contract.js
// changing its formatting without core.js following.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { managerById } = require('../../../src/pm-contract');
const core = require('../src/core');

// Every shape that changes which branch a writer takes: fresh file, existing
// entries, a foreign indent, a yaml block that is not the last thing in the
// file, and a yaml file with no block at all.
const CASES = [
  ['npm', 'fresh manifest', '{\n  "name": "app",\n  "dependencies": { "sharp": "^0.33.5" }\n}\n', ''],
  ['npm', 'tab indent, existing entries', '{\n\t"name": "app",\n\t"allowScripts": { "zz@1": false }\n}\n', ''],
  ['yarn', 'other dependenciesMeta keys', '{\n  "dependenciesMeta": { "sharp": { "optional": true } }\n}\n', ''],
  ['bun', 'existing trusted list', '{\n  "trustedDependencies": ["argon2"]\n}\n', ''],
  ['pnpm', 'block with keys after it', '{}', 'packages:\n  - "packages/*"\nallowBuilds:\n  esbuild: true\nonlyBuiltDependencies: []\n'],
  ['pnpm', 'no workspace file yet', '{}', ''],
  ['pnpm', 'workspace file with no block', '{}', 'packages:\n  - "."\n'],
];

for (const [manager, shape, pkgText, yamlText] of CASES) {
  // try/finally rather than t.after: the repo's declared Node floor is 18, and
  // the test context only grew `after` partway through that line.
  test(`decisionEdit matches the CLI writer: ${manager}, ${shape}`, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsl-parity-'));
    try {
      fs.writeFileSync(path.join(dir, 'package.json'), pkgText);
      if (yamlText) fs.writeFileSync(path.join(dir, 'pnpm-workspace.yaml'), yamlText);

      managerById(manager).writeDecisions(dir, [{ name: 'sharp', version: '0.33.5', allow: true }]);
      const file = core.allowlistFileFor(manager);
      const fromCli = fs.readFileSync(path.join(dir, file), 'utf8');
      const fromEditor = core.decisionEdit({ manager, name: 'sharp', version: '0.33.5', allow: true, pkgText, yamlText });

      assert.strictEqual(fromEditor.file, file, 'both writers pick the same file');
      assert.strictEqual(fromEditor.text, fromCli);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}

test('decisionEdit matches the CLI writer for denials, where the format can spell one', () => {
  for (const manager of ['npm', 'yarn', 'pnpm']) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsl-parity-'));
    const pkgText = '{\n  "name": "app"\n}\n';
    fs.writeFileSync(path.join(dir, 'package.json'), pkgText);
    managerById(manager).writeDecisions(dir, [{ name: 'sharp', version: '0.33.5', allow: false }]);
    const fromCli = fs.readFileSync(path.join(dir, core.allowlistFileFor(manager)), 'utf8');
    const mine = core.decisionEdit({ manager, name: 'sharp', version: '0.33.5', allow: false, pkgText, yamlText: '' });
    assert.strictEqual(mine.text, fromCli, manager);
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // bun is deliberately excluded: it has no denial to write. The CLI drops the
  // name from trustedDependencies and says so, and so does decisionEdit.
  const denied = core.decisionEdit({ manager: 'bun', name: 'sharp', version: '1', allow: false, pkgText: '{"trustedDependencies":["sharp"]}' });
  assert.deepStrictEqual(JSON.parse(denied.text).trustedDependencies, []);
  assert.ok(denied.note.includes('no way to record a denial'));
});
