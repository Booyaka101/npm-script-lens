'use strict';
// Terminal layout: prose reflows to the width, everything that carries
// meaning in its columns (tables, diffs, JSON, aligned rows) does not, and
// piped output is never touched.
const { test } = require('node:test');
const assert = require('node:assert');
const { wrapReport, wrapLine, isProse, terminalWidth } = require('../src/format');

const SENTENCE = 'the job declares no environment key so GitHub cannot require an approval before this publishes';

test('wrapReport is a no-op when stdout is not a terminal', () => {
  const text = `x ${SENTENCE} ${SENTENCE}`;
  // no width resolved (pipe, file, CI) means byte-identical output, which is
  // what every test in this suite and every CI log depends on
  assert.strictEqual(wrapReport(text, null), text);
  assert.strictEqual(terminalWidth({ isTTY: false, columns: 200 }), null);
  assert.strictEqual(terminalWidth({ isTTY: true, columns: 0 }), null);
});

test('terminalWidth clamps to a readable range', () => {
  assert.strictEqual(terminalWidth({ isTTY: true, columns: 40 }), 60);
  assert.strictEqual(terminalWidth({ isTTY: true, columns: 300 }), 100);
  assert.strictEqual(terminalWidth({ isTTY: true, columns: 90 }), 89);
});

test('wrapped lines stay within the width and keep their leading indent', () => {
  const out = wrapLine(`            gate:    TAG: ${SENTENCE}`, 70).split('\n');
  assert.ok(out.length > 1, 'expected a wrap');
  for (const line of out) assert.ok(line.length <= 70, `too long: ${line.length}`);
  assert.match(out[0], /^ {12}gate: {4}TAG: /);
  // continuations hang under the text, not under the indent
  for (const line of out.slice(1)) assert.match(line, /^ {21}\S/);
});

test('a label prefix is copied verbatim, so column alignment survives', () => {
  const line = `  workflow filename:   release.yml ${SENTENCE}`;
  assert.ok(wrapLine(line, 60).startsWith('  workflow filename:   release.yml'));
});

test('glyph prefixes are measured in columns, not code units', () => {
  // `ℹ️` is U+2139 + U+FE0F: two code units, one visible column, and U+2139
  // is categorized as a LETTER, which is why the prefix match is ASCII-based
  const out = wrapLine(`ℹ️  package manager: ${SENTENCE}`, 60).split('\n');
  assert.match(out[0], /^ℹ️ {2}package manager: /);
  assert.strictEqual(out[1].match(/^ */)[0].length, 'ℹ  package manager: '.length);
});

test('a word longer than the width gets its own line rather than being broken', () => {
  const url = 'https://github.blog/changelog/2026-07-31-restricting-npm-bypass-2fa-granular-access-tokens/';
  const out = wrapLine(`see ${url} for the announcement text`, 40).split('\n');
  assert.ok(out.some((l) => l.includes(url)), 'url must survive intact');
});

test('isProse rejects diffs, JSON, tables, aligned rows and short lines', () => {
  assert.ok(!isProse('    + permissions:'));
  assert.ok(!isProse('    -   NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}'));
  assert.ok(!isProse('  "allowScripts": {'));
  assert.ok(!isProse('| `chalk@5.3.0` | — | 🟢 SAFE | no lifecycle scripts |'));
  assert.ok(!isProse('  TOKEN     .github/workflows/release.yml:15  npm publish   [job release]'));
  assert.ok(!isProse('publish paths (1)'));
  assert.ok(isProse(`            gate:    AUTO: ${SENTENCE}`));
});

test('wrapReport leaves a report alone when every line already fits', () => {
  const text = ['publish paths (1)', '  TRUSTED  release.yml:22  npm publish', ''].join('\n');
  assert.strictEqual(wrapReport(text, 100), text);
});

test('wrapReport reflows only the lines that are too long', () => {
  const text = ['publish paths (1)', `  ${SENTENCE}`, '    + permissions:'].join('\n');
  const out = wrapReport(text, 60).split('\n');
  assert.strictEqual(out[0], 'publish paths (1)');
  assert.strictEqual(out[out.length - 1], '    + permissions:');
  assert.ok(out.length > 3, 'the prose line should have wrapped');
});
