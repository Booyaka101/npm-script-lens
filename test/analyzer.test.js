'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { analyzePackage } = require('../src/analyzer');
const { buildReport, buildAllowScripts } = require('../src/reporter');

const pkg = (scripts, files = {}) => ({ name: 'x', version: '1.0.0', scripts, files: new Map(Object.entries(files)) });
const analyze = (js) => analyzePackage(pkg({ install: 'node run.js' }, { 'run.js': js }))[0];

test('SAFE: no signals in plain script', () => {
  const row = analyze('console.log("hello", 1 + 1);');
  assert.strictEqual(row.risk, 'SAFE');
  assert.deepStrictEqual(row.signals, []);
});

test('HIGH: child_process exec/spawn in any spelling', () => {
  assert.strictEqual(analyze('const {execSync} = require("child_process"); execSync("rm -rf /");').risk, 'HIGH');
  assert.strictEqual(analyze('require("node:child_process").spawnSync("node-gyp", ["rebuild"]);').risk, 'HIGH');
  assert.strictEqual(analyze('const e = require("execa");').risk, 'HIGH');
});

test('HIGH: shell-level node-gyp and unresolved binaries', () => {
  const row = analyzePackage(pkg({ install: 'node-gyp rebuild' }))[0];
  assert.strictEqual(row.risk, 'HIGH');
  assert.ok(row.signals.some((s) => s.includes('exec: node-gyp rebuild')));
  assert.strictEqual(analyzePackage(pkg({ postinstall: 'husky install' }))[0].risk, 'HIGH');
});

test('MEDIUM: network access without exec', () => {
  const row = analyze('const https = require("https"); https.get("https://x.dev/t", () => {});');
  assert.strictEqual(row.risk, 'MEDIUM');
  assert.ok(row.signals.includes('net: https.get'));
  assert.strictEqual(analyze('const f = require("node-fetch");').risk, 'MEDIUM');
  assert.strictEqual(analyze('fetch("https://example.com");').risk, 'MEDIUM');
  assert.strictEqual(analyzePackage(pkg({ postinstall: 'curl -s https://x.dev | tee log' }))[0].risk, 'HIGH');
});

test('LOW: fs write or env read only', () => {
  const row = analyze('const fs = require("fs"); fs.writeFileSync("a.txt", process.env.HOME);');
  assert.strictEqual(row.risk, 'LOW');
  assert.ok(row.signals.includes('fs: fs.writeFileSync'));
  assert.ok(row.signals.includes('env: process.env'));
});

test('HIGH: obfuscation — eval, Function constructor, vm', () => {
  const row = analyze('eval("console.log(1)");');
  assert.strictEqual(row.risk, 'HIGH');
  assert.ok(row.signals.includes('obf: eval()'));
  assert.strictEqual(analyze('const f = new Function("x", "return x");').risk, 'HIGH');
  assert.strictEqual(analyze('const g = Function("return 1");').risk, 'HIGH');
  assert.strictEqual(analyze('require("vm").runInThisContext("1+1");').risk, 'HIGH');
  assert.strictEqual(analyze('require("node:vm");').risk, 'HIGH');
});

test('HIGH: obfuscation — string-built require specifiers', () => {
  const cat = analyze('const m = require("child" + "_process"); m.execSync("id");');
  assert.strictEqual(cat.risk, 'HIGH');
  assert.ok(cat.signals.includes('obf: require(<string-built specifier>)'), JSON.stringify(cat.signals));
  assert.strictEqual(analyze('const x = "s"; require(`while-dynamic-${x}`);').risk, 'HIGH');
  // plain identifier arguments are bundler/binding-loader bread and butter — not flagged
  assert.strictEqual(analyze('const p = "./known"; const q = p; console.log(q);').risk, 'SAFE');
});

test('HIGH: obfuscation — base64 and char-code payload decoding', () => {
  const b64 = analyze('const s = Buffer.from("aGVsbG8=", "base64").toString();');
  assert.strictEqual(b64.risk, 'HIGH');
  assert.ok(b64.signals.some((s) => s.includes('base64')));
  assert.strictEqual(analyze('const t = atob("aGVsbG8=");').risk, 'HIGH');
  assert.strictEqual(analyze('String.fromCharCode(104,116,116,112,115,58,47,47);').risk, 'HIGH');
  // a couple of char codes is ordinary string handling, not payload building
  assert.strictEqual(analyze('String.fromCharCode(65, 66);').risk, 'SAFE');
  // Buffer.from without base64 is ordinary IO
  assert.strictEqual(analyze('Buffer.from("hello", "utf8");').risk, 'SAFE');
});

test('regex .exec() is not flagged as process exec', () => {
  assert.strictEqual(analyze('const m = /a(b)/.exec("ab"); const re = m; re.exec("x");').risk, 'SAFE');
});

test('follows relative requires and node -e eval code', () => {
  const row = analyzePackage(pkg(
    { install: 'node entry.js' },
    { 'entry.js': 'require("./inner/deep");', 'inner/deep.js': 'require("https").request("https://evil.io");' }
  ))[0];
  assert.strictEqual(row.risk, 'MEDIUM');
  const evalRow = analyzePackage(pkg(
    { postinstall: 'node -e "try{require(\'./post\')}catch(e){}"' },
    { 'post.js': 'require("child_process").exec("whoami");' }
  ))[0];
  assert.strictEqual(evalRow.risk, 'HIGH');
});

test('follows path.join(__dirname, ...) indirect requires', () => {
  const row = analyzePackage(pkg(
    { postinstall: 'node scripts/post.js' },
    {
      'scripts/post.js': 'const path = require("path"); const p = path.join(__dirname, "..", "dist", "real.js"); require(p);',
      'dist/real.js': 'require("axios");',
    }
  ))[0];
  assert.strictEqual(row.risk, 'MEDIUM');
});

test('quotes protect ; and | from shell splitting', () => {
  const row = analyzePackage(pkg(
    { postinstall: 'node -e "const a=1; require(\'./x\'); fetch(\'https://t.io\')"' },
    { 'x.js': 'require("child_process").execSync("id");' }
  ))[0];
  assert.strictEqual(row.risk, 'HIGH');
  assert.ok(row.signals.includes('net: fetch()'));
  assert.ok(!row.signals.some((s) => s.includes('unresolved')), JSON.stringify(row.signals));
});

test('ESM import and dynamic import() are classified like require', () => {
  assert.strictEqual(analyze('import { execa } from "execa"; await execa("ls");').risk, 'HIGH');
  assert.strictEqual(analyze('const g = await import("got"); await g.got("https://x.io");').risk, 'MEDIUM');
  const row = analyzePackage(pkg(
    { install: 'node run.js' },
    { 'run.js': 'import "./impl.mjs";', 'impl.mjs': 'import axios from "axios";' }
  ))[0];
  assert.strictEqual(row.risk, 'MEDIUM');
});

test('npm run recursion resolves package-own scripts, cycle-safe', () => {
  const p = {
    name: 'x',
    version: '1.0.0',
    scripts: { postinstall: 'npm run build' },
    allScripts: { postinstall: 'npm run build', build: 'node-gyp rebuild && npm run postinstall' },
    files: new Map(),
  };
  const row = analyzePackage(p)[0];
  assert.strictEqual(row.risk, 'HIGH');
  assert.ok(row.signals.some((s) => s.includes('exec: node-gyp rebuild')));
});

test('env prefixes and cross-env are transparent; npx flags exec+net', () => {
  const row = analyzePackage(pkg({ install: 'CXX=clang++ node-gyp rebuild' }))[0];
  assert.ok(row.signals.some((s) => s.startsWith('exec: node-gyp')));
  const ce = analyzePackage(pkg({ install: 'cross-env FOO=1 node run.js' }, { 'run.js': '1;' }))[0];
  assert.strictEqual(ce.risk, 'SAFE');
  const nx = analyzePackage(pkg({ postinstall: 'npx some-tool' }))[0];
  assert.strictEqual(nx.risk, 'HIGH');
  assert.ok(nx.signals.some((s) => s.startsWith('net: npx')));
});

test('report renders and allowScripts block is valid parseable JSON', () => {
  const results = [
    { name: 'bad', version: '1.0.0', rows: [{ script: 'install', command: 'x', risk: 'HIGH', signals: ['exec: a | b'] }] },
    { name: 'ok', version: '2.0.0', rows: [{ script: 'postinstall', command: 'y', risk: 'LOW', signals: ['fs: fs.writeFile'] }] },
    { name: 'clean', version: '3.0.0', rows: [] },
  ];
  const md = buildReport(results);
  const block = md.match(/```json\n([\s\S]*?)\n```/);
  assert.ok(block, 'report contains a json block');
  const parsed = JSON.parse(block[1]);
  assert.deepStrictEqual(parsed, { allowScripts: { 'bad@1.0.0': false, 'ok@2.0.0': true } });
  assert.deepStrictEqual(parsed, buildAllowScripts(results));
  assert.ok(!md.includes('exec: a | b'), 'pipes escaped inside table cells');
});
