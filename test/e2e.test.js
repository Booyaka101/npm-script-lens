'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { fetchPackage } = require('../src/registry');
const { analyzePackage } = require('../src/analyzer');

const ROOT = path.join(__dirname, '..');

test('acceptance: sharp@0.33.5 is HIGH with exec: node-gyp rebuild', async () => {
  const rows = analyzePackage(await fetchPackage('sharp', '0.33.5'));
  const install = rows.find((r) => r.script === 'install');
  assert.strictEqual(install.risk, 'HIGH');
  assert.ok(install.signals.some((s) => s.includes('exec: node-gyp rebuild')), JSON.stringify(install.signals));
});

test('acceptance: chalk@5.3.0 is SAFE (no lifecycle scripts)', async () => {
  const rows = analyzePackage(await fetchPackage('chalk', '5.3.0'));
  assert.strictEqual(rows.length, 0);
});

test('acceptance: prisma@5 chain surfaces its network capability', async () => {
  const engines = analyzePackage(await fetchPackage('@prisma/engines', '5.22.0'));
  const post = engines.find((r) => r.script === 'postinstall');
  assert.ok(post.signals.some((s) => s.startsWith('net: ')), JSON.stringify(post.signals));
  const prisma = analyzePackage(await fetchPackage('prisma', '5.22.0'));
  assert.ok(['SAFE', 'LOW'].includes(prisma.find((r) => r.script === 'preinstall').risk));
});

test('acceptance: action exits 1 on HIGH, posts PR comment, valid allowScripts', async () => {
  const received = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      received.push({ url: req.url, auth: req.headers.authorization, body });
      res.writeHead(201, { 'content-type': 'application/json' }).end('{"id":1}');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-'));
  const eventPath = path.join(tmp, 'event.json');
  const summaryPath = path.join(tmp, 'summary.md');
  const sarifPath = path.join(tmp, 'audit.sarif');
  fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 7 } }));
  fs.writeFileSync(summaryPath, '');
  // async spawn: the mock server above must keep serving while the child runs
  const child = spawn(process.execPath, [path.join(ROOT, 'src', 'action.js')], {
    timeout: 180000,
    env: {
      ...process.env,
      INPUT_PATH: path.join(ROOT, 'fixtures', 'demo'),
      INPUT_FAIL_ON_HIGH: 'true',
      INPUT_COMMENT_ON_PR: 'true',
      INPUT_SARIF_FILE: sarifPath,
      GITHUB_EVENT_PATH: eventPath,
      GITHUB_STEP_SUMMARY: summaryPath,
      GITHUB_REPOSITORY: 'octo/demo',
      GITHUB_TOKEN: 'test-token',
      GITHUB_API_URL: `http://127.0.0.1:${server.address().port}`,
    },
  });
  let stdout = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stdout += d; });
  const status = await new Promise((r) => child.on('exit', r));
  server.close();
  assert.strictEqual(status, 1, stdout);
  assert.ok(stdout.includes('::error::'), 'emits workflow error annotation');
  assert.strictEqual(received.length, 1);
  assert.strictEqual(received[0].url, '/repos/octo/demo/issues/7/comments');
  assert.strictEqual(received[0].auth, 'Bearer test-token');
  const comment = JSON.parse(received[0].body).body;
  const block = comment.match(/```json\n([\s\S]*?)\n```/);
  const allow = JSON.parse(block[1]).allowScripts;
  assert.strictEqual(allow['sharp@0.33.5'], false);
  assert.strictEqual(allow['core-js@3.38.1'], true);
  assert.ok(fs.readFileSync(summaryPath, 'utf8').includes('# npm-script-lens report'));
  const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
  assert.ok(sarif.runs[0].results.some((r) => r.level === 'error'), 'sharp/prisma HIGH appear as SARIF errors');
});
