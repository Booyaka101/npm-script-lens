#!/usr/bin/env node
'use strict';
// npm-compat canary: the automated half of the durability story. Unlike the
// unit tests (which drive STUB npms), this drives the REAL npm on the runner
// against a real scratch project, so a genuine upstream change to
// `npm install --dry-run --json`, the shape `review`/`doctor` depend on,
// turns this red. Run by .github/workflows/npm-compat.yml across a matrix of
// npm versions (12 / latest / next); intended to be run manually too.
//
// Exit 0 = this build still understands the runner's npm. Exit 1 = drift
// (doctor flagged an unrecognized shape). Investigate before users do.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');

function run(args) {
  return execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
}

function main() {
  const npmVer = execFileSync('npm', ['--version'], { encoding: 'utf8', shell: process.platform === 'win32' }).trim();
  console.log(`# npm-compat canary, runner npm v${npmVer}`);

  // A real project with a real scripted dependency (core-js runs a postinstall,
  // pure JS, no native build) so npm's pending list is actually exercised.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-canary-'));
  fs.writeFileSync(path.join(dir, 'package.json'), `${JSON.stringify({
    name: 'lens-canary', version: '1.0.0', dependencies: { 'core-js': '3.38.1' },
  }, null, 2)}\n`);

  let failed = false;

  // 1. doctor: the authoritative drift verdict.
  const report = JSON.parse(run(['doctor', '--path', dir, '--json']));
  console.log(`\n## doctor (npmMajor=${report.npmMajor}, ok=${report.ok})`);
  for (const c of report.checks) console.log(`  [${c.status}] ${c.name}: ${c.detail}`);
  const drift = report.checks.filter((c) => c.status === 'fail');
  if (drift.length > 0) {
    failed = true;
    console.error(`\n::error::npm-compat drift: doctor flagged ${drift.length} unrecognized-shape check(s) on npm v${npmVer}`);
  }

  // 2. When npm enforces allowScripts, doctor's live probe must have actually
  // RECOGNIZED the shape (ok), not silently degraded to info.
  if (typeof report.npmMajor === 'number' && report.npmMajor >= 12) {
    const probe = report.checks.find((c) => c.name === 'live dry-run probe');
    if (!probe || probe.status !== 'ok') {
      failed = true;
      console.error(`::error::npm v${report.npmMajor} enforces allowScripts but the live dry-run probe did not recognize its output (status=${probe && probe.status}), likely drift`);
    }
    // 3. Ground truth: core-js has a postinstall and nothing is approved, so a
    // v12+ npm MUST report it pending. review going through the dry-run path
    // and NOT listing core-js means the key was renamed while keeping the
    // summary (the byte-ambiguous drift the shape parser cannot catch alone).
    const rev = JSON.parse(run(['review', '--path', dir, '--json', '--no-trust']));
    console.log(`\n## review source: ${rev.source}, ${rev.pending.length} pending`);
    if (!/dry-run/.test(rev.source)) {
      failed = true;
      console.error(`::error::review did not use the npm v12 dry-run path on npm v${report.npmMajor} (source: ${rev.source}), so the pending-set parser may be out of date`);
    } else if (!rev.pending.some((p) => p.name === 'core-js')) {
      failed = true;
      console.error(`::error::npm v${report.npmMajor} dry-run did NOT report the planted scripted dep core-js as pending, so its pending list shape likely changed (renamed key?)`);
    }
  }

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n${failed ? '❌ npm-compat canary FAILED, see ::error lines' : '✅ npm-compat canary passed: build understands this npm'}`);
  process.exit(failed ? 1 : 0);
}

try {
  main();
} catch (err) {
  console.error(`::error::npm-compat canary crashed: ${err.message}`);
  process.exit(1);
}
