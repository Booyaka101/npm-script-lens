'use strict';
// `review`: the missing half of npm v12's approval flow. npm's own pending
// list (`npm approve-scripts --allow-scripts-pending`, or `unreviewedScripts`
// in `npm install --dry-run --json`) shows script COMMANDS ("node
// install/check") but never the content of the files those commands run
// (github.com/orgs/community/discussions/198547). This module detects the
// pending set; cli.js renders the content plus the scan verdict.
const { spawn } = require('node:child_process');
const { DRY_RUN_ARGS, UNREVIEWED_KEY, SUMMARY_KEYS, MIN_ALLOWSCRIPTS_NPM } = require('./npm-contract');

// Classify npm's `install --dry-run --json` output. npm v12's object carries
// unreviewedScripts: [{name, version, path, scripts}], and OMITS the key
// entirely when nothing is pending (verified against npm 12.0.1). Human "add
// pkg 1.2.3" lines precede the JSON on stdout, and the first run in a dir can
// exit non-zero, so scan forward to the JSON and ignore the exit code.
// Returns one of:
//   { kind: 'pending',      pending: [...] }, packages awaiting a decision
//   { kind: 'empty',        pending: [] }, successful summary, none pending
//   { kind: 'error',        pending: null }: npm errored / no JSON / garbage
//   { kind: 'unrecognized', pending: null }, got JSON, but not a shape we
//                                               know: the loud drift signal
function classifyDryRun(text) {
  let i = text.indexOf('{');
  let sawJson = false;
  while (i !== -1) {
    let j;
    try { j = JSON.parse(text.slice(i)); } catch { i = text.indexOf('{', i + 1); continue; }
    sawJson = true;
    if (j && typeof j === 'object' && !Array.isArray(j)) {
      if (Array.isArray(j[UNREVIEWED_KEY])) {
        const pending = j[UNREVIEWED_KEY]
          .filter((u) => u && u.name && u.version)
          .map((u) => ({ name: u.name, version: u.version, scripts: u.scripts || {} }));
        return { kind: pending.length ? 'pending' : 'empty', pending };
      }
      if (UNREVIEWED_KEY in j) return { kind: 'unrecognized', pending: null }; // key exists, wrong type
      if (j.error) return { kind: 'error', pending: null };
      if (SUMMARY_KEYS.some((k) => typeof j[k] === 'number')) return { kind: 'empty', pending: [] };
      return { kind: 'unrecognized', pending: null }; // valid JSON, unfamiliar
    }
    return { kind: 'unrecognized', pending: null };
  }
  return { kind: sawJson ? 'unrecognized' : 'error', pending: null };
}

// Back-compatible thin wrapper: the pending array for a recognized answer
// (possibly empty), null for error/unrecognized.
function parseDryRun(text) {
  const { kind, pending } = classifyDryRun(text);
  return kind === 'pending' || kind === 'empty' ? pending : null;
}

// Bare command name + shell:true is the only spawn form that resolves npm's
// .cmd shim on Windows. Never rejects: null on spawn failure.
function runCmd(cmd, cwd, timeoutMs) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, [], { cwd, shell: true, timeout: timeoutMs });
    } catch { return resolve(null); }
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('error', () => resolve(null));
    child.on('exit', (code) => resolve({ code, out }));
  });
}

// The local npm's full version ("11.16.1"), or null when it cannot be
// determined. NPM_SCRIPT_LENS_NPM overrides the command (tests, alternate
// npms). The allow-git/allow-remote support checks need minor precision
// (introduced in 11.10.0 / 11.15.0), which the major alone can't answer.
async function npmFullVersion(cwd) {
  const npmCmd = process.env.NPM_SCRIPT_LENS_NPM || 'npm';
  const ver = await runCmd(`${npmCmd} --version`, cwd, 30000);
  const m = ver && ver.out.match(/(\d+\.\d+\.\d+)/);
  return m ? m[1] : null;
}

// The local npm's major version, or null when it cannot be determined.
async function npmMajorVersion(cwd) {
  const full = await npmFullVersion(cwd);
  return full ? parseInt(full.split('.')[0], 10) : null;
}

// Ask the project's npm what is pending. Resolves:
//   { pending }             when npm is v12+ and the shape was recognized
//                           (pending may be empty, a definitive "nothing
//                           pending")
//   { unrecognized, npmMajor } when npm is v12+ but its output shape drifted
//                           from what we parse, the caller warns and falls
//                           back instead of silently trusting an empty answer
//   null                    when npm < 12 (dry-run skipped, its output would
//                           be meaningless) or spawn failure/timeout/error
async function npmDryRunPending(cwd, { timeoutMs = 180000 } = {}) {
  const major = await npmMajorVersion(cwd);
  if (major === null || major < MIN_ALLOWSCRIPTS_NPM) return null;
  const npmCmd = process.env.NPM_SCRIPT_LENS_NPM || 'npm';
  const res = await runCmd(`${npmCmd} ${DRY_RUN_ARGS.join(' ')}`, cwd, timeoutMs);
  if (!res) return null;
  const { kind, pending } = classifyDryRun(res.out);
  if (kind === 'pending' || kind === 'empty') return { pending };
  if (kind === 'unrecognized') return { unrecognized: true, npmMajor: major };
  return null;
}

// npm v12 counts either allowScripts key form as a decision, bare name or
// name@version, true or false (verified against npm 12.0.1).
const isCovered = (allow, name, version) => name in allow || `${name}@${version}` in allow;

module.exports = { classifyDryRun, parseDryRun, npmDryRunPending, npmMajorVersion, npmFullVersion, isCovered };
