'use strict';
// `review`: the missing half of npm v12's approval flow. npm's own pending
// list (`npm approve-scripts --allow-scripts-pending`, or `unreviewedScripts`
// in `npm install --dry-run --json`) shows script COMMANDS ("node
// install/check") but never the content of the files those commands run
// (github.com/orgs/community/discussions/198547). This module detects the
// pending set; cli.js renders the content plus the scan verdict.
const { spawn } = require('node:child_process');

// npm v12's `install --dry-run --json` ends with a JSON object carrying
// unreviewedScripts: [{name, version, path, scripts}] — and OMITS the key
// entirely when nothing is pending (verified against npm 12.0.1). Human
// "add pkg 1.2.3" lines precede the JSON on stdout, and the very first run in
// a directory can exit non-zero — so scan forward to the JSON and ignore the
// exit code. Returns the pending list, [] for a successful summary without
// the key (nothing pending — only meaningful when the caller has confirmed
// npm >= 12), or null for error/garbage output.
function parseDryRun(text) {
  let i = text.indexOf('{');
  while (i !== -1) {
    try {
      const j = JSON.parse(text.slice(i));
      if (Array.isArray(j.unreviewedScripts)) {
        return j.unreviewedScripts
          .filter((u) => u && u.name && u.version)
          .map((u) => ({ name: u.name, version: u.version, scripts: u.scripts || {} }));
      }
      if (!j.error && (typeof j.added === 'number' || typeof j.audited === 'number')) return [];
      return null;
    } catch { i = text.indexOf('{', i + 1); }
  }
  return null;
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

// Ask the project's npm what is pending. NPM_SCRIPT_LENS_NPM overrides the
// npm command (tests, alternate npms). Resolves { pending } when the local
// npm is v12+ and the dry-run succeeded (pending may be empty — that is a
// definitive "nothing pending"), null when npm cannot answer (npm < 12 — the
// dry-run is skipped entirely, its output would be meaningless — or spawn
// failure/timeout/error output).
async function npmDryRunPending(cwd, { timeoutMs = 180000 } = {}) {
  const npmCmd = process.env.NPM_SCRIPT_LENS_NPM || 'npm';
  const ver = await runCmd(`${npmCmd} --version`, cwd, 30000);
  const m = ver && ver.out.match(/(\d+)\.\d+\.\d+/);
  if (!m || parseInt(m[1], 10) < 12) return null;
  const res = await runCmd(`${npmCmd} install --dry-run --json`, cwd, timeoutMs);
  if (!res) return null;
  const pending = parseDryRun(res.out);
  return pending === null ? null : { pending };
}

// npm v12 counts either allowScripts key form as a decision — bare name or
// name@version, true or false (verified against npm 12.0.1).
const isCovered = (allow, name, version) => name in allow || `${name}@${version}` in allow;

module.exports = { parseDryRun, npmDryRunPending, isCovered };
