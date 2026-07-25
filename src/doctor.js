'use strict';
// `doctor`: does npm-script-lens still understand your npm? Every high-value
// feature (review, allow, the v12 gap checks) couples to npm's own behavior;
// this command probes the local npm and reports, check by check, whether the
// contract this build assumes still holds. It is the human-facing half of the
// durability story — the npm-compat CI canary is the automated half, and both
// run exactly these checks.
const fs = require('node:fs');
const path = require('node:path');
const { npmMajorVersion, npmDryRunPending, classifyDryRun } = require('./review');
const { resolveLockfile } = require('./lockfiles');
const { managerFor } = require('./pm-contract');
const {
  MIN_ALLOWSCRIPTS_NPM, ALLOWSCRIPTS_FIELD, DRY_RUN_ARGS, UNREVIEWED_KEY,
  SAMPLE_DRY_RUN, DETECTORS, enforcesAllowScripts,
} = require('./npm-contract');

const dirOf = (target) => {
  const resolved = path.resolve(target);
  return fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
};

// status: 'ok' (contract holds) · 'warn' (couldn't verify) · 'info' (context)
// · 'fail' (genuine drift — the contract this build assumes no longer matches
//   reality; only 'fail' sets a non-zero exit).
async function runDoctor({ path: target = '.', offline = false, live = true } = {}) {
  const checks = [];
  const add = (name, status, detail) => checks.push({ name, status, detail });
  const projectDir = dirOf(target);

  const major = await npmMajorVersion(projectDir);
  if (major === null) add('npm version', 'warn', 'could not run `npm --version` — is npm on PATH? review/allow will use the lockfile fallback');
  else add('npm version', 'ok', `npm v${major} detected`);

  // Which package manager's allowlist does `allow` target here?
  try {
    const m = managerFor(resolveLockfile(target).type);
    add('package manager', 'ok', `detected ${m.label} — allow targets ${m.nativeKey} in ${m.allowlistFile}`);
  } catch {
    add('package manager', 'info', 'no lockfile at this path — allow defaults to npm (allowScripts in package.json)');
  }

  if (major === null) add('allowScripts enforcement', 'info', 'unknown — npm version undetermined');
  else if (enforcesAllowScripts(major)) {
    add('allowScripts enforcement', 'ok', `npm v${major} enforces allowScripts (>= v${MIN_ALLOWSCRIPTS_NPM}): dependency install scripts are opt-in`);
  } else {
    add('allowScripts enforcement', 'info', `npm v${major} predates allowScripts (< v${MIN_ALLOWSCRIPTS_NPM}): install scripts still run implicitly. review/allow fall back to the lockfile`);
  }

  // Parser self-test: prove this build still classifies the canonical shapes.
  // If npm's real output diverges, the live probe below catches it; if THIS
  // fails, the build itself regressed.
  const p = classifyDryRun(SAMPLE_DRY_RUN.pending);
  const e = classifyDryRun(SAMPLE_DRY_RUN.empty);
  const selfOk = p.kind === 'pending' && p.pending.length === 1 && p.pending[0].name === 'sharp' && e.kind === 'empty';
  add('dry-run parser self-test', selfOk ? 'ok' : 'fail',
    selfOk ? 'recognizes the canonical unreviewedScripts payload and the omitted-key "nothing pending" summary'
      : `canonical samples misclassified (pending→${p.kind}, empty→${e.kind}) — build regression`);

  // Live probe: only meaningful when npm actually enforces allowScripts. An
  // unrecognized shape here is the real drift alarm.
  if (!offline && live && major !== null && enforcesAllowScripts(major)) {
    const res = await npmDryRunPending(projectDir);
    if (res && res.unrecognized) {
      add('live dry-run probe', 'fail',
        `npm v${major} returned JSON from \`npm ${DRY_RUN_ARGS.join(' ')}\` but not a shape this build recognizes — npm-script-lens is likely out of date with your npm`);
    } else if (res && res.pending) {
      add('live dry-run probe', 'ok', `npm v${major} output recognized — ${res.pending.length} package(s) currently pending in ${projectDir}`);
    } else {
      add('live dry-run probe', 'info', 'npm returned no recognizable pending list here (no installable project, or npm errored) — not a drift signal on its own');
    }
  } else if (!live) {
    add('live dry-run probe', 'info', 'skipped (--no-live)');
  } else if (offline) {
    add('live dry-run probe', 'info', 'skipped (--offline)');
  } else {
    add('live dry-run probe', 'info', `skipped — npm v${major === null ? '?' : major} does not enforce allowScripts`);
  }

  // Project allowScripts block
  let hasAllow = false, count = 0;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
    count = pkg[ALLOWSCRIPTS_FIELD] ? Object.keys(pkg[ALLOWSCRIPTS_FIELD]).length : 0;
    hasAllow = count > 0;
  } catch { /* no package.json here */ }
  add('project allowScripts', hasAllow ? 'ok' : 'info',
    hasAllow ? `package.json has ${count} ${ALLOWSCRIPTS_FIELD} entr${count === 1 ? 'y' : 'ies'}`
      : `no ${ALLOWSCRIPTS_FIELD} block in ${projectDir}/package.json — run \`npm-script-lens allow --write\` to generate one`);

  // Contract summary + detector currency
  add('assumed contract', 'info',
    `field=${ALLOWSCRIPTS_FIELD} · dry-run=\`npm ${DRY_RUN_ARGS.join(' ')}\` · key=${UNREVIEWED_KEY} · min npm=v${MIN_ALLOWSCRIPTS_NPM}`);
  for (const d of Object.values(DETECTORS)) {
    add(`detector ${d.id}`, 'info', `${d.issue} — ${d.upstream}${d.fixedInNpm ? ` (fixed in npm v${d.fixedInNpm})` : ' (fixed-version not yet pinned — verify against your npm)'}`);
  }

  const failed = checks.some((c) => c.status === 'fail');
  return { tool: 'npm-script-lens', npmMajor: major, ok: !failed, checks };
}

const ICON = { ok: '✅', warn: '⚠️ ', info: 'ℹ️ ', fail: '❌' };

function renderDoctor(report) {
  const lines = ['npm-script-lens doctor — npm compatibility check', ''];
  for (const c of report.checks) lines.push(`${ICON[c.status] || '·'} ${c.name}: ${c.detail}`);
  lines.push('', report.ok
    ? '✅ No drift detected — this build understands your npm.'
    : '❌ Drift detected — npm-script-lens may be out of date with your npm. See the ❌ line(s) above.');
  return lines.join('\n');
}

module.exports = { runDoctor, renderDoctor };
