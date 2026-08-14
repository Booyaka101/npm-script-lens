'use strict';
// `doctor`: does npm-script-lens still understand your npm? Every high-value
// feature (review, allow, the v12 gap checks) couples to npm's own behavior;
// this command probes the local npm and reports, check by check, whether the
// contract this build assumes still holds. It is the human-facing half of the
// durability story, the npm-compat CI canary is the automated half, and both
// run exactly these checks.
//
// One function per check, each taking `add` and the probe context, so a new
// check is a new function plus one line in runDoctor.
const fs = require('node:fs');
const path = require('node:path');
const { npmFullVersion, npmDryRunPending, classifyDryRun } = require('./review');
const { resolveLockfile } = require('./lockfiles');
const { managerFor } = require('./pm-contract');
const { analyzeSources, checkSourceConfig, readSourceConfig, versionGte } = require('./sources');
const {
  MIN_ALLOWSCRIPTS_NPM, ALLOWSCRIPTS_FIELD, DRY_RUN_ARGS, UNREVIEWED_KEY,
  SAMPLE_DRY_RUN, SOURCES, DETECTORS, PUBLISH, enforcesAllowScripts,
} = require('./npm-contract');

const dirOf = (target) => {
  const resolved = path.resolve(target);
  return fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
};

function checkNpmVersion(add, { major }) {
  if (major === null) add('npm version', 'warn', 'could not run `npm --version`. Is npm on PATH? review/allow will use the lockfile fallback');
  else add('npm version', 'ok', `npm v${major} detected`);
}

// Which package manager's allowlist does `allow` target here?
function checkPackageManager(add, { target }) {
  try {
    const m = managerFor(resolveLockfile(target).type);
    add('package manager', 'ok', `detected ${m.label}, so allow targets ${m.nativeKey} in ${m.allowlistFile}`);
  } catch {
    add('package manager', 'info', 'no lockfile at this path, so allow defaults to npm (allowScripts in package.json)');
  }
}

function checkAllowScriptsEnforcement(add, { major }) {
  if (major === null) add('allowScripts enforcement', 'info', 'unknown (npm version undetermined)');
  else if (enforcesAllowScripts(major)) {
    add('allowScripts enforcement', 'ok', `npm v${major} enforces allowScripts (>= v${MIN_ALLOWSCRIPTS_NPM}): dependency install scripts are opt-in`);
  } else {
    add('allowScripts enforcement', 'info', `npm v${major} predates allowScripts (< v${MIN_ALLOWSCRIPTS_NPM}): install scripts still run implicitly. review/allow fall back to the lockfile`);
  }
}

// Prove this build still classifies the canonical shapes. If npm's real
// output diverges, the live probe catches it; if THIS fails, the build itself
// regressed.
function checkDryRunParser(add) {
  const p = classifyDryRun(SAMPLE_DRY_RUN.pending);
  const e = classifyDryRun(SAMPLE_DRY_RUN.empty);
  const ok = p.kind === 'pending' && p.pending.length === 1 && p.pending[0].name === 'sharp' && e.kind === 'empty';
  add('dry-run parser self-test', ok ? 'ok' : 'fail',
    ok ? 'recognizes the canonical unreviewedScripts payload and the omitted-key "nothing pending" summary'
      : `canonical samples misclassified (pending→${p.kind}, empty→${e.kind}), a build regression`);
}

// Only meaningful when npm actually enforces allowScripts. An unrecognized
// shape here is the real drift alarm.
async function checkLiveProbe(add, { projectDir, major, offline, live }) {
  if (!live) return add('live dry-run probe', 'info', 'skipped (--no-live)');
  if (offline) return add('live dry-run probe', 'info', 'skipped (--offline)');
  if (major === null || !enforcesAllowScripts(major)) {
    return add('live dry-run probe', 'info', `skipped, npm v${major === null ? '?' : major} does not enforce allowScripts`);
  }
  const res = await npmDryRunPending(projectDir);
  if (res && res.unrecognized) {
    return add('live dry-run probe', 'fail',
      `npm v${major} returned JSON from \`npm ${DRY_RUN_ARGS.join(' ')}\` but not a shape this build recognizes. npm-script-lens is likely out of date with your npm`);
  }
  if (res && res.pending) {
    return add('live dry-run probe', 'ok', `npm v${major} output recognized, ${res.pending.length} package(s) currently pending in ${projectDir}`);
  }
  return add('live dry-run probe', 'info', 'npm returned no recognizable pending list here (no installable project, or npm errored), not a drift signal on its own');
}

function checkProjectAllowlist(add, { projectDir }) {
  let count = 0;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
    count = pkg[ALLOWSCRIPTS_FIELD] ? Object.keys(pkg[ALLOWSCRIPTS_FIELD]).length : 0;
  } catch { /* no package.json here */ }
  add('project allowScripts', count > 0 ? 'ok' : 'info',
    count > 0 ? `package.json has ${count} ${ALLOWSCRIPTS_FIELD} entr${count === 1 ? 'y' : 'ies'}`
      : `no ${ALLOWSCRIPTS_FIELD} block in ${projectDir}/package.json. Run \`npm-script-lens allow --write\` to generate one`);
}

// npm v12's allow-git / allow-remote flips: counts and minimal values from the
// lockfile against the committed .npmrc, whether the local npm has the keys
// yet (minor precision: 11.10.0 / 11.15.0), and whether it is new enough for
// `root` to be trusted (npm 11 shipped npm/cli#9189). Returns the report's
// `sources` block.
async function checkSources(add, { target, major, fullVersion }) {
  let sources = null;
  try {
    const analysis = await analyzeSources(target, { probeNpm: false });
    const config = readSourceConfig(analysis.projectDir);
    const { failures } = checkSourceConfig(analysis, config);
    sources = {};
    for (const kind of ['git', 'remote']) {
      const { key } = SOURCES[kind];
      const a = analysis[kind];
      const committed = config[kind];
      sources[kind] = { count: a.deps.length, minimal: a.minimal, committed };
      const failure = failures.find((f) => f.source === kind);
      if (failure) add(`${key} config`, 'warn', failure.message);
      else if (a.deps.length === 0) add(`${key} config`, 'info', `no ${kind} dependencies in the lockfile, so the npm v${SOURCES.enforcedInNpm} default (${key}=${SOURCES.default}) is correct here`);
      else add(`${key} config`, 'ok', `${a.deps.length} ${kind} dependenc${a.deps.length === 1 ? 'y' : 'ies'}, and .npmrc ${key}=${committed} is the minimal correct value`);
      if (a.minimal === 'root' && major === SOURCES.enforcedInNpm - 1) {
        const d = DETECTORS.allowGitRoot;
        add(`${key}=root reliability`, 'warn',
          `npm v${major} wrongly rejected root-level git deps under ${key}=root (${d.issue}, ${d.upstream}${d.fixedInNpm ? `, fixed in npm v${d.fixedInNpm}` : '; fixed npm version not yet pinned'}). Prefer ${key}=all until your npm verifiably carries the fix`);
      }
    }
  } catch {
    add('dependency sources', 'info', 'no lockfile at this path, allow-git/allow-remote check skipped');
  }
  for (const kind of ['git', 'remote']) {
    const { key, introduced } = SOURCES[kind];
    if (fullVersion === null) add(`${key} support`, 'info', `npm version unknown, cannot tell whether ${key} is available (introduced in npm ${introduced})`);
    else if (versionGte(fullVersion, introduced)) add(`${key} support`, 'ok', `npm v${fullVersion} supports ${key} (introduced in npm ${introduced}; enforced by default from v${SOURCES.enforcedInNpm})`);
    else add(`${key} support`, 'info', `npm v${fullVersion} predates ${key} (introduced in npm ${introduced}). The setting takes effect after upgrading`);
  }
  return sources;
}

// Static CI-config analysis (src/publish.js), so these can only warn, never
// fail: a TOKEN path is a coming break, not tool drift. Returns the report's
// `publish` block.
function checkPublishReadiness(add, { target }) {
  try {
    const { analyzePublish } = require('./publish');
    const pub = analyzePublish(target);
    const c = pub.counts;
    const mix = `${c.TRUSTED} trusted, ${c.STAGED} staged, ${c.TOKEN} token, ${c.BROKEN} broken, ${c.UNKNOWN} unknown`;
    if (pub.paths.length === 0) {
      add('publish readiness', 'info', 'no publish steps found in CI configs (.github/workflows, .github/actions/**/action.yml, .gitlab-ci.yml, .circleci/config.yml), so nothing is exposed to the January 2027 token cliff');
    } else if (c.TOKEN > 0) {
      add('publish readiness', 'warn', `${c.TOKEN} of ${pub.paths.length} publish path(s) still authenticate with a long-lived token (${mix}). Direct token publishing ends around ${PUBLISH.cliff.date}; run \`npm-script-lens publish\` for the migration patch and the npmjs.com checklist`);
    } else if (c.BROKEN > 0) {
      add('publish readiness', 'warn', `${c.BROKEN} of ${pub.paths.length} publish path(s) intend trusted publishing but are BROKEN by setup-node (${mix}). Run \`npm-script-lens publish\` for the fixes`);
    } else {
      add('publish readiness', 'ok', `${pub.paths.length} publish path(s): ${mix}. No long-lived token publishing, ready for the ${PUBLISH.cliff.date} change`);
    }
    for (const p of pub.paths) {
      if (p.classification === 'BROKEN' && p.setupNode) {
        add('publish oidc', 'warn', `${p.file}:${p.line} grants id-token: write, but actions/setup-node@${p.setupNode.ref} (${p.setupNode.file}:${p.setupNode.line}) with registry-url writes a dummy _authToken that breaks the OIDC exchange, fixed in setup-node v${PUBLISH.oidc.setupNodeFixedIn}`);
      }
    }
    if (pub.paths.length > 0) addGateSummary(add, pub.gates);
    for (const p of pub.paths) {
      if (p.nodeBelowFloor) {
        add('publish node floor', 'warn', `${p.nodeVersionFile || p.file}:${p.nodeVersionLine || p.line} pins node-version ${p.nodeVersion}, below the Node ${PUBLISH.trusted.minNode} floor that both trusted publishing (npm >= ${PUBLISH.trusted.minNpm}) and staged publishing (npm >= ${PUBLISH.staged.minNpm}) require`);
      }
    }
    return { counts: c, gates: pub.gates, paths: pub.paths.length };
  } catch {
    add('publish readiness', 'info', 'could not analyze the CI configs at this path');
    return null;
  }
}

// Who can cause a publish to run today, one line for the whole repo.
function addGateSummary(add, g) {
  const mix = `${g.DANGEROUS} dangerous, ${g.REVIEWABLE} reviewable, ${g.MANUAL} manual, ${g.TAG} tag, ${g.AUTO} auto, ${g.UNKNOWN} unknown`;
  if (g.DANGEROUS > 0) {
    add('publish gates', 'warn', `${g.DANGEROUS} publish path(s) reachable from ${PUBLISH.gates.dangerousTriggers.join('/')}, triggers crates.io removed from Trusted Publishing (${mix}). Run \`npm-script-lens publish\` for the fix`);
  } else if (g.AUTO > 0) {
    add('publish gates', 'warn', `${g.AUTO} publish path(s) run on a plain branch push, schedule or PR with no environment approval (${mix}). A ChainDrop-style account takeover publishes with no human gate; run \`npm-script-lens publish\` for the fix ladder`);
  } else {
    add('publish gates', 'ok', `release gates: ${mix}. No publish path is auto-reachable from a branch push`);
  }
}

// The keyv/ChainDrop worm's persistence layer (2026-08-04): folderOpen tasks
// and Claude Code hooks fire when the folder is opened, before any install
// step the other checks gate.
function checkOpenTimeHooks(add, { projectDir }) {
  try {
    const { scanProject } = require('./hooks');
    const scan = scanProject(projectDir);
    const auto = scan.findings.filter((f) => f.auto && f.kind === 'command');
    if (auto.length > 0) {
      add('open-time hooks', 'warn', `${auto.length} auto-run entr${auto.length === 1 ? 'y' : 'ies'} in the working tree (.vscode/tasks.json folderOpen tasks / .claude/settings.json hooks). Inspect with \`npm-script-lens hooks\``);
    } else if (scan.partials.length > 0) {
      add('open-time hooks', 'warn', `${scan.partials.length} surface file(s) did not parse. Inspect with \`npm-script-lens hooks\``);
    } else {
      add('open-time hooks', 'ok', 'no folderOpen tasks or auto-firing Claude Code command hooks in the working tree (`hooks --deps` also checks dependency tarballs)');
    }
  } catch {
    add('open-time hooks', 'info', 'could not scan the working tree for open-time execution surfaces');
  }
}

// What this build assumes, and how current each npm-bug detector is.
function addContractSummary(add) {
  add('assumed contract', 'info',
    `field=${ALLOWSCRIPTS_FIELD} · dry-run=\`npm ${DRY_RUN_ARGS.join(' ')}\` · key=${UNREVIEWED_KEY} · min npm=v${MIN_ALLOWSCRIPTS_NPM}`);
  for (const d of Object.values(DETECTORS)) {
    add(`detector ${d.id}`, 'info', `${d.issue}, ${d.upstream}`
      + (d.fixedInNpm ? ` (fixed in npm v${d.fixedInNpm}${d.note ? `; ${d.note}` : ''})`
        : ' (fixed-version not yet pinned, verify against your npm)'));
  }
}

// status: 'ok' (contract holds) · 'warn' (couldn't verify) · 'info' (context)
// · 'fail' (genuine drift, the contract this build assumes no longer matches
//   reality; only 'fail' sets a non-zero exit).
async function runDoctor({ path: target = '.', offline = false, live = true } = {}) {
  const checks = [];
  const add = (name, status, detail) => checks.push({ name, status, detail });
  const projectDir = dirOf(target);
  const fullVersion = await npmFullVersion(projectDir);
  const major = fullVersion ? parseInt(fullVersion.split('.')[0], 10) : null;
  const ctx = { target, projectDir, fullVersion, major, offline, live };

  checkNpmVersion(add, ctx);
  checkPackageManager(add, ctx);
  checkAllowScriptsEnforcement(add, ctx);
  checkDryRunParser(add);
  await checkLiveProbe(add, ctx);
  checkProjectAllowlist(add, ctx);
  const sources = await checkSources(add, ctx);
  const publish = checkPublishReadiness(add, ctx);
  checkOpenTimeHooks(add, ctx);
  addContractSummary(add);

  const failed = checks.some((c) => c.status === 'fail');
  return { tool: 'npm-script-lens', npmMajor: major, npmVersion: fullVersion, ok: !failed, sources, publish, checks };
}

const ICON = { ok: '✅', warn: '⚠️ ', info: 'ℹ️ ', fail: '❌' };

function renderDoctor(report) {
  const lines = ['npm-script-lens doctor: npm compatibility check', ''];
  for (const c of report.checks) lines.push(`${ICON[c.status] || '·'} ${c.name}: ${c.detail}`);
  lines.push('', report.ok
    ? '✅ No drift detected. This build understands your npm.'
    : '❌ Drift detected. npm-script-lens may be out of date with your npm. See the ❌ line(s) above.');
  return lines.join('\n');
}

module.exports = { runDoctor, renderDoctor };
