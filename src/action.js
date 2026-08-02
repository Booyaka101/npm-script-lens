'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { runAudit, ciCheckResult } = require('./cli');
const { resolveLockfile } = require('./lockfiles');
const { buildReport, buildSarif, buildManifest, serializeManifest, diffManifests, packageRisk, buildGapsReport } = require('./reporter');
const { checkV12Gaps } = require('./v12gaps');

// POST the report as a PR comment via the GitHub REST API (the same
// issues.createComment call octokit makes, sans the dependency).
async function commentOnPr(body) {
  const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const pr = event.pull_request && event.pull_request.number;
  if (!pr) return console.log('not a pull_request event; skipping comment');
  if (body.length > 60000) {
    body = `${body.slice(0, 60000)}\n\n…_report truncated (GitHub comment size limit); full version in the job summary._`;
  }
  const api = process.env.GITHUB_API_URL || 'https://api.github.com';
  const res = await fetch(`${api}/repos/${process.env.GITHUB_REPOSITORY}/issues/${pr}/comments`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ body }),
  });
  if (!res.ok) console.log(`::warning::PR comment failed: HTTP ${res.status} ${await res.text()}`);
  else console.log(`posted audit comment on PR #${pr}`);
}

async function main() {
  const input = (name, dflt) => process.env[`INPUT_${name}`] || dflt;
  const target = input('PATH', '.');
  const diffBase = input('DIFF_BASE', '') || null;
  const results = await runAudit(target, {
    log: console.log,
    diffBase,
    trust: input('TRUST', 'true') === 'true',
    deep: input('DEEP', 'false') === 'true',
  });
  const note = diffBase
    ? `_Diff mode: only packages added or upgraded relative to \`${diffBase}\` were audited._`
    : undefined;
  const report = buildReport(results, { note });
  console.log(report);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${report}\n`);
  const sarifFile = input('SARIF_FILE', '');
  if (sarifFile) {
    const { path: lp } = resolveLockfile(target);
    let rel = path.relative(process.cwd(), lp).replace(/\\/g, '/');
    if (rel.startsWith('..')) rel = path.basename(lp);
    fs.writeFileSync(sarifFile,
      JSON.stringify(buildSarif(results, { lockPath: rel, lockText: fs.readFileSync(lp, 'utf8') }), null, 2));
    console.log(`SARIF written to ${sarifFile}`);
  }
  if (input('COMMENT_ON_PR', 'true') === 'true' && process.env.GITHUB_EVENT_PATH && process.env.GITHUB_TOKEN) {
    await commentOnPr(report);
  }
  const bad = results.filter((r) => r.malicious || packageRisk(r) === 'HIGH').length;
  if (input('FAIL_ON_HIGH', 'true') === 'true' && bad > 0) {
    console.log(`::error::${bad} package(s) with HIGH risk or known-malicious install scripts`);
    process.exitCode = 1;
  }
  // manifest-check: fail when the committed behavior receipt is stale
  if (input('MANIFEST_CHECK', 'false') === 'true') {
    const { path: lp } = resolveLockfile(target);
    const file = path.join(path.dirname(lp), input('MANIFEST_FILE', 'script-lens.json'));
    const { manifest } = buildManifest(results, { deep: input('DEEP', 'false') === 'true' });
    const json = serializeManifest(manifest);
    if (!fs.existsSync(file)) {
      console.log(`::error::no audit manifest at ${file} — run: npx npm-script-lens manifest --write`);
      process.exitCode = 1;
    } else if (fs.readFileSync(file, 'utf8') !== json) {
      let parsed; try { parsed = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { parsed = {}; }
      const drift = diffManifests(parsed, manifest);
      console.log('::error::audit manifest is out of date — install-time behavior changed');
      for (const line of drift) console.log(`::warning::${line}`);
      if (process.env.GITHUB_STEP_SUMMARY) {
        fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,
          `\n## ⚠️ Audit manifest out of date\n\n${drift.map((l) => `- \`${l}\``).join('\n')}\n\nRun \`npx npm-script-lens manifest --write\` and commit \`${input('MANIFEST_FILE', 'script-lens.json')}\`.\n`);
      }
      process.exitCode = 1;
    } else {
      console.log('audit manifest up to date');
    }
  }
}

// `node action.js v12-gaps` — the separate Action step that runs when the
// runner's npm is v12+: report the approve-scripts gap findings to the job
// summary, annotate with ::warning (severity is warn, never fails the job),
// and fold them into the SARIF file the audit step already wrote.
async function v12GapsMain() {
  const input = (name, dflt) => process.env[`INPUT_${name}`] || dflt;
  const target = input('PATH', '.');
  const { findings, npmMajor, npmVersion } = await checkV12Gaps(target, { log: console.log });
  const report = buildGapsReport(findings, { npmMajor, npmVersion });
  console.log(report);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `\n${report}\n`);
  for (const f of findings) {
    const at = f.file ? ` (${f.file}:${f.line})` : '';
    console.log(`::warning::${f.id}: ${f.package}${at} — ${f.fix}`);
  }
  const sarifFile = input('SARIF_FILE', '');
  if (sarifFile && findings.length > 0 && fs.existsSync(sarifFile)) {
    const { path: lp } = resolveLockfile(target);
    let rel = path.relative(process.cwd(), lp).replace(/\\/g, '/');
    if (rel.startsWith('..')) rel = path.basename(lp);
    const fresh = buildSarif([], { lockPath: rel, lockText: fs.readFileSync(lp, 'utf8'), findings });
    const sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
    const run = sarif.runs && sarif.runs[0];
    if (run) {
      const have = new Set((run.tool.driver.rules || []).map((r) => r.id));
      run.tool.driver.rules = run.tool.driver.rules || [];
      for (const rule of fresh.runs[0].tool.driver.rules) {
        if (!have.has(rule.id)) run.tool.driver.rules.push(rule);
      }
      run.results = run.results || [];
      run.results.push(...fresh.runs[0].results);
      fs.writeFileSync(sarifFile, JSON.stringify(sarif, null, 2));
      console.log(`merged ${findings.length} v12 gap finding(s) into ${sarifFile}`);
    }
  }
}

// `node action.js ci-check` — the fail-fast gate step (opt-in via the
// `ci-check` input). Fails the job when npm v12 would silently disable every
// dependency's install scripts: a workflow runs npm install, package.json has
// no allowScripts block, and the runner's npm is v12+. No scan.
async function ciCheckMain() {
  const input = (name, dflt) => process.env[`INPUT_${name}`] || dflt;
  const target = input('PATH', '.');
  const resolved = path.resolve(target);
  const projectDir = fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
  const { willBreak, reason } = await ciCheckResult(projectDir);
  if (willBreak) {
    const msg = 'CI will break on npm v12: dependency install scripts are disabled by default and '
      + 'package.json has no allowScripts block. Run `npx npm-script-lens allow --write` to generate one.';
    console.log(`::error::${msg}`);
    if (process.env.GITHUB_STEP_SUMMARY) {
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `\n## ❌ npm v12 allowScripts check\n\n${msg}\n`);
    }
    process.exitCode = 1;
    return;
  }
  console.log(`npm v12 allowScripts check passed: ${reason}.`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `\n## ✅ npm v12 allowScripts check\n\nPassed: ${reason}.\n`);
  }
}

// `node action.js sources-check` — opt-in gate (the `sources-check` input):
// fails the job when the committed .npmrc allow-git/allow-remote is
// insufficient, over-permissive, or invalid for the git/remote dependencies
// actually in the lockfile — npm v12 refuses to resolve uncovered ones.
async function sourcesCheckMain() {
  const input = (name, dflt) => process.env[`INPUT_${name}`] || dflt;
  const target = input('PATH', '.');
  const { analyzeSources, checkSourceConfig, readSourceConfig } = require('./sources');
  const { SOURCES } = require('./npm-contract');
  let analysis;
  try {
    analysis = await analyzeSources(target, { probeNpm: false });
  } catch (err) {
    console.log(`npm v12 git/remote dependency check skipped: ${err.message}`);
    return;
  }
  const counts = `${analysis.git.deps.length} git dep(s) (minimal ${SOURCES.git.key}=${analysis.git.minimal}) · ${analysis.remote.deps.length} remote dep(s) (minimal ${SOURCES.remote.key}=${analysis.remote.minimal})`;
  if (analysis.lockType !== 'npm') {
    console.log(`npm v12 git/remote dependency check: ${counts} — .npmrc check skipped (npm-only; this is a ${analysis.lockType} lockfile)`);
    return;
  }
  const { ok, failures } = checkSourceConfig(analysis, readSourceConfig(analysis.projectDir));
  if (ok) {
    console.log(`npm v12 git/remote dependency check passed: ${counts}`);
    if (process.env.GITHUB_STEP_SUMMARY) {
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `\n## ✅ npm v12 git/remote dependency check\n\n${counts} — .npmrc matches.\n`);
    }
    return;
  }
  for (const f of failures) console.log(`::error::${f.message}`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,
      `\n## ❌ npm v12 git/remote dependency check\n\n${counts}\n\n${failures.map((f) => `- **${f.kind}**: ${f.message}`).join('\n')}\n\nRun \`npx npm-script-lens sources --write\` and commit the updated \`.npmrc\`.\n`);
  }
  process.exitCode = 1;
}

// `node action.js publish-check` — opt-in gate (the `publish-check` input):
// fails the job when a CI publish path still authenticates with a long-lived
// npm token, which loses direct publish around January 2027. TOKEN paths get
// an ::error each and a publish-token-cliff SARIF result merged into the file
// the audit step wrote; UNKNOWN paths and no-publish repos pass.
async function publishCheckMain() {
  const input = (name, dflt) => process.env[`INPUT_${name}`] || dflt;
  const target = input('PATH', '.');
  const { analyzePublish, checkPublish, publishFindings } = require('./publish');
  const { PUBLISH } = require('./npm-contract');
  let analysis;
  try {
    analysis = await analyzePublish(target);
  } catch (err) {
    console.log(`npm token-cliff publish check skipped: ${err.message}`);
    return;
  }
  const { ok, reason, failures } = checkPublish(analysis);
  if (ok) {
    console.log(`npm token-cliff publish check passed: ${reason}.`);
    if (process.env.GITHUB_STEP_SUMMARY) {
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `\n## ✅ npm token-cliff publish check\n\nPassed: ${reason}.\n`);
    }
    return;
  }
  for (const f of failures) console.log(`::error::${f.message}`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,
      `\n## ❌ npm token-cliff publish check\n\nDirect token publishing ends around **${PUBLISH.cliff.date}** (${PUBLISH.cliff.changelog}).\n\n${failures.map((f) => `- ${f.message}`).join('\n')}\n\nRun \`npx npm-script-lens publish\` for the migration patch and the pre-filled npmjs.com trusted-publisher checklist.\n`);
  }
  const sarifFile = input('SARIF_FILE', '');
  const findings = publishFindings(analysis);
  if (sarifFile && findings.length > 0 && fs.existsSync(sarifFile)) {
    const sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
    const run = sarif.runs && sarif.runs[0];
    if (run) {
      const fresh = buildSarif([], { lockPath: 'package.json', lockText: '', findings });
      const have = new Set((run.tool.driver.rules || []).map((r) => r.id));
      run.tool.driver.rules = run.tool.driver.rules || [];
      for (const rule of fresh.runs[0].tool.driver.rules) {
        if (!have.has(rule.id)) run.tool.driver.rules.push(rule);
      }
      run.results = run.results || [];
      run.results.push(...fresh.runs[0].results);
      fs.writeFileSync(sarifFile, JSON.stringify(sarif, null, 2));
      console.log(`merged ${findings.length} publish-token-cliff finding(s) into ${sarifFile}`);
    }
  }
  process.exitCode = 1;
}

const MODE = { 'v12-gaps': v12GapsMain, 'ci-check': ciCheckMain, 'sources-check': sourcesCheckMain, 'publish-check': publishCheckMain };
(MODE[process.argv[2]] || main)().catch((err) => {
  console.log(`::error::${err.message}`);
  process.exitCode = 2;
});
