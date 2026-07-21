'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { runAudit } = require('./cli');
const { resolveLockfile } = require('./lockfiles');
const { buildReport, buildSarif, packageRisk } = require('./reporter');

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
  const results = await runAudit(target, { log: console.log, diffBase });
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
  const high = results.filter((r) => packageRisk(r) === 'HIGH').length;
  if (input('FAIL_ON_HIGH', 'true') === 'true' && high > 0) {
    console.log(`::error::${high} package(s) with HIGH risk install scripts`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.log(`::error::${err.message}`);
  process.exitCode = 2;
});
