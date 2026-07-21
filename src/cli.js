#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { program } = require('commander');
const { fetchPackage } = require('./registry');
const { analyzePackage } = require('./analyzer');
const { loadDeps, resolveLockfile } = require('./lockfiles');
const { cacheGet, cacheSet } = require('./cache');
const { buildReport, buildAllowScripts, buildSarif, packageRisk } = require('./reporter');

async function runAudit(lockPath, { concurrency = 8, log = () => {}, cache = true, diffBase = null } = {}) {
  const { lockPath: p, deps: allDeps } = loadDeps(lockPath);
  let deps = allDeps;
  if (diffBase) {
    const baseKeys = new Set(loadDeps(diffBase).deps.map((d) => `${d.name}@${d.version}`));
    deps = allDeps.filter((d) => !baseKeys.has(`${d.name}@${d.version}`));
    log(`auditing ${deps.length} added/upgraded packages (of ${allDeps.length} locked) from ${p}`);
  } else {
    log(`auditing ${deps.length} locked packages from ${p}`);
  }
  const results = [];
  let i = 0, done = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, deps.length) }, async () => {
    while (i < deps.length) {
      const { name, version } = deps[i++];
      const hit = cache ? cacheGet(name, version) : null;
      if (hit) {
        results.push({ name, version, rows: hit, cached: true });
      } else {
        try {
          const pkg = await fetchPackage(name, version);
          const rows = analyzePackage(pkg);
          results.push({ name, version, rows });
          if (cache) cacheSet(name, version, rows);
        } catch (err) {
          results.push({ name, version, rows: [], error: String(err.message || err).replace(/\|/g, '\\|') });
        }
      }
      if (++done % 25 === 0) log(`  ${done}/${deps.length}`);
    }
  }));
  return results.sort((a, b) => a.name.localeCompare(b.name));
}

async function auditAction(opts) {
  const results = await runAudit(opts.path, {
    log: (m) => process.stderr.write(`${m}\n`),
    cache: opts.cache,
    diffBase: opts.diff || null,
  });
  const note = opts.diff
    ? `_Diff mode: only packages added or upgraded relative to \`${opts.diff}\` were audited._`
    : undefined;
  const output = opts.json
    ? JSON.stringify({
      results: results.map((r) => ({ ...r, risk: packageRisk(r) })),
      allowScripts: buildAllowScripts(results).allowScripts,
    }, null, 2)
    : buildReport(results, { note });
  if (opts.out) fs.writeFileSync(opts.out, output);
  else process.stdout.write(`${output}\n`);
  if (opts.sarif) {
    const { path: lp } = resolveLockfile(opts.path);
    let rel = path.relative(process.cwd(), lp).replace(/\\/g, '/');
    if (rel.startsWith('..')) rel = path.basename(lp);
    fs.writeFileSync(opts.sarif,
      JSON.stringify(buildSarif(results, { lockPath: rel, lockText: fs.readFileSync(lp, 'utf8') }), null, 2));
    process.stderr.write(`SARIF written to ${opts.sarif}\n`);
  }
  const high = results.filter((r) => packageRisk(r) === 'HIGH').length;
  if (opts.failOnHigh && high > 0) {
    process.stderr.write(`FAIL: ${high} package(s) with HIGH risk install scripts\n`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  program.name('npm-script-lens')
    .description('Audit npm lifecycle scripts for behavioral risks before approving them under npm v12 allowScripts')
    .version(require('../package.json').version);
  program.command('audit')
    .description('audit every package in a lockfile and report install-script risks')
    .option('--path <path>', 'project dir or lockfile (package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml)', '.')
    .option('--json', 'emit JSON instead of Markdown')
    .option('--out <file>', 'write report to a file instead of stdout')
    .option('--sarif <file>', 'also write SARIF 2.1.0 for GitHub code scanning')
    .option('--diff <base-lockfile>', 'audit only packages added or upgraded relative to a base lockfile')
    .option('--no-cache', 'disable the on-disk result cache')
    .option('--fail-on-high', 'exit 1 if any package scores HIGH')
    .action(auditAction);
  program.parseAsync().catch((err) => {
    process.stderr.write(`error: ${err.message}\n`);
    process.exit(2);
  });
}

module.exports = { runAudit };
