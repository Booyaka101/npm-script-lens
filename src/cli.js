#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { program } = require('commander');
const { fetchPackage, loadLocalPackage } = require('./registry');
const { analyzePackage, walkFiles, resolveFile, score } = require('./analyzer');
const { loadDeps, resolveLockfile, viaChain } = require('./lockfiles');
const { cacheGet, cacheSet } = require('./cache');
const { osvMalicious, fetchTrust, trustLabel } = require('./trust');
const { buildReport, buildAllowScripts, buildSarif, packageRisk } = require('./reporter');

const flatSignals = (rows) => rows.flatMap((r) => r.signals);

// Signals from walking another package's bin script or main entry — how
// `husky install` gets judged by husky's actual code instead of a
// conservative "unresolved binary" flag. Cached; null = could not resolve
// (caller keeps its conservative signal).
async function crossPackageSignals(dep, entryKind, ctx) {
  const cKey = [`x~${dep.name.replace('/', '+')}`, `${dep.version}~${entryKind.replace(/[\\/:]/g, '_')}`];
  const hit = ctx.cache ? cacheGet(cKey[0], cKey[1]) : null;
  if (hit) return hit;
  let out = null;
  try {
    const pkg = ctx.offline
      ? loadLocalPackage(dep.name, dep.version, ctx.projectDir, dep.lockKey, { forceFiles: true })
      : await fetchPackage(dep.name, dep.version, { forceTarball: true });
    let target = null;
    if (entryKind.startsWith('bin:')) {
      target = pkg.bin[entryKind.slice(4)];
    } else {
      target = 'index.js';
      try { target = JSON.parse(pkg.files.get('package.json')).main || 'index.js'; } catch { /* default */ }
    }
    const entry = target && resolveFile(pkg.files, 'x', `./${target.replace(/^\.\//, '')}`);
    if (entry) {
      const signals = new Set();
      walkFiles(pkg.files, [entry], signals);
      out = [...signals].filter((s) => !s.startsWith('ref: '));
    }
  } catch { /* keep conservative */ }
  if (ctx.cache && out !== null) cacheSet(cKey[0], cKey[1], out);
  return out;
}

// Post-analysis pass over a package's rows:
//  - unresolved binaries owned by a lockfile package get replaced by the
//    actual analysis of that package's bin script (and the row re-scored)
//  - with --deep, bare requires of lockfile packages pull in that package's
//    entry-file signals
//  - 'ref:' breadcrumbs never leave this function
async function enrichRows(rows, ctx) {
  for (const row of rows) {
    const sigs = new Set(row.signals);
    for (const s of [...sigs]) {
      const m = s.match(/^exec: (.+?) \(unresolved binary\)$/);
      if (!m || !ctx.depsByName) continue;
      const binName = m[1].split(/\s+/)[0].split(/[\\/]/).pop().replace(/\.(exe|cmd|bat)$/i, '');
      const owner = ctx.depsByName.get(binName);
      if (!owner) continue;
      const resolved = await crossPackageSignals(owner, `bin:${binName}`, ctx);
      if (resolved === null) continue;
      sigs.delete(s);
      sigs.add(`bin: ${m[1]} → ${owner.name}@${owner.version}`);
      for (const x of resolved) sigs.add(x);
    }
    for (const s of [...sigs]) {
      if (!s.startsWith('ref: ')) continue;
      sigs.delete(s);
      if (!ctx.deep || !ctx.depsByName) continue;
      const owner = ctx.depsByName.get(s.slice(5));
      if (!owner) continue;
      const extra = await crossPackageSignals(owner, 'main', ctx);
      if (extra) for (const x of extra) sigs.add(`${x} (via ${owner.name})`);
    }
    row.signals = [...sigs].sort();
    row.risk = score(row.signals);
  }
}

// Analysis rows for one name@version: cache, then node_modules (offline) or
// the registry. Returns { rows } or { error }.
async function auditOne(dep, ctx) {
  const { cache, offline, projectDir, deep } = ctx;
  const cacheVer = deep ? `${dep.version}+deep` : dep.version;
  const hit = cache ? cacheGet(dep.name, cacheVer) : null;
  if (hit) return { rows: hit, cached: true };
  try {
    const pkg = offline
      ? loadLocalPackage(dep.name, dep.version, projectDir, dep.lockKey)
      : await fetchPackage(dep.name, dep.version);
    const rows = analyzePackage(pkg);
    await enrichRows(rows, ctx);
    if (cache) cacheSet(dep.name, cacheVer, rows);
    return { rows };
  } catch (err) {
    return { error: String(err.message || err).replace(/\|/g, '\\|') };
  }
}

async function runAudit(lockPath, {
  concurrency = 8, log = () => {}, cache = true, diffBase = null, offline = false, trust = true, via = true, deep = false,
} = {}) {
  const { lockPath: p, deps: allDeps, edges } = loadDeps(lockPath);
  const projectDir = path.dirname(p);
  const depsByName = new Map(allDeps.map((d) => [d.name, d]));
  const ctx = { cache, offline, projectDir, deep, depsByName };
  let deps = allDeps;
  const baseVersions = new Map();
  if (diffBase) {
    for (const d of loadDeps(diffBase).deps) baseVersions.set(d.name, d.version);
    deps = allDeps.filter((d) => baseVersions.get(d.name) !== d.version);
    log(`auditing ${deps.length} added/upgraded packages (of ${allDeps.length} locked) from ${p}`);
  } else {
    log(`auditing ${deps.length} locked packages from ${p}`);
  }
  const results = [];
  let i = 0, done = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, deps.length) }, async () => {
    while (i < deps.length) {
      const dep = deps[i++];
      const r = { name: dep.name, version: dep.version, rows: [], ...await auditOne(dep, ctx) };
      // upgrade: also audit the base version and report capabilities the new
      // version gained — the fingerprint of a hijacked release
      const baseVer = baseVersions.get(dep.name);
      if (baseVer && baseVer !== dep.version && !r.error) {
        const base = await auditOne({ name: dep.name, version: baseVer }, ctx);
        r.base = base.error
          ? { version: baseVer, gained: null }
          : { version: baseVer, gained: flatSignals(r.rows).filter((s) => !flatSignals(base.rows).includes(s)) };
      }
      if (via && edges.size > 0) {
        const chain = viaChain(edges, dep.name);
        if (chain.length > 0) r.via = chain;
      }
      results.push(r);
      if (++done % 25 === 0) log(`  ${done}/${deps.length}`);
    }
  }));
  if (trust && !offline && results.length > 0) {
    const mal = await osvMalicious(results.map((r) => ({ name: r.name, version: r.version })));
    for (const r of results) {
      const ids = mal.get(`${r.name}@${r.version}`);
      if (ids) { r.malicious = true; r.advisories = ids; }
    }
    const wanted = results.filter((r) => r.malicious || ['HIGH', 'MEDIUM'].includes(packageRisk(r)));
    let t = 0;
    await Promise.all(Array.from({ length: Math.min(6, wanted.length) }, async () => {
      while (t < wanted.length) {
        const r = wanted[t++];
        r.trust = await fetchTrust(r.name, r.version);
      }
    }));
  }
  return results.sort((a, b) => a.name.localeCompare(b.name));
}

function writeSarif(results, target, file) {
  const { path: lp } = resolveLockfile(target);
  let rel = path.relative(process.cwd(), lp).replace(/\\/g, '/');
  if (rel.startsWith('..')) rel = path.basename(lp);
  fs.writeFileSync(file,
    JSON.stringify(buildSarif(results, { lockPath: rel, lockText: fs.readFileSync(lp, 'utf8') }), null, 2));
}

const failCount = (results) => results.filter((r) => r.malicious || packageRisk(r) === 'HIGH').length;

async function auditAction(opts) {
  const results = await runAudit(opts.path, {
    log: (m) => process.stderr.write(`${m}\n`),
    cache: opts.cache,
    trust: opts.trust,
    offline: opts.offline,
    deep: opts.deep,
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
    writeSarif(results, opts.path, opts.sarif);
    process.stderr.write(`SARIF written to ${opts.sarif}\n`);
  }
  const bad = failCount(results);
  if (opts.failOnHigh && bad > 0) {
    process.stderr.write(`FAIL: ${bad} package(s) with HIGH risk or known-malicious install scripts\n`);
    process.exitCode = 1;
  }
}

// --- sync: reconcile package.json allowScripts with the lockfile ---------

function projectPackageJson(target) {
  const resolved = path.resolve(target);
  const dir = fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
  const pkgPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) throw new Error(`package.json not found next to the lockfile: ${pkgPath}`);
  const raw = fs.readFileSync(pkgPath, 'utf8');
  return { pkgPath, raw, pkg: JSON.parse(raw) };
}

function writePackageJson(pkgPath, raw, pkg) {
  const indentMatch = raw.match(/^([ \t]+)"/m);
  const out = JSON.stringify(pkg, null, indentMatch ? indentMatch[1] : 2) + (raw.endsWith('\n') ? '\n' : '');
  fs.writeFileSync(pkgPath, out);
}

const sortedBlock = (obj) => Object.fromEntries(Object.entries(obj).sort(([a], [b]) => a.localeCompare(b)));

async function syncAction(opts) {
  const { pkgPath, raw, pkg } = projectPackageJson(opts.path);
  const existing = pkg.allowScripts || {};
  const results = await runAudit(opts.path, {
    log: (m) => process.stderr.write(`${m}\n`), cache: opts.cache, trust: opts.trust, offline: opts.offline, deep: opts.deep,
  });
  const needsEntry = results.filter((r) => r.rows.length > 0 || r.error || r.malicious);
  const byName = new Map(results.map((r) => [r.name, r]));
  const baseCtx = {
    cache: opts.cache, offline: opts.offline, projectDir: path.dirname(pkgPath), deep: opts.deep,
    depsByName: new Map(results.map((r) => [r.name, { name: r.name, version: r.version }])),
  };
  const next = {};
  const kept = [], removed = [], repinned = [], added = [];
  for (const [entry, decision] of Object.entries(existing)) {
    const at = entry.indexOf('@', 1);
    const name = at > 0 ? entry.slice(0, at) : entry;
    const version = at > 0 ? entry.slice(at + 1) : '';
    const r = byName.get(name);
    if (!r || (r.rows.length === 0 && !r.error && !r.malicious)) {
      removed.push(entry);
    } else if (r.version === version) {
      next[entry] = r.malicious ? false : decision;
      kept.push(entry);
    } else {
      // version moved: preserve the old decision only when the upgrade gained
      // no new capabilities, otherwise fall back to the risk default
      const base = await auditOne({ name, version }, baseCtx);
      const gained = base.error ? null : flatSignals(r.rows).filter((s) => !flatSignals(base.rows).includes(s));
      const preserve = gained !== null && gained.length === 0;
      const value = r.malicious ? false
        : preserve ? decision : ['SAFE', 'LOW'].includes(packageRisk(r));
      next[`${r.name}@${r.version}`] = value;
      repinned.push({ from: entry, to: `${r.name}@${r.version}`, preserve, gained, value });
    }
  }
  for (const r of needsEntry) {
    const key = `${r.name}@${r.version}`;
    if (key in next) continue;
    next[key] = r.malicious ? false : ['SAFE', 'LOW'].includes(packageRisk(r));
    added.push({ key, value: next[key], risk: packageRisk(r), malicious: r.malicious });
  }
  const lines = ['# allowScripts sync', ''];
  lines.push(`${kept.length} current, ${repinned.length} re-pinned, ${added.length} new, ${removed.length} removed.`, '');
  if (removed.length > 0) lines.push('Removed (no longer in the lockfile or no longer scripted):', ...removed.map((e) => `- \`${e}\``), '');
  for (const rp of repinned) {
    lines.push(rp.preserve
      ? `- \`${rp.from}\` → \`${rp.to}\`: no new capabilities, decision **preserved** (${rp.value})`
      : `- \`${rp.from}\` → \`${rp.to}\`: **needs re-review** — ${rp.gained === null ? 'base version could not be compared' : `gained ${rp.gained.map((g) => `\`${g}\``).join(' ')}`} (defaulted to ${rp.value})`);
  }
  if (repinned.length > 0) lines.push('');
  for (const a of added) {
    lines.push(`- new: \`${a.key}\` ${a.malicious ? '⛔ MALICIOUS' : a.risk} → ${a.value}`);
  }
  if (added.length > 0) lines.push('');
  lines.push('```json', JSON.stringify({ allowScripts: sortedBlock(next) }, null, 2), '```');
  process.stdout.write(`${lines.join('\n')}\n`);
  const drift = removed.length + repinned.length + added.length;
  if (opts.write && drift > 0) {
    pkg.allowScripts = sortedBlock(next);
    writePackageJson(pkgPath, raw, pkg);
    process.stderr.write(`updated ${pkgPath}\n`);
  }
  if (opts.check && drift > 0) {
    process.stderr.write(`FAIL: allowScripts is out of sync (${drift} change(s) needed)\n`);
    process.exitCode = 1;
  }
}

// --- approve: interactive, evidence-driven allowScripts editing ----------

async function approveAction(opts) {
  const { pkgPath, raw, pkg } = projectPackageJson(opts.path);
  const existing = pkg.allowScripts || {};
  const results = await runAudit(opts.path, {
    log: (m) => process.stderr.write(`${m}\n`), cache: opts.cache, trust: opts.trust, offline: opts.offline, deep: opts.deep,
  });
  const RANK = { HIGH: 0, MEDIUM: 1, LOW: 2, SAFE: 3, ERROR: 4 };
  const queue = results
    .filter((r) => r.rows.length > 0 || r.error || r.malicious)
    .sort((a, b) => (a.malicious ? -1 : RANK[packageRisk(a)]) - (b.malicious ? -1 : RANK[packageRisk(b)]));
  if (queue.length === 0) {
    process.stdout.write('nothing to approve: no packages with install-time scripts\n');
    return;
  }
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let closed = false;
  rl.on('close', () => { closed = true; });
  const ask = (q) => new Promise((resolve) => (closed ? resolve('q') : rl.question(q, resolve)));
  const decisions = {};
  for (const r of queue) {
    const key = `${r.name}@${r.version}`;
    const out = [`\n${key}  [${r.malicious ? '⛔ KNOWN MALICIOUS — ' + r.advisories.join(', ') : packageRisk(r)}]`];
    if (r.via) out.push(`  via ${r.via.join(' → ')}`);
    if (r.trust) out.push(`  ${trustLabel(r.trust)}`);
    for (const row of r.rows) {
      out.push(`  ${row.script}: ${row.command}`);
      for (const s of row.signals) out.push(`    ${s}`);
    }
    if (r.error) out.push(`  fetch error: ${r.error}`);
    if (key in existing) out.push(`  current decision: ${existing[key]}`);
    process.stdout.write(`${out.join('\n')}\n`);
    const ans = (await ask('allow? [y]es / [n]o / [s]kip / [q]uit > ')).trim().toLowerCase();
    if (ans === 'q') break;
    if (ans === 'y' || ans === 'yes') decisions[key] = true;
    else if (ans === 'n' || ans === 'no') decisions[key] = false;
  }
  if (!closed) rl.close();
  if (Object.keys(decisions).length === 0) {
    process.stdout.write('no decisions made; package.json untouched\n');
    return;
  }
  pkg.allowScripts = sortedBlock({ ...existing, ...decisions });
  writePackageJson(pkgPath, raw, pkg);
  process.stdout.write(`wrote ${Object.keys(decisions).length} decision(s) to ${pkgPath}\n`);
}

if (require.main === module) {
  program.name('npm-script-lens')
    .description('Audit npm lifecycle scripts for behavioral risks before approving them under npm v12 allowScripts')
    .version(require('../package.json').version);
  const common = (cmd) => cmd
    .option('--path <path>', 'project dir or lockfile (package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock)', '.')
    .option('--no-cache', 'disable the on-disk result cache')
    .option('--no-trust', 'skip trust enrichment (OSV malware check, publish age, downloads, provenance)')
    .option('--deep', 'also analyze lockfile packages that install scripts require() by bare name')
    .option('--offline', 'analyze packages from node_modules instead of the registry (implies --no-trust)');
  common(program.command('audit'))
    .description('audit every package in a lockfile and report install-script risks')
    .option('--json', 'emit JSON instead of Markdown')
    .option('--out <file>', 'write report to a file instead of stdout')
    .option('--sarif <file>', 'also write SARIF 2.1.0 for GitHub code scanning')
    .option('--diff <base-lockfile>', 'audit only packages added or upgraded relative to a base lockfile, and report capabilities gained across upgrades')
    .option('--fail-on-high', 'exit 1 if any package scores HIGH or is known malicious')
    .action(auditAction);
  common(program.command('sync'))
    .description('reconcile the allowScripts block in package.json with the lockfile')
    .option('--write', 'update package.json in place')
    .option('--check', 'exit 1 when allowScripts is out of sync (for CI)')
    .action(syncAction);
  common(program.command('approve'))
    .description('step through risky packages interactively and write allowScripts decisions')
    .action(approveAction);
  program.command('mcp')
    .description('run as an MCP server on stdio (tools: audit_package, audit_lockfile)')
    .action(() => require('./mcp').serve());
  program.parseAsync().catch((err) => {
    process.stderr.write(`error: ${err.message}\n`);
    process.exit(2);
  });
}

module.exports = { runAudit, auditOne, flatSignals };
