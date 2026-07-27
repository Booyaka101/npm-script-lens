#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { execFileSync } = require('node:child_process');
const { program } = require('commander');
const { fetchPackage, loadLocalPackage } = require('./registry');
const { analyzePackage, walkFiles, resolveFile, score, commandEntryFiles } = require('./analyzer');
const { loadDeps, resolveLockfile, viaChain } = require('./lockfiles');
const { cacheGet, cacheSet } = require('./cache');
const { osvMalicious, fetchTrust, trustLabel } = require('./trust');
const { buildReport, buildHtml, buildAllowScripts, buildSarif, buildManifest, serializeManifest, diffManifests, packageRisk, buildGapsReport, BADGE } = require('./reporter');
const { checkV12Gaps, workflowFiles } = require('./v12gaps');
const { npmDryRunPending, npmMajorVersion, isCovered } = require('./review');
const { runDoctor, renderDoctor } = require('./doctor');
const { analyzeSources, sourcesJson, renderSources, rootWarnings, checkSourceConfig, readSourceConfig } = require('./sources');
const { mergeNpmrc } = require('./npmrc');
const { SOURCES } = require('./npm-contract');
const { managerFor, managerById } = require('./pm-contract');
const { loadPolicy, evaluate: evaluatePolicy } = require('./policy');
const { parseSpec, fetchScripts, computeScriptDiff, renderDiff } = require('./diff');

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
  concurrency = 8, log = () => {}, cache = true, diffBase = null, offline = false, trust = true, via = true, deep = false, trustAll = false,
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
    // trustAll (policy needs age/provenance for every candidate) widens the
    // trust fetch from just-risky to every scripted package.
    const wanted = results.filter((r) => r.malicious
      || (trustAll ? r.rows.length > 0 : ['HIGH', 'MEDIUM'].includes(packageRisk(r))));
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

function writeSarif(results, target, file, findings = []) {
  const { path: lp } = resolveLockfile(target);
  let rel = path.relative(process.cwd(), lp).replace(/\\/g, '/');
  if (rel.startsWith('..')) rel = path.basename(lp);
  fs.writeFileSync(file,
    JSON.stringify(buildSarif(results, { lockPath: rel, lockText: fs.readFileSync(lp, 'utf8'), findings }), null, 2));
}

const failCount = (results) => results.filter((r) => r.malicious || packageRisk(r) === 'HIGH').length;

// --check-v12-gaps: only the two npm v12 approve-scripts bug detectors
// (npm/cli#9562 optional-dep gap, npm/cli#9463 EGLOBAL), same output surfaces
// as a full audit: Markdown, --json, --sarif, --out.
async function v12GapsAction(opts) {
  const { findings, npmMajor } = await checkV12Gaps(opts.path, { log: (m) => process.stderr.write(`${m}\n`) });
  const output = opts.json ? JSON.stringify({ findings }, null, 2) : buildGapsReport(findings, { npmMajor });
  if (opts.out) fs.writeFileSync(opts.out, output);
  else process.stdout.write(`${output}\n`);
  if (opts.sarif) {
    writeSarif([], opts.path, opts.sarif, findings);
    process.stderr.write(`SARIF written to ${opts.sarif}\n`);
  }
}

// --since <ref>: materialize the lockfile as it was at a git ref into a temp
// dir (named so the lockfile type still resolves), for use as the --diff base.
// Audits only what changed since a branch/tag/SHA without hand-extracting it.
function baseLockfileFromGit(target, ref) {
  const { path: lp } = resolveLockfile(target);
  const lockDir = path.dirname(lp);
  const base = path.basename(lp);
  const git = (args) => execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
  try {
    git(['-C', lockDir, 'rev-parse', '--show-toplevel']);
  } catch {
    throw new Error(`--since needs a git repository, but ${lockDir} is not inside one`);
  }
  // Let git resolve the path via `<ref>:./<file>` from inside lockDir. Doing
  // the path math host-side (path.relative(toplevel, lp)) breaks on Windows
  // when git's toplevel and os.tmpdir() disagree on 8.3 short names
  // (runneradmin vs RUNNER~1) — git rejects the escaped path as "outside
  // repository". The `./` prefix makes git resolve relative to -C, not root.
  let content;
  try {
    content = git(['-C', lockDir, 'show', `${ref}:./${base}`]);
  } catch (err) {
    throw new Error(`could not read ${base} at git ref '${ref}': ${String(err.stderr || err.message || err).trim()}`);
  }
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-since-'));
  fs.writeFileSync(path.join(tmpDir, base), content);
  return path.join(tmpDir, base);
}

async function auditAction(opts) {
  if (opts.checkV12Gaps) return v12GapsAction(opts);
  let diffBase = opts.diff || null;
  let sinceDir = null;
  if (opts.since) {
    if (opts.diff) throw new Error('use either --diff or --since, not both');
    diffBase = baseLockfileFromGit(opts.path, opts.since);
    sinceDir = path.dirname(diffBase);
  }
  try {
    const results = await runAudit(opts.path, {
      log: (m) => process.stderr.write(`${m}\n`),
      cache: opts.cache,
      trust: opts.trust,
      offline: opts.offline,
      deep: opts.deep,
      diffBase,
    });
    const note = opts.since
      ? `_Diff mode: only packages added or upgraded relative to git ref \`${opts.since}\` were audited._`
      : opts.diff
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
    if (opts.html) {
      fs.writeFileSync(opts.html, buildHtml(results, { note }));
      process.stderr.write(`HTML report written to ${opts.html}\n`);
    }
    const bad = failCount(results);
    if (opts.failOnHigh && bad > 0) {
      process.stderr.write(`FAIL: ${bad} package(s) with HIGH risk or known-malicious install scripts\n`);
      process.exitCode = 1;
    }
  } finally {
    if (sinceDir) fs.rmSync(sinceDir, { recursive: true, force: true });
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
  let mgr = managerById('npm');
  if (opts.manager) mgr = managerById(opts.manager);
  else { try { mgr = managerFor(resolveLockfile(opts.path).type); } catch { /* default npm */ } }
  const { policy, source } = loadPolicy(dirOf(opts.path), opts.policy);
  if (source) process.stderr.write(`using policy: ${source}\n`);
  return mgr.id === 'npm' ? syncNpm(opts, policy) : syncNameKeyed(opts, mgr, policy);
}

// npm's version-pinned reconcile: entries are name@version, so an upgrade
// invalidates the pin — preserve the decision only if the new version gained
// no capabilities, else default by risk.
async function syncNpm(opts, policy) {
  const { pkgPath, raw, pkg } = projectPackageJson(opts.path);
  const existing = pkg.allowScripts || {};
  const results = await runAudit(opts.path, {
    log: (m) => process.stderr.write(`${m}\n`), cache: opts.cache, trust: opts.trust, offline: opts.offline, deep: opts.deep,
    trustAll: policyNeedsTrust(policy) && opts.trust,
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
        : preserve ? decision : isAutoApproved(r, policy);
      next[`${r.name}@${r.version}`] = value;
      repinned.push({ from: entry, to: `${r.name}@${r.version}`, preserve, gained, value });
    }
  }
  for (const r of needsEntry) {
    const key = `${r.name}@${r.version}`;
    if (key in next) continue;
    next[key] = isAutoApproved(r, policy);
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

// pnpm/yarn/bun key their allowlist by package NAME (no version), so an
// upgrade never invalidates an entry — reconcile is simpler: keep decisions
// for still-scripted packages, drop entries whose package is gone or no longer
// scripted, add new scripted packages (SAFE/LOW default true). writeFull
// replaces the whole allowlist so removals actually take effect.
async function syncNameKeyed(opts, mgr, policy) {
  const projectDir = dirOf(opts.path);
  const existing = mgr.readExisting(projectDir); // {name:bool} (pnpm/yarn) or [names] (bun)
  const existingNames = Array.isArray(existing) ? new Set(existing) : new Set(Object.keys(existing));
  const decisionOf = (name) => (Array.isArray(existing) ? true : existing[name]);
  const results = await runAudit(opts.path, {
    log: (m) => process.stderr.write(`${m}\n`), cache: opts.cache, trust: opts.trust, offline: opts.offline, deep: opts.deep,
    trustAll: policyNeedsTrust(policy) && opts.trust,
  });
  const scripted = new Map();
  for (const r of results) if ((r.rows.length > 0 || r.error || r.malicious) && !scripted.has(r.name)) scripted.set(r.name, r);

  const next = {};
  const kept = [], added = [], removed = [];
  for (const [name, r] of scripted) {
    if (existingNames.has(name)) { next[name] = r.malicious ? false : decisionOf(name); kept.push(name); }
    else { next[name] = isAutoApproved(r, policy); added.push({ name, value: next[name], risk: packageRisk(r), malicious: r.malicious }); }
  }
  for (const name of existingNames) if (!scripted.has(name)) removed.push(name);

  const lines = [`# ${mgr.nativeKey} sync (${mgr.label})`, ''];
  lines.push(`${kept.length} current, ${added.length} new, ${removed.length} removed.`, '');
  if (removed.length > 0) lines.push('Removed (no longer in the lockfile or no longer scripted):', ...removed.map((e) => `- \`${e}\``), '');
  for (const a of added) lines.push(`- new: \`${a.name}\` ${a.malicious ? '⛔ MALICIOUS' : a.risk} → ${a.value}`);
  if (added.length > 0) lines.push('');
  lines.push('```json', JSON.stringify({ [mgr.nativeKey]: mgr.renderDecisions(Object.entries(next).map(([name, allow]) => ({ name, allow }))) }, null, 2), '```');
  process.stdout.write(`${lines.join('\n')}\n`);

  const drift = added.length + removed.length;
  if (opts.write && drift > 0) {
    const { file } = mgr.writeFull(projectDir, next);
    process.stderr.write(`updated ${file}\n`);
  }
  if (opts.check && drift > 0) {
    process.stderr.write(`FAIL: ${mgr.nativeKey} is out of sync (${drift} change(s) needed)\n`);
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

// --- review: pending approvals with actual script content + scan verdict --
// npm v12's pending list shows only the script command ("node install/check"),
// never what the file it runs contains. review shows both, plus the existing
// behavioral scan + OSV verdict, for exactly the packages awaiting a decision.

// Audit exactly the packages npm reported as pending: same analyzers, cache,
// OSV and trust enrichment as a full audit, scoped to the pending set (which
// npm can report even when no lockfile exists yet).
async function auditSubset(list, { lockDeps, edges, depsByName }, ctx, trust) {
  const results = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(6, list.length) }, async () => {
    while (i < list.length) {
      const u = list[i++];
      const dep = lockDeps.get(`${u.name}@${u.version}`) || { name: u.name, version: u.version };
      const r = { name: u.name, version: u.version, rows: [], ...await auditOne(dep, { ...ctx, depsByName }) };
      if (edges.size > 0) {
        const chain = viaChain(edges, u.name);
        if (chain.length > 0) r.via = chain;
      }
      results.push(r);
    }
  }));
  if (trust && !ctx.offline && results.length > 0) {
    const mal = await osvMalicious(results.map((r) => ({ name: r.name, version: r.version })));
    for (const r of results) {
      const ids = mal.get(`${r.name}@${r.version}`);
      if (ids) { r.malicious = true; r.advisories = ids; }
    }
    for (const r of results) {
      if (r.malicious || ['HIGH', 'MEDIUM'].includes(packageRisk(r))) r.trust = await fetchTrust(r.name, r.version);
    }
  }
  return results.sort((a, b) => a.name.localeCompare(b.name));
}

// The actual bytes behind each script command — the thing npm's pending list
// cannot show. First CONTENT_LINES lines of every file the command directly
// runs (via the same `node <file>` resolution the analyzer uses); binding.gyp
// for node-gyp builds; the command itself when it references no local file.
const CONTENT_LINES = 40;
async function scriptContent(r, ctx, lockDep) {
  try {
    const pkg = ctx.offline
      ? loadLocalPackage(r.name, r.version, ctx.projectDir, lockDep && lockDep.lockKey, { forceFiles: true })
      : await fetchPackage(r.name, r.version, { forceTarball: true });
    const out = [];
    for (const [script, command] of Object.entries(pkg.scripts)) {
      const entries = commandEntryFiles(command, pkg.files);
      if (entries.length === 0 && /(^|\s)node-gyp(\s|$)/.test(command) && pkg.files.has('binding.gyp')) {
        entries.push('binding.gyp');
      }
      if (entries.length === 0) {
        out.push({ script, command, file: null, note: 'command is self-contained — no local script file to open' });
        continue;
      }
      for (const file of entries) {
        const all = (pkg.files.get(file) || '').split(/\r?\n/);
        out.push({ script, command, file, totalLines: all.length, lines: all.slice(0, CONTENT_LINES) });
      }
    }
    return out;
  } catch (err) {
    return [{ error: String(err.message || err) }];
  }
}

async function reviewAction(opts) {
  const resolved = path.resolve(opts.path);
  const projectDir = fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
  const log = (m) => process.stderr.write(`${m}\n`);
  let lockInfo = null;
  try { lockInfo = resolveLockfile(opts.path); } catch { /* npm v12 can answer without one */ }
  const lock = { lockDeps: new Map(), edges: new Map(), depsByName: new Map() };
  if (lockInfo) {
    const loaded = loadDeps(opts.path);
    lock.edges = loaded.edges;
    for (const d of loaded.deps) {
      if (!lock.depsByName.has(d.name)) lock.depsByName.set(d.name, d);
      const key = `${d.name}@${d.version}`;
      if (!lock.lockDeps.has(key)) lock.lockDeps.set(key, d);
    }
  }
  const ctx = { cache: opts.cache, offline: opts.offline, projectDir, deep: opts.deep };

  // Which package manager's allowlist are we reviewing against?
  let mgr = managerById('npm');
  if (opts.manager) mgr = managerById(opts.manager);
  else if (lockInfo) mgr = managerFor(lockInfo.type);
  const { policy, source: policySrc } = loadPolicy(projectDir, opts.policy);
  if (policySrc) log(`using policy: ${policySrc}`);

  let source, pending;
  let viaNpm = null;
  // The dry-run pending list is an npm-v12 mechanism; other managers use the
  // lockfile + their own allowlist for coverage.
  if (!opts.offline && mgr.id === 'npm') {
    log('asking the local npm for pending script approvals (npm install --dry-run --json)…');
    viaNpm = await npmDryRunPending(projectDir);
  }
  // npm is v12+ but its --dry-run --json shape is not one we recognize: do NOT
  // trust it as "nothing pending" — say so loudly and fall back to the
  // lockfile. This is the drift alarm; `npm-script-lens doctor` diagnoses it.
  if (viaNpm && viaNpm.unrecognized) {
    log(`⚠️  local npm v${viaNpm.npmMajor} answered but its --dry-run --json shape is not recognized — `
      + 'npm-script-lens may be out of date with this npm. Falling back to the lockfile; run `npm-script-lens doctor` to diagnose.');
  }
  if (viaNpm && viaNpm.pending) {
    source = 'npm install --dry-run --json (npm v12 unreviewedScripts)';
    log(`npm reports ${viaNpm.pending.length} package(s) with unreviewed install scripts`);
    pending = await auditSubset(viaNpm.pending, lock, ctx, opts.trust);
  } else if (lockInfo) {
    source = viaNpm && viaNpm.unrecognized
      ? `lockfile + ${mgr.nativeKey} (local npm output shape unrecognized — see doctor)`
      : mgr.id === 'npm'
        ? 'lockfile + allowScripts (local npm does not report unreviewed scripts — npm >= 12 does)'
        : `lockfile + ${mgr.nativeKey} (${mgr.label})`;
    if (mgr.id === 'npm' && !opts.offline && !(viaNpm && viaNpm.unrecognized)) log('local npm did not report unreviewed scripts — computing from the lockfile instead');
    const existing = mgr.readExisting(projectDir);
    const results = await runAudit(opts.path, {
      log, cache: opts.cache, trust: opts.trust, offline: opts.offline, deep: opts.deep,
      trustAll: policyNeedsTrust(policy) && opts.trust,
    });
    pending = results.filter((r) => (r.rows.length > 0 || r.error || r.malicious) && !mgr.covers(existing, r.name, r.version));
  } else {
    throw new Error(`no lockfile found under ${projectDir} and the local npm does not report unreviewed scripts (npm >= 12 does) — create one with \`npm install --package-lock-only\` or upgrade npm`);
  }

  const contents = new Map();
  for (const r of pending) {
    if (r.error) continue;
    contents.set(`${r.name}@${r.version}`, await scriptContent(r, ctx, lock.lockDeps.get(`${r.name}@${r.version}`)));
  }
  const decisions = pending.map((r) => ({
    name: r.name, version: r.version, allow: isAutoApproved(r, policy),
  }));
  const nativeBlock = mgr.renderDecisions(decisions);

  if (opts.json) {
    process.stdout.write(`${JSON.stringify({
      source,
      manager: mgr.id,
      pending: pending.map((r) => ({ ...r, risk: packageRisk(r), content: contents.get(`${r.name}@${r.version}`) || [] })),
      [mgr.nativeKey]: nativeBlock,
    }, null, 2)}\n`);
  } else {
    const lines = ['npm-script-lens review — pending install-script approvals', `source: ${source}`, ''];
    if (pending.length === 0) {
      lines.push(`🟢 nothing pending — every package with install scripts is covered by ${mgr.nativeKey}.`);
    } else {
      lines.push(`${pending.length} package(s) need a ${mgr.nativeKey} decision (${mgr.label}):`);
      for (const r of pending) {
        const key = `${r.name}@${r.version}`;
        lines.push('', `── ${key}  [${r.malicious ? `⛔ KNOWN MALICIOUS — ${r.advisories.join(', ')}` : BADGE[packageRisk(r)]}]`);
        if (r.via) lines.push(`   via ${r.via.join(' → ')}`);
        if (r.trust) lines.push(`   ${trustLabel(r.trust)}`);
        lines.push(`   OSV: ${!opts.trust || opts.offline ? 'skipped (--no-trust / --offline)'
          : r.malicious ? `⛔ ${r.advisories.join(', ')}` : 'no known malicious advisories'}`);
        if (r.error) { lines.push(`   fetch error: ${r.error}`); continue; }
        for (const row of r.rows) {
          lines.push(`   ${row.script}: ${row.command}`);
          for (const s of row.signals) lines.push(`     ${s}`);
        }
        for (const c of contents.get(key) || []) {
          if (c.error) { lines.push(`   (content unavailable: ${c.error})`); continue; }
          if (!c.file) { lines.push(`   ${c.script}: ${c.note}`); continue; }
          lines.push('', `   ┌─ ${c.file} (${c.totalLines > c.lines.length
            ? `first ${c.lines.length} of ${c.totalLines} lines` : `${c.totalLines} line${c.totalLines === 1 ? '' : 's'}`})`);
          c.lines.forEach((l, idx) => lines.push(`   │ ${String(idx + 1).padStart(3)}  ${l}`));
          lines.push('   └─');
        }
      }
      lines.push('', `Suggested ${mgr.nativeKey} for the pending packages (SAFE/LOW default to true; review HIGH/MEDIUM before flipping):`,
        '', JSON.stringify({ [mgr.nativeKey]: nativeBlock }, null, 2));
      if (mgr.note) lines.push('', `note: ${mgr.note}`);
      if (!opts.outputAllowscripts) lines.push('', `Run again with --output-allowscripts to write these into ${mgr.allowlistFile}.`);
    }
    process.stdout.write(`${lines.join('\n')}\n`);
  }

  if (opts.outputAllowscripts && pending.length > 0) {
    const { file, note } = mgr.writeDecisions(dirOf(opts.path), decisions);
    process.stderr.write(`wrote ${decisions.length} ${mgr.nativeKey} entr${decisions.length === 1 ? 'y' : 'ies'} to ${file}\n`);
    if (note) process.stderr.write(`note: ${note}\n`);
  }
}

// --- allow: pre-approve the safe packages, hold the risky ones for review --
// Splits every package with install-time scripts into an auto-approvable
// allowScripts block (behavioral risk SAFE or LOW, and not known-malicious)
// and a _review list (MEDIUM/HIGH, known-malicious, or un-fetchable — the ones
// a human should look at before flipping to true). Emits the split as JSON on
// stdout; --ci-check is a separate fast guard that runs no scan.

// Is this package auto-approvable? With a policy, defer to it; otherwise the
// built-in default (SAFE/LOW behavioral risk, not malicious/un-fetchable).
function isAutoApproved(r, policy) {
  if (policy) return evaluatePolicy(r, policy, packageRisk, Date.now()).allow;
  return !r.malicious && !r.error && ['SAFE', 'LOW'].includes(packageRisk(r));
}

// A policy that gates on age or provenance needs trust data for EVERY
// candidate (not just the risky ones runAudit fetches by default).
const policyNeedsTrust = (policy) => Boolean(policy && policy.autoApprove
  && (policy.autoApprove.minAgeDays > 0 || policy.autoApprove.requireProvenance));

// Split the audited packages into an auto-approve set and a review set. This
// is manager-agnostic — {name, version} pairs — so pm-contract can render each
// manager's native allowlist format from the same decision.
function classifyDecisions(results, policy) {
  const approved = [], review = [];
  for (const r of results) {
    // only packages that actually run install-time scripts (or that OSV/fetch
    // flagged) need an approval decision at all — clean packages are skipped
    if ((!r.rows || r.rows.length === 0) && !r.error && !r.malicious) continue;
    (isAutoApproved(r, policy) ? approved : review).push({ name: r.name, version: r.version });
  }
  return { approved, review };
}

// npm-shaped split kept for the MCP tool and back-compat (name@version keys).
function classifyForAllow(results) {
  const { approved, review } = classifyDecisions(results);
  const allowScripts = Object.fromEntries(approved.map((d) => [`${d.name}@${d.version}`, true]));
  return { allowScripts: sortedBlock(allowScripts), _review: review.map((d) => `${d.name}@${d.version}`).sort() };
}

// --ci-check: fail CI when npm v12 would silently skip install scripts. No
// scan — just three cheap facts: a workflow runs `npm install`/`i`/`ci`, the
// project has no allowScripts block, and the local npm is v12+. Any one of
// those being false means the install is safe (or already covered), so pass.
const CI_INSTALL_RE = /\bnpm\s+(?:install|i|ci)\b/;

function workflowsRunNpmInstall(projectDir) {
  for (const file of workflowFiles(projectDir)) {
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    if (lines.some((l) => !/^\s*#/.test(l) && CI_INSTALL_RE.test(l))) return true;
  }
  return false;
}

function projectHasAllowScripts(projectDir) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
    return Boolean(pkg.allowScripts) && Object.keys(pkg.allowScripts).length > 0;
  } catch { return false; }
}

const dirOf = (target) => {
  const resolved = path.resolve(target);
  return fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
};

// The shared CI-break verdict, reused by the CLI (`allow --ci-check`) and the
// GitHub Action step. willBreak is true only when all three break conditions
// hold; reason explains the pass otherwise (null when willBreak).
async function ciCheckResult(projectDir) {
  const installsInCi = workflowsRunNpmInstall(projectDir);
  const hasAllow = projectHasAllowScripts(projectDir);
  const npmMajor = await npmMajorVersion(projectDir);
  const enforcing = npmMajor !== null && npmMajor >= 12;
  const scriptsBreak = installsInCi && !hasAllow && enforcing;
  // npm v12 also refuses to RESOLVE git/remote dependencies unless allow-git /
  // allow-remote covers them — the same silent-CI-break shape as allowScripts.
  // Over-permission doesn't break an install, so only insufficient/invalid
  // config counts here (`sources --check` is the strict gate).
  let sourcesFailures = [];
  if (installsInCi && enforcing) {
    try {
      const analysis = await analyzeSources(projectDir, { probeNpm: false });
      if (analysis.lockType === 'npm') {
        const { failures } = checkSourceConfig(analysis, readSourceConfig(analysis.projectDir));
        sourcesFailures = failures.filter((f) => f.kind !== 'over-permissive');
      }
    } catch { /* no lockfile here — nothing for npm to resolve */ }
  }
  const sourcesBreak = sourcesFailures.length > 0;
  const willBreak = scriptsBreak || sourcesBreak;
  const reason = willBreak ? null
    : !installsInCi ? 'no workflow runs npm install'
      : hasAllow ? 'package.json already has an allowScripts block'
        : npmMajor === null ? 'local npm version could not be determined'
          : `local npm is v${npmMajor} (< 12)`;
  return { willBreak, reason, installsInCi, hasAllow, npmMajor, scriptsBreak, sourcesBreak, sourcesFailures };
}

async function ciCheckAction(opts) {
  const { willBreak, reason, scriptsBreak, sourcesBreak, sourcesFailures } = await ciCheckResult(dirOf(opts.path));
  if (willBreak) {
    if (scriptsBreak) process.stderr.write('CI will break on npm v12: run lens allow to generate allowScripts block.\n');
    if (sourcesBreak) {
      for (const f of sourcesFailures) process.stderr.write(`CI will break on npm v12: ${f.message}\n`);
      process.stderr.write('Run lens sources --write to set the minimal correct .npmrc.\n');
    }
    process.exitCode = 1;
    return;
  }
  process.stderr.write(`ci-check passed: ${reason}.\n`);
}

async function allowAction(opts) {
  if (opts.ciCheck) return ciCheckAction(opts);
  const { policy, source } = loadPolicy(dirOf(opts.path), opts.policy);
  if (source) process.stderr.write(`using policy: ${source}\n`);
  let results;
  if (opts.input) {
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(opts.input, 'utf8')); }
    catch (err) { throw new Error(`could not read --input JSON (${opts.input}): ${err.message}`); }
    results = Array.isArray(parsed) ? parsed : parsed.results;
    if (!Array.isArray(results)) {
      throw new Error('--input must be `audit --json` output (an object with a "results" array) or a bare results array');
    }
  } else {
    results = await runAudit(opts.path, {
      log: (m) => process.stderr.write(`${m}\n`),
      cache: opts.cache, trust: opts.trust, offline: opts.offline, deep: opts.deep,
      trustAll: policyNeedsTrust(policy) && opts.trust,
    });
  }
  // Pick the target package manager: explicit --manager wins, else auto-detect
  // from the lockfile, else default to npm (e.g. --input with no lockfile).
  let mgr;
  if (opts.manager) mgr = managerById(opts.manager);
  else { try { mgr = managerFor(resolveLockfile(opts.path).type); } catch { mgr = managerById('npm'); } }

  const { approved, review } = classifyDecisions(results, policy);
  const _review = review.map((d) => `${d.name}@${d.version}`).sort();
  // stdout is the manager's NATIVE allowlist block, directly pasteable into its
  // config file — allowScripts (npm) / allowBuilds (pnpm) / dependenciesMeta
  // (yarn) / trustedDependencies (bun) — plus the _review list.
  process.stdout.write(`${JSON.stringify({ [mgr.nativeKey]: mgr.renderValue(approved), _review }, null, 2)}\n`);
  process.stderr.write(`${approved.length} package${approved.length === 1 ? '' : 's'} auto-approved, ${_review.length} need manual review. `
    + `(${mgr.label} — allowlist in ${mgr.allowlistFile})\n`);
  if (mgr.note) process.stderr.write(`note: ${mgr.note}\n`);

  // --write merges the auto-approved entries into the manager's native file,
  // preserving existing entries. _review packages are deliberately left OUT —
  // writing them would decide for the user; absent keeps them pending so the
  // manager (and a human) still has to act on them.
  if (opts.write && approved.length > 0) {
    const { file, note } = mgr.write(dirOf(opts.path), approved);
    process.stderr.write(`wrote ${approved.length} auto-approved entr${approved.length === 1 ? 'y' : 'ies'} to ${file}`
      + `${_review.length ? `; ${_review.length} still need manual review (left out)` : ''}\n`);
    if (note) process.stderr.write(`note: ${note}\n`);
  } else if (opts.write) {
    process.stderr.write(`nothing auto-approved — ${mgr.allowlistFile} untouched\n`);
  }
}

// --- init: scaffold policy + CI so a repo adopts this in one command ------

const POLICY_STARTER = `{
  "autoApprove": {
    "maxRisk": "LOW",
    "denyCapabilities": [],
    "minAgeDays": 0,
    "requireProvenance": false
  },
  "waivers": {}
}
`;

const WORKFLOW_STARTER = `# Audit dependency install scripts on every PR and gate the allowlist.
name: script-lens
on: [pull_request]
permissions:
  contents: read
  pull-requests: write
jobs:
  script-lens:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Booyaka101/npm-script-lens@v1
        with:
          fail-on-high: 'true'
          comment-on-pr: 'true'
          ci-check: 'true'
`;

// Auto-fix bot: on dependency-update branches (Renovate/Dependabot), reconcile
// the allowlist and commit it back so the update branch stays installable.
const AUTOFIX_WORKFLOW = `# Auto-fix: when a bot opens a dependency update, reconcile the install-script
# allowlist and commit it back to the branch so the update stays installable.
name: script-lens-autofix
on:
  push:
    branches: ['renovate/**', 'dependabot/**']
permissions:
  contents: write
jobs:
  reconcile:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - run: npx npm-script-lens@latest sync --write
      - name: Commit the reconciled allowlist
        run: |
          if [ -n "$(git status --porcelain)" ]; then
            git config user.name 'github-actions[bot]'
            git config user.email 'github-actions[bot]@users.noreply.github.com'
            git commit -am 'chore: reconcile install-script allowlist (npm-script-lens)'
            git push
          else
            echo 'allowlist already in sync'
          fi
`;

async function initAction(opts) {
  const dir = dirOf(opts.path);
  let mgrLabel = 'npm';
  try { mgrLabel = managerFor(resolveLockfile(opts.path).type).label; } catch { /* default */ }
  const targets = [
    { file: path.join(dir, 'script-lens.policy.json'), body: POLICY_STARTER, what: 'governance policy' },
    { file: path.join(dir, '.github', 'workflows', 'script-lens.yml'), body: WORKFLOW_STARTER, what: 'CI workflow' },
  ];
  if (opts.autoFix) {
    targets.push({ file: path.join(dir, '.github', 'workflows', 'script-lens-autofix.yml'), body: AUTOFIX_WORKFLOW, what: 'auto-fix workflow' });
  }
  // --hook: a git pre-commit hook that blocks commits leaving the allowlist
  // out of sync. Only when a .git directory is present.
  let hookFile = null;
  if (opts.hook) {
    const gitDir = path.join(dir, '.git');
    if (fs.existsSync(gitDir) && fs.statSync(gitDir).isDirectory()) {
      hookFile = path.join(gitDir, 'hooks', 'pre-commit');
    } else {
      process.stderr.write(`--hook: no .git directory in ${dir}; skipping the pre-commit hook\n`);
    }
  }
  const done = [];
  for (const t of targets) {
    if (fs.existsSync(t.file) && !opts.force) { done.push(`skipped (exists): ${t.file}`); continue; }
    fs.mkdirSync(path.dirname(t.file), { recursive: true });
    fs.writeFileSync(t.file, t.body);
    done.push(`wrote ${t.what}: ${t.file}`);
  }
  if (hookFile) {
    if (fs.existsSync(hookFile) && !opts.force) {
      done.push(`skipped (exists): ${hookFile}`);
    } else {
      fs.mkdirSync(path.dirname(hookFile), { recursive: true });
      fs.writeFileSync(hookFile, '#!/bin/sh\n# npm-script-lens: block commits that leave the install-script allowlist out of sync\nexec npx npm-script-lens sync --check --path .\n');
      try { fs.chmodSync(hookFile, 0o755); } catch { /* Windows: git runs it regardless */ }
      done.push(`wrote git pre-commit hook: ${hookFile}`);
    }
  }
  const lines = [
    `npm-script-lens init — detected package manager: ${mgrLabel}`, '',
    ...done.map((d) => `  ${d}`), '',
    'Next steps:',
    '  1. Review script-lens.policy.json (raise maxRisk / add waivers as your team needs).',
    `  2. Run \`npx npm-script-lens allow --write\` to generate your ${mgrLabel} allowlist.`,
    '  3. Commit both — the CI workflow will keep them enforced on every PR.',
    opts.force ? '' : '  (re-run with --force to overwrite existing files)',
  ].filter((l) => l !== '');
  process.stdout.write(`${lines.join('\n')}\n`);
}

// --- sources: git/remote deps vs npm v12's allow-git / allow-remote --------
// npm v12's third flipped default: git and remote-URL dependencies stop
// resolving unless allow-git / allow-remote (enum all|none|root) is set.
// Pure lockfile+package.json+.npmrc analysis — no scan, no network.

async function sourcesAction(opts) {
  const analysis = await analyzeSources(opts.path);
  const config = readSourceConfig(analysis.projectDir);
  if (opts.json) process.stdout.write(`${JSON.stringify(sourcesJson(analysis), null, 2)}\n`);
  else process.stdout.write(`${renderSources(analysis)}\n`);
  for (const w of rootWarnings(analysis)) process.stderr.write(`${w}\n`);
  const npmrcApplies = analysis.lockType === 'npm';

  if (opts.write) {
    if (!npmrcApplies) {
      process.stderr.write(`--write skipped: the .npmrc emitter is npm-only, and this is a ${analysis.lockType} lockfile\n`);
    } else {
      // set each needed key to its minimal value; a committed key that is no
      // longer needed is tightened to an explicit 'none' rather than deleted
      const updates = {};
      for (const kind of ['git', 'remote']) {
        const minimal = analysis[kind].minimal;
        if (minimal !== 'none') updates[SOURCES[kind].key] = minimal;
        else if (config[kind] !== null) updates[SOURCES[kind].key] = 'none';
      }
      if (Object.keys(updates).length === 0) {
        process.stderr.write('nothing to write: no git/remote dependencies and no allow-git/allow-remote entries to correct\n');
      } else {
        const text = config.exists ? fs.readFileSync(config.file, 'utf8') : '';
        const merged = mergeNpmrc(text, updates);
        if (merged === text) {
          process.stderr.write(`${config.file} already has the minimal correct values — nothing to write\n`);
        } else {
          fs.writeFileSync(config.file, merged);
          process.stderr.write(`wrote ${Object.keys(updates).map((k) => `${k}=${updates[k]}`).join(', ')} to ${config.file}\n`);
        }
      }
    }
  }

  if (opts.check) {
    if (!npmrcApplies) {
      process.stderr.write(`sources check skipped: .npmrc allow-git/allow-remote is npm-only, and this is a ${analysis.lockType} lockfile\n`);
      return;
    }
    const { ok, failures } = checkSourceConfig(analysis, config);
    if (ok) {
      process.stderr.write('sources check passed: .npmrc matches the minimal correct allow-git/allow-remote for this lockfile\n');
      return;
    }
    for (const f of failures) process.stderr.write(`FAIL (${f.kind}): ${f.message}\n`);
    process.stderr.write('Run `npm-script-lens sources --write` to set the minimal correct values.\n');
    process.exitCode = 1;
  }
}

// --- doctor: does this build still understand your npm? -------------------

async function doctorAction(opts) {
  const report = await runDoctor({ path: opts.path, offline: opts.offline, live: opts.live });
  if (opts.json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else process.stdout.write(`${renderDoctor(report)}\n`);
  if (!report.ok) process.exitCode = 1; // genuine drift is a CI-actionable failure
}

// --- manifest: a committable behavior receipt, diffable in git ------------

async function manifestAction(opts) {
  const { path: lp } = resolveLockfile(opts.path);
  const file = path.isAbsolute(opts.out) ? opts.out : path.join(path.dirname(lp), opts.out);
  const results = await runAudit(opts.path, {
    log: (m) => process.stderr.write(`${m}\n`),
    cache: opts.cache,
    trust: false, // behavior receipt is deterministic — no OSV/downloads
    offline: opts.offline,
    deep: opts.deep,
  });
  const { manifest, errors } = buildManifest(results, { deep: opts.deep });
  const json = serializeManifest(manifest);
  const count = Object.keys(manifest.packages).length;
  if (errors.length > 0) {
    process.stderr.write(`warning: ${errors.length} package(s) could not be fetched and are omitted: ${errors.slice(0, 5).join(', ')}${errors.length > 5 ? '…' : ''}\n`);
  }
  if (opts.check) {
    if (!fs.existsSync(file)) {
      process.stderr.write(`FAIL: no manifest at ${file} — run: npm-script-lens manifest --write\n`);
      process.exitCode = 1;
      return;
    }
    const committed = fs.readFileSync(file, 'utf8');
    if (committed === json) {
      process.stderr.write(`manifest up to date (${count} package(s) with install-time behavior)\n`);
      return;
    }
    let parsed;
    try { parsed = JSON.parse(committed); } catch { parsed = {}; }
    process.stderr.write('FAIL: audit manifest is out of date. Install-time behavior changed:\n');
    for (const line of diffManifests(parsed, manifest)) process.stderr.write(`  ${line}\n`);
    process.stderr.write('\nReview the changes, then run: npm-script-lens manifest --write\n');
    process.exitCode = 1;
    return;
  }
  if (opts.write) {
    fs.writeFileSync(file, json);
    process.stderr.write(`wrote ${file} (${count} package(s) with install-time behavior)\n`);
  } else {
    process.stdout.write(json);
  }
}

// --- diff: compare install-time scripts of a package across two versions ---

async function diffAction(oldSpec, newSpec, opts) {
  const a = parseSpec(oldSpec);
  const b = parseSpec(newSpec);
  const [oldPkg, newPkg] = await Promise.all([
    fetchScripts(a.name, a.version),
    fetchScripts(b.name, b.version),
  ]);
  const result = computeScriptDiff(oldPkg, newPkg);
  if (opts.json) {
    process.stdout.write(`${JSON.stringify(result.json, null, 2)}\n`);
  } else {
    process.stdout.write(`${renderDiff(oldPkg, newPkg, result)}\n`);
  }
  if (result.changed) process.exitCode = 1;
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
    .option('--html <file>', 'also write a self-contained shareable HTML report')
    .option('--diff <base-lockfile>', 'audit only packages added or upgraded relative to a base lockfile, and report capabilities gained across upgrades')
    .option('--since <git-ref>', 'like --diff, but extract the base lockfile from a git ref (branch, tag, or SHA) automatically — audit only what changed since then')
    .option('--fail-on-high', 'exit 1 if any package scores HIGH or is known malicious')
    .option('--check-v12-gaps', 'run only the npm v12 approve-scripts bug detectors: optional deps missing from allowScripts (npm/cli#9562) and EGLOBAL-prone global installs in CI workflows (npm/cli#9463)')
    .action(auditAction);
  common(program.command('sync'))
    .description('reconcile your package manager\'s native allowlist (npm allowScripts / pnpm allowBuilds / yarn dependenciesMeta / bun trustedDependencies) with the lockfile')
    .option('--manager <pm>', 'target package manager: npm | pnpm | yarn | bun (default: auto-detect from the lockfile)')
    .option('--policy <file>', 'governance policy file (default: script-lens.policy.json if present)')
    .option('--write', 'update the allowlist file in place')
    .option('--check', 'exit 1 when the allowlist is out of sync (for CI)')
    .action(syncAction);
  common(program.command('approve'))
    .description('step through risky packages interactively and write allowScripts decisions')
    .action(approveAction);
  common(program.command('review'))
    .description('show pending npm v12 script approvals WITH their actual script content and OSV verdict — the detail npm approve-scripts --allow-scripts-pending leaves out')
    .option('--json', 'emit JSON instead of terminal output')
    .option('--manager <pm>', 'target package manager: npm | pnpm | yarn | bun (default: auto-detect from the lockfile)')
    .option('--policy <file>', 'governance policy file (default: script-lens.policy.json if present)')
    .option('--output-allowscripts', 'write the decisions into the manager\'s allowlist file (package.json / pnpm-workspace.yaml)')
    .action(reviewAction);
  common(program.command('allow'))
    .description('split scripted packages into an auto-approved allowlist (SAFE/LOW) and a _review list (MEDIUM/HIGH/malicious), in your package manager\'s native format (npm allowScripts · pnpm allowBuilds · yarn dependenciesMeta · bun trustedDependencies); --ci-check fails CI when npm v12 would silently skip install scripts')
    .option('--input <json-file>', 'classify a saved `audit --json` result instead of running a fresh scan')
    .option('--manager <pm>', 'target package manager: npm | pnpm | yarn | bun (default: auto-detect from the lockfile)')
    .option('--policy <file>', 'governance policy file (default: script-lens.policy.json if present)')
    .option('--write', 'merge the auto-approved (SAFE/LOW) entries into the manager\'s allowlist file; _review packages are left out for a manual decision')
    .option('--ci-check', 'exit 1 if a workflow runs npm install, package.json has no allowScripts, and the local npm is v12+ (runs no scan)')
    .action(allowAction);
  common(program.command('manifest'))
    .description('write or verify a committable behavior receipt whose git diff is the approval-surface change')
    .option('--out <file>', 'manifest file (relative paths resolve next to the lockfile)', 'script-lens.json')
    .option('--write', 'write the manifest to disk')
    .option('--check', 'exit 1 if the committed manifest is out of date (for CI)')
    .action(manifestAction);
  program.command('init')
    .description('scaffold a governance policy (script-lens.policy.json) and a CI workflow so a repo adopts npm-script-lens in one command')
    .option('--path <path>', 'project dir', '.')
    .option('--auto-fix', 'also scaffold an auto-fix workflow that reconciles the allowlist on Renovate/Dependabot branches')
    .option('--hook', 'also install a git pre-commit hook that runs `sync --check`')
    .option('--force', 'overwrite existing files')
    .action(initAction);
  program.command('sources')
    .description('report git and remote-URL dependencies against npm v12\'s allow-git/allow-remote defaults: ROOT vs TRANSITIVE per dep, the minimal correct .npmrc, and which transitive deps force allow-git=all — no scan, no network')
    .option('--path <path>', 'project dir or lockfile (package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock)', '.')
    .option('--json', 'emit { git, remote, npmrc } JSON instead of text')
    .option('--write', 'merge the minimal correct allow-git/allow-remote into .npmrc, preserving every other key and comment (npm lockfiles only)')
    .option('--check', 'exit 1 when the committed .npmrc is insufficient, over-permissive, or holds an invalid value for these keys (for CI)')
    .action(sourcesAction);
  program.command('doctor')
    .description('check whether this build still understands your local npm (contract probe + parser self-test + live dry-run shape check) — exit 1 on drift')
    .option('--path <path>', 'project dir or lockfile to probe live', '.')
    .option('--offline', 'skip the live npm dry-run probe')
    .option('--no-live', 'skip the live npm dry-run probe (contract + self-test only)')
    .option('--json', 'emit the structured report as JSON')
    .action(doctorAction);
  program.command('completion')
    .description('print a shell completion script (bash | zsh | fish) — e.g. `source <(npm-script-lens completion bash)`')
    .argument('[shell]', 'bash | zsh | fish', 'bash')
    .action((shell) => process.stdout.write(require('./completion').completionScript(shell)));
  program.command('diff')
    .description('compare a package\'s install-time lifecycle scripts (preinstall/install/postinstall + implicit node-gyp) between two versions — exit 1 if any script was added or changed')
    .argument('<old>', 'baseline spec, e.g. sharp@0.32.6')
    .argument('<new>', 'candidate spec, e.g. sharp@0.33.0')
    .option('--json', 'emit JSON { unchanged, added, removed, modified } instead of colored text')
    .action(diffAction);
  program.command('mcp')
    .description('run as an MCP server on stdio (tools: audit_package, audit_lockfile, classify_allowscripts)')
    .action(() => require('./mcp').serve());
  program.parseAsync().catch((err) => {
    process.stderr.write(`error: ${err.message}\n`);
    process.exit(2);
  });
}

module.exports = { runAudit, auditOne, flatSignals, ciCheckResult, classifyForAllow };
