'use strict';
// Detectors for two known npm v12 approve-scripts tooling bugs:
//  - npm/cli#9562: `npm approve-scripts --allow-scripts-pending` never surfaces
//    optional dependencies, but `npm ci --strict-allow-scripts` rejects any
//    optional dep with install scripts that is missing from allowScripts.
//  - npm/cli#9463: `npm approve-scripts` errors with EGLOBAL in global-install
//    contexts, so CI lines like `npm install -g pkg` have no approval path —
//    the working form is `npm install -g --allow-scripts=pkg pkg`.
const fs = require('node:fs');
const path = require('node:path');
const { resolveLockfile } = require('./lockfiles');
const { REGISTRY, LIFECYCLE } = require('./registry');
const { npmFullVersion } = require('./review');
const { DETECTORS, INERT_SKIP_FROM, skipsInertOptional } = require('./npm-contract');

// Best-effort version metadata: null on any failure — these checks warn on
// what they can confirm and stay quiet (or fall back to lockfile facts)
// otherwise.
async function versionMeta(name, version) {
  try {
    const res = await fetch(`${REGISTRY}/${name.replace('/', '%2f')}/${encodeURIComponent(version)}`, {
      signal: AbortSignal.timeout(30000),
      headers: { accept: 'application/json' },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

const lifecycleNames = (meta) => (meta && meta.scripts
  ? LIFECYCLE.filter((k) => typeof meta.scripts[k] === 'string')
  : []);

// Optional entries from a package-lock.json object. hasInstallScript is
// authoritative in v2/v3 lockfiles (present iff true); null for the v1
// fallback, where only the registry can answer.
function collectOptionalDeps(lock) {
  const out = new Map();
  if (lock.packages) {
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (!key.includes('node_modules/') || !entry.version || entry.link || !entry.optional) continue;
      const name = entry.name || key.split('node_modules/').pop();
      if (!name || name.startsWith('.')) continue;
      const id = `${name}@${entry.version}`;
      if (!out.has(id)) {
        out.set(id, {
          name,
          version: entry.version,
          hasInstallScript: entry.hasInstallScript === true,
          // npm records os/cpu on the lockfile entry for platform-specific
          // deps; the registry copy (versionMeta) is the fallback.
          os: Array.isArray(entry.os) ? entry.os : null,
          cpu: Array.isArray(entry.cpu) ? entry.cpu : null,
        });
      }
    }
  } else if (lock.dependencies) {
    const visit = (obj) => {
      for (const [name, entry] of Object.entries(obj)) {
        if (entry.version && entry.optional) {
          const id = `${name}@${entry.version}`;
          if (!out.has(id)) out.set(id, { name, version: entry.version, hasInstallScript: null });
        }
        if (entry.dependencies) visit(entry.dependencies);
      }
    };
    visit(lock.dependencies);
  }
  return [...out.values()];
}

const optionalGapFix = (name, npmVersion) => `Add to allowScripts in package.json: { "allowScripts": { "${name}": true } } — npm approve-scripts will not surface this package but npm ci --strict-allow-scripts will reject it (npm/cli#9562). Checked against npm ${npmVersion || 'version unknown'}; fixed for INERT optional deps in npm >= ${INERT_SKIP_FROM.npm11} (and >= ${INERT_SKIP_FROM.npm12} on the v12 line) via PR #9597, which skips inert nodes during the script-collection walk — this package is still reported because it is not inert on this platform (or your npm predates the fix).`;

// npm's os/cpu matching: a bare entry allowlists, a `!`-prefixed one blocks.
// Empty/absent list = every platform. Mirrors npm's own checkPlatform.
function platformAllows(list, value) {
  if (!Array.isArray(list) || list.length === 0) return true;
  const blocked = [];
  const allowed = [];
  for (const raw of list) {
    if (typeof raw !== 'string') continue;
    if (raw.startsWith('!')) blocked.push(raw.slice(1));
    else allowed.push(raw);
  }
  if (blocked.includes(value)) return false;
  if (allowed.length > 0) return allowed.includes(value) || allowed.includes('any');
  return true;
}

// "Inert" the way npm's reify means it: the dependency's os/cpu exclude this
// machine, so npm removes it from the tree BEFORE install scripts run. Since
// PR #9597 the strict check skips these, so warning about them (the classic
// "allowlist fsevents on Linux" false positive) is wrong on a modern npm.
const isInertHere = (osList, cpuList) => !platformAllows(osList, process.platform) || !platformAllows(cpuList, process.arch);

// Check 1 — optional deps with install scripts missing from allowScripts.
// npm-lockfile-only: the bug lives in npm's own approve-scripts/ci pair.
// Version-gated: on an npm carrying PR #9597 the inert candidates are dropped.
async function checkOptionalGap(target, { concurrency = 6, npmVersion } = {}) {
  const { path: lockPath, type } = resolveLockfile(target);
  if (type !== 'npm') return [];
  let lock;
  try { lock = JSON.parse(fs.readFileSync(lockPath, 'utf8')); } catch { return []; }
  let allow = {};
  try {
    allow = JSON.parse(fs.readFileSync(path.join(path.dirname(lockPath), 'package.json'), 'utf8')).allowScripts || {};
  } catch { /* no package.json — nothing is approved */ }
  const localNpm = npmVersion === undefined ? await npmFullVersion(path.dirname(lockPath)) : npmVersion;
  const skipInert = skipsInertOptional(localNpm);
  const candidates = collectOptionalDeps(lock)
    // hasInstallScript false is authoritative (v2/v3): no install scripts, skip
    .filter((d) => d.hasInstallScript !== false)
    // covered under either allowScripts key form: bare name or name@version
    .filter((d) => !(d.name in allow) && !(`${d.name}@${d.version}` in allow))
    // on a fixed npm, a dep the lockfile already marks platform-inert never
    // reaches the strict check — drop it before spending a registry request
    .filter((d) => !(skipInert && (d.os || d.cpu) && isInertHere(d.os, d.cpu)));
  const findings = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, candidates.length) }, async () => {
    while (i < candidates.length) {
      const d = candidates[i++];
      const meta = await versionMeta(d.name, d.version);
      // the registry copy of os/cpu answers when the lockfile omitted them
      if (skipInert && meta && (Array.isArray(meta.os) || Array.isArray(meta.cpu))
          && isInertHere(meta.os, meta.cpu)) continue;
      const names = lifecycleNames(meta);
      let script;
      if (names.length > 0) script = names.join(', ');
      else if (meta && meta.hasInstallScript) script = 'install (implicit node-gyp rebuild)';
      else if (meta) continue; // registry says no install scripts after all
      else if (d.hasInstallScript === true) script = 'unknown (hasInstallScript in lockfile; registry metadata unavailable)';
      else continue; // v1 lockfile, registry unreachable — cannot confirm
      findings.push({
        id: DETECTORS.optionalGap.id,
        severity: 'warn',
        package: d.name,
        version: d.version,
        script,
        fix: optionalGapFix(d.name, localNpm),
        issue: DETECTORS.optionalGap.issue,
        upstream: DETECTORS.optionalGap.upstream,
      });
    }
  }));
  return findings.sort((a, b) => a.package.localeCompare(b.package));
}

// --- check 2: EGLOBAL-prone global installs in CI workflows ---------------

// npm flags that consume the next token, so it must not be read as a package
// spec.
const VALUE_FLAGS = new Set(['--registry', '--location', '--prefix', '--loglevel', '--cache', '--userconfig', '--omit', '--include', '--allow-scripts']);

// `npm install|i|add …` occurrences in one line of a workflow run: block.
// Returns [{ specs, global, allowed }] — allowed when the command already
// carries --allow-scripts / --ignore-scripts.
function globalNpmInstalls(line) {
  const out = [];
  for (const m of line.matchAll(/\bnpm\s+(?:install|i|add)\b([^&|;><#\n]*)/g)) {
    const args = m[1].trim().split(/\s+/).filter(Boolean).map((a) => a.replace(/^['"]|['"]$/g, ''));
    const hit = { specs: [], global: false, allowed: false };
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '-g' || a === '--global' || a === '--location=global') { hit.global = true; continue; }
      if (a === '--ignore-scripts' || a === '--allow-scripts' || a.startsWith('--allow-scripts=')) {
        hit.allowed = true;
        if (a === '--allow-scripts' && args[i + 1] && !args[i + 1].startsWith('-')) i++;
        continue;
      }
      if (a.startsWith('--')) {
        if (VALUE_FLAGS.has(a)) {
          if (a === '--location' && args[i + 1] === 'global') hit.global = true;
          i++;
        }
        continue;
      }
      if (a.startsWith('-')) continue;
      // URLs, git refs, tarballs, and paths have no registry metadata to check
      if (/^(https?:|git(\+|:)|github:|file:|[./~\\])/.test(a)) continue;
      hit.specs.push(a);
    }
    if (hit.global) out.push(hit);
  }
  return out;
}

// "name" | "name@ver" | "@scope/name" | "@scope/name@ver"
function splitSpec(spec) {
  const at = spec.indexOf('@', 1);
  return at > 0 ? { name: spec.slice(0, at), version: spec.slice(at + 1) } : { name: spec, version: null };
}

function workflowFiles(projectDir) {
  const dir = path.join(projectDir, '.github', 'workflows');
  let names = [];
  try { names = fs.readdirSync(dir); } catch { return []; }
  return names.filter((n) => /\.ya?ml$/i.test(n)).sort().map((n) => path.join(dir, n));
}

const eglobalFix = (name) => `Replace \`npm install -g ${name}\` with \`npm install -g --allow-scripts=${name} ${name}\` — npm approve-scripts fails with EGLOBAL in global install contexts (npm/cli#9463)`;

// Check 2 — `npm install -g <pkg>` in .github/workflows/*.yml where <pkg> has
// install scripts (per registry metadata) and the command carries no
// --allow-scripts: there is no post-install approval path (EGLOBAL), the
// scripts silently stay blocked.
async function checkEglobal(target, { concurrency = 6 } = {}) {
  const { path: lockPath } = resolveLockfile(target);
  const projectDir = path.dirname(lockPath);
  const sites = [];
  const seen = new Set();
  for (const file of workflowFiles(projectDir)) {
    const rel = path.relative(projectDir, file).replace(/\\/g, '/');
    fs.readFileSync(file, 'utf8').split(/\r?\n/).forEach((line, idx) => {
      if (/^\s*#/.test(line)) return;
      for (const hit of globalNpmInstalls(line)) {
        if (hit.allowed) continue;
        for (const spec of hit.specs) {
          const { name, version } = splitSpec(spec);
          const key = `${name}~${rel}~${idx + 1}`;
          if (seen.has(key)) continue;
          seen.add(key);
          sites.push({ name, version, file: rel, line: idx + 1 });
        }
      }
    });
  }
  const findings = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, sites.length) }, async () => {
    while (i < sites.length) {
      const s = sites[i++];
      const exact = s.version && /^\d+\.\d+\.\d+/.test(s.version) ? s.version : 'latest';
      const meta = await versionMeta(s.name, exact);
      if (!meta) continue; // not on the registry (or unreachable) — cannot confirm
      const names = lifecycleNames(meta);
      if (names.length === 0 && !meta.hasInstallScript) continue;
      findings.push({
        id: DETECTORS.eglobal.id,
        severity: 'warn',
        package: s.name,
        script: names.join(', ') || 'install (implicit node-gyp rebuild)',
        file: s.file,
        line: s.line,
        fix: eglobalFix(s.name),
        issue: DETECTORS.eglobal.issue,
        upstream: DETECTORS.eglobal.upstream,
      });
    }
  }));
  return findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.package.localeCompare(b.package));
}

async function checkV12Gaps(target, { log = () => {} } = {}) {
  const { path: lockPath } = resolveLockfile(target);
  const projectDir = path.dirname(lockPath);
  // Probed once up front: the optional-gap detector is version-gated on it
  // (PR #9597), so it must not be a second, racing `npm --version` spawn.
  const npmVersion = await npmFullVersion(projectDir);
  const npmMajor = npmVersion ? parseInt(npmVersion.split('.')[0], 10) : null;
  const [optional, eglobal] = await Promise.all([
    checkOptionalGap(target, { npmVersion }), checkEglobal(target),
  ]);
  const findings = [...optional, ...eglobal];
  log(`v12 gap check: ${optional.length} optional-dep gap(s), ${eglobal.length} EGLOBAL-prone global install(s)`
    + ` (local npm ${npmVersion === null ? 'version unknown' : `v${npmVersion}`}`
    + `${skipsInertOptional(npmVersion) ? '; carries the npm/cli#9562 inert-optional fix, so inert optional deps are not reported' : ''})`);
  return { findings, npmMajor, npmVersion };
}

module.exports = {
  checkV12Gaps, checkOptionalGap, checkEglobal, collectOptionalDeps,
  globalNpmInstalls, splitSpec, workflowFiles, platformAllows, isInertHere,
};
