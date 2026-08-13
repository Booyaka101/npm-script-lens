'use strict';
// npm v12 flips THREE defaults, not one. allowScripts has the rest of this
// tool; this module covers the other two: `allow-git` and `allow-remote`,
// both the strict enum all|none|root defaulting to 'none' (see SOURCES in
// npm-contract.js). 'root' allows only deps declared in the ROOT
// package.json; any transitive git/remote dep forces 'all'. Pure lockfile +
// package.json + .npmrc analysis, no registry calls.
const fs = require('node:fs');
const path = require('node:path');
const { resolveLockfile, loadDeps, collectNonRegistryDeps, viaChain } = require('./lockfiles');
const { npmMajorVersion } = require('./review');
const { SOURCES, DETECTORS } = require('./npm-contract');
const { readSourceConfig } = require('./npmrc');

const KINDS = ['git', 'remote'];
const LEVEL = { none: 0, root: 1, all: 2 };

// "11.16.1" >= "11.10.0"?  (numeric dotted compare, no semver dependency)
function versionGte(a, b) {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0);
  }
  return true;
}

// Names declared in the ROOT package.json, the only declarations
// allow-*=root honors. A dep declared only in a workspace package's
// package.json is deliberately NOT here (npm resolves root against the
// project root; we classify workspace-declared deps conservatively as
// transitive).
function rootDeclaredNames(projectDir) {
  const names = new Set();
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const n of Object.keys(pkg[field] || {})) names.add(n);
    }
  } catch { /* no package.json, nothing is root-declared */ }
  return names;
}

// analyzeSources(target) -> { git: {deps, minimal, forcing}, remote: {…},
// npmMajor, lockType, projectDir }. Each dep: {name, spec, resolved, root,
// via?}. A dep counts as root only when it is root-declared AND has no
// package-level parent declaring it (i.e. every occurrence is root);
// minimal = 'none' | 'root' | 'all'. forcing lists the transitive deps (the
// ones that force 'all') with their via-chains.
async function analyzeSources(target, { probeNpm = true } = {}) {
  const { path: lockPath, type } = resolveLockfile(target);
  const projectDir = path.dirname(lockPath);
  const { edges } = loadDeps(target);
  const found = collectNonRegistryDeps(fs.readFileSync(lockPath, 'utf8'), type);
  const rootNames = rootDeclaredNames(projectDir);
  const out = {
    npmMajor: probeNpm ? await npmMajorVersion(projectDir) : null,
    lockType: type,
    projectDir,
  };
  for (const kind of KINDS) {
    const deps = [];
    for (const d of found.filter((f) => f.kind === kind)) {
      const root = rootNames.has(d.name) && d.parents.length === 0;
      const dep = { name: d.name, spec: d.spec, resolved: d.resolved, root };
      if (!root) {
        const chain = viaChain(edges, d.name);
        dep.via = [...(chain.length > 0 ? chain : d.parents.slice(0, 1)), d.name];
      }
      deps.push(dep);
    }
    deps.sort((a, b) => (a.root === b.root ? a.name.localeCompare(b.name) : a.root ? -1 : 1));
    const forcing = deps.filter((d) => !d.root).map((d) => ({ name: d.name, via: d.via }));
    out[kind] = {
      deps,
      minimal: deps.length === 0 ? 'none' : forcing.length === 0 ? 'root' : 'all',
      forcing,
    };
  }
  return out;
}

// The minimal correct .npmrc content: one line per source that needs opting
// in, nothing for sources with no such deps ('' when neither needs a line).
function minimalNpmrc(analysis) {
  let text = '';
  for (const kind of KINDS) {
    if (analysis[kind].minimal !== 'none') text += `${SOURCES[kind].key}=${analysis[kind].minimal}\n`;
  }
  return text;
}

// The exact { git, remote, npmrc } shape `sources --json` emits: deps +
// minimal per source, forcing only when something forces 'all'.
function sourcesJson(analysis) {
  const one = (a) => {
    const o = { deps: a.deps, minimal: a.minimal };
    if (a.forcing.length > 0) o.forcing = a.forcing;
    return o;
  };
  return { git: one(analysis.git), remote: one(analysis.remote), npmrc: minimalNpmrc(analysis) };
}

const plural = (n, word) => `${n} ${word}${n === 1 ? 'y' : 'ies'}`;

// Human report. Deterministic, everything here derives from the lockfile
// and package.json only (npm-version caveats go to stderr via rootWarnings,
// so this stays byte-stable for CI diffing).
function renderSources(analysis) {
  const lines = [];
  for (const kind of KINDS) {
    const a = analysis[kind];
    lines.push(`${kind} dependencies (${a.deps.length})`);
    for (const d of a.deps) {
      const via = !d.root && d.via && d.via.length > 1 ? `   via ${d.via.join(' -> ')}` : '';
      lines.push(`  ${(d.root ? 'ROOT' : 'TRANSITIVE').padEnd(10)}  ${d.name} @ ${d.spec}${via}`);
    }
  }
  lines.push('');
  const needed = KINDS.filter((k) => analysis[k].minimal !== 'none');
  if (needed.length > 0) {
    lines.push('minimal correct .npmrc:');
    for (const kind of needed) lines.push(`  ${SOURCES[kind].key}=${analysis[kind].minimal}`);
    lines.push('');
    for (const kind of needed) {
      const { key } = SOURCES[kind];
      const a = analysis[kind];
      if (a.minimal === 'all') {
        const n = a.forcing.length;
        lines.push(`${key}=all is required because ${n} ${kind} ${n === 1 ? 'dependency is' : 'dependencies are'} transitive; ${key}=root would otherwise suffice.`);
        for (const f of a.forcing) {
          const chain = f.via && f.via.length > 1 ? ` (via ${f.via.slice(0, -1).join(' -> ')})` : '';
          lines.push(`Re-point or drop \`${f.name}\`${chain} to tighten this to ${key}=root.`);
        }
      } else {
        lines.push(`${key}=root suffices: every ${kind} dependency is declared in the root package.json.`);
      }
    }
  } else {
    for (const kind of KINDS) lines.push(`${SOURCES[kind].key} not needed (no ${kind} dependencies)`);
  }
  if (analysis.lockType !== 'npm') {
    lines.push('', `note: the .npmrc emitter targets npm only — this is a ${analysis.lockType} lockfile, and ${analysis.lockType} does not read allow-git/allow-remote from .npmrc. The dependency report above still applies.`);
  }
  return lines.join('\n');
}

// npm-version caveats for the report (stderr, so stdout stays deterministic):
//  - npm 11 wrongly rejected ROOT git deps under allow-git=root (npm/cli#9189,
//    closed via PR #9206; fixed version not pinned), recommending `root` on
//    npm 11 must come with a warning to prefer `all`.
//  - npm < 11.10/11.15 predates the keys entirely.
function rootWarnings(analysis) {
  const warnings = [];
  const major = analysis.npmMajor;
  if (major === null) return warnings;
  for (const kind of KINDS) {
    const { key, introduced } = SOURCES[kind];
    if (analysis[kind].minimal !== 'root') continue;
    if (major === SOURCES.enforcedInNpm - 1) {
      const d = DETECTORS.allowGitRoot;
      warnings.push(`⚠️  ${key}=root is unreliable on npm v${major}: root-level git deps were wrongly rejected (${d.issue}, ${d.upstream}${d.fixedInNpm ? `, fixed in npm v${d.fixedInNpm}` : '; fixed npm version not yet pinned'}). Recommend ${key}=all until your npm verifiably carries the fix.`);
    } else if (major < SOURCES.enforcedInNpm - 1) {
      warnings.push(`note: local npm v${major} predates ${key} (introduced in npm ${introduced}); the setting takes effect once you upgrade — npm v${SOURCES.enforcedInNpm} enforces the '${SOURCES.default}' default.`);
    }
  }
  return warnings;
}

// Compare the committed .npmrc against the minimal correct values. config is
// readSourceConfig(dir) output. Fails in three distinct ways:
//   invalid: a value outside the all|none|root enum (e.g. the
//                      `allow-git=true` some migration guides recommend)
//   insufficient: installs will BREAK on npm v12 (committed < minimal)
//   over-permissive, installs work but more is allowed than the tree needs
function checkSourceConfig(analysis, config) {
  const failures = [];
  for (const kind of KINDS) {
    const { key } = SOURCES[kind];
    const committed = config[kind];
    if (committed !== null && !SOURCES.values.includes(committed)) {
      failures.push({
        source: kind,
        kind: 'invalid',
        message: `.npmrc has ${key}=${committed}, which is not a valid value — ${key} is an enum: ${SOURCES.values.join(' | ')}. (A bare --${key} or ${key}=true does NOT enable ${kind} dependencies; npm v${SOURCES.enforcedInNpm} treats it as unset.)`,
      });
      continue;
    }
    const effective = committed === null ? SOURCES.default : committed;
    const minimal = analysis[kind].minimal;
    if (LEVEL[effective] < LEVEL[minimal]) {
      const n = analysis[kind].deps.length;
      failures.push({
        source: kind,
        kind: 'insufficient',
        message: `${key}=${effective}${committed === null ? ` (the npm v${SOURCES.enforcedInNpm} default — no .npmrc entry)` : ' (committed)'} is insufficient: ${plural(n, `${kind} dependenc`)} in the lockfile need${n === 1 ? 's' : ''} ${key}=${minimal} — npm v${SOURCES.enforcedInNpm} will refuse to install ${n === 1 ? 'it' : 'them'}.`,
      });
    } else if (LEVEL[effective] > LEVEL[minimal]) {
      failures.push({
        source: kind,
        kind: 'over-permissive',
        message: `${key}=${committed} (committed) is over-permissive: ${minimal === 'none'
          ? `the lockfile has no ${kind} dependencies — remove the line (or set ${key}=none)`
          : `every ${kind} dependency is declared in the root package.json — tighten to ${key}=root`}.`,
      });
    }
  }
  return { ok: failures.length === 0, failures };
}

module.exports = {
  analyzeSources, minimalNpmrc, sourcesJson, renderSources, rootWarnings,
  checkSourceConfig, versionGte, readSourceConfig,
};
