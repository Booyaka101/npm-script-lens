'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Lockfiles we can read, in the order a directory is searched.
const LOCKFILE_NAMES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];

// Unique name@version pairs from a package-lock.json / npm-shrinkwrap.json
// object (v2/v3 "packages" map, with a v1 "dependencies" fallback). Root
// project and link: entries skipped.
function collectNpmDeps(lock) {
  const deps = new Map();
  if (lock.packages) {
    for (const [key, entry] of Object.entries(lock.packages)) {
      // no node_modules/ prefix = the root project or a local workspace package
      if (!key.includes('node_modules/') || !entry.version || entry.link) continue;
      const name = entry.name || key.split('node_modules/').pop();
      if (name && !name.startsWith('.')) deps.set(`${name}@${entry.version}`, { name, version: entry.version });
    }
  } else if (lock.dependencies) {
    const visit = (obj) => {
      for (const [name, entry] of Object.entries(obj)) {
        if (entry.version) deps.set(`${name}@${entry.version}`, { name, version: entry.version });
        if (entry.dependencies) visit(entry.dependencies);
      }
    };
    visit(lock.dependencies);
  }
  return [...deps.values()];
}

// Selectors whose range points outside the registry — the tarball we would
// fetch is not the code that installs, so skip rather than mislead.
const NON_REGISTRY = /^(file|link|portal|workspace|patch|git\+|github:)|:\/\//;

// "name@range" -> the package name the registry knows, or null to skip.
// Handles scopes (first @ past position 0 splits) and classic yarn aliases
// ("alias@npm:real-name@^2" installs real-name).
function yarnSelectorName(sel) {
  const at = sel.indexOf('@', 1);
  if (at < 0) return null;
  let name = sel.slice(0, at);
  const range = sel.slice(at + 1);
  if (range.startsWith('npm:')) {
    const real = range.slice(4);
    const rat = real.indexOf('@', 1);
    name = rat > 0 ? real.slice(0, rat) : real;
  } else if (NON_REGISTRY.test(range)) return null;
  return name;
}

function parseYarnClassic(text) {
  const deps = new Map();
  let selectors = [];
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(raw)) {
      selectors = raw.replace(/:\s*$/, '').split(',').map((s) => s.trim().replace(/^"|"$/g, ''));
    } else {
      const m = raw.match(/^\s+version:?\s+"?([^"\s]+)"?/);
      if (m && selectors.length > 0) {
        for (const sel of selectors) {
          const name = yarnSelectorName(sel);
          if (name) deps.set(`${name}@${m[1]}`, { name, version: m[1] });
        }
        selectors = [];
      }
    }
  }
  return [...deps.values()];
}

// Berry lockfiles carry an exact "resolution: name@npm:version" per entry —
// use it and accept only the npm: protocol (workspace:/patch:/portal: entries
// are local code, not registry tarballs).
function parseYarnBerry(text) {
  const deps = new Map();
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s+resolution:\s*"?([^"]+?)"?\s*$/);
    if (!m) continue;
    const at = m[1].indexOf('@', 1);
    if (at < 0) continue;
    const name = m[1].slice(0, at);
    const rest = m[1].slice(at + 1);
    if (!rest.startsWith('npm:')) continue;
    const version = rest.slice(4).split('::')[0]; // strip ::__archiveUrl=…
    if (version) deps.set(`${name}@${version}`, { name, version });
  }
  return [...deps.values()];
}

const parseYarnLock = (text) => (text.includes('__metadata:') ? parseYarnBerry(text) : parseYarnClassic(text));

// pnpm-lock.yaml "packages:" keys across format generations:
//   v5  /name/1.2.3_peerstuff        v6  /name@1.2.3(peer@2.0.0)
//   v9  name@1.2.3   (quoted when scoped)
function parsePnpmLock(text) {
  const deps = new Map();
  let inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^packages:\s*$/.test(line)) { inPackages = true; continue; }
    if (inPackages && /^\S/.test(line)) inPackages = false;
    if (!inPackages) continue;
    const m = line.match(/^  ['"]?([^'"]+?)['"]?:\s*$/);
    if (!m) continue;
    let key = m[1].replace(/\([^)]*\)/g, '');
    // v5 peer suffix ("/name/1.2.3_peer@2.0.0") can itself contain @ — strip
    // it before locating the name/version split
    key = key.replace(/(\/\d+\.\d+\.\d+[^_/]*)_[^/]*$/, '$1');
    if (NON_REGISTRY.test(key)) continue;
    if (key.startsWith('/')) key = key.slice(1);
    let name, version;
    const at = key.lastIndexOf('@');
    if (at > 0) {
      name = key.slice(0, at);
      version = key.slice(at + 1);
    } else {
      const slash = key.lastIndexOf('/');
      if (slash < 0) continue;
      name = key.slice(0, slash);
      version = key.slice(slash + 1);
    }
    version = version.split('_')[0]; // v5 peer suffix
    // registry versions are semver; git hashes and tarball keys are not
    if (name && /^\d+\.\d+\.\d+/.test(version)) deps.set(`${name}@${version}`, { name, version });
  }
  return [...deps.values()];
}

// Accepts a directory (searched in LOCKFILE_NAMES order) or a lockfile path;
// returns { path, type: 'npm' | 'yarn' | 'pnpm' }.
function resolveLockfile(input) {
  let p = path.resolve(input);
  if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
    const found = LOCKFILE_NAMES.map((n) => path.join(p, n)).find((f) => fs.existsSync(f));
    if (!found) throw new Error(`lockfile not found in ${p} (looked for ${LOCKFILE_NAMES.join(', ')})`);
    p = found;
  } else if (!fs.existsSync(p)) {
    throw new Error(`lockfile not found: ${p} (run npm install --package-lock-only)`);
  }
  const base = path.basename(p);
  const type = base === 'yarn.lock' ? 'yarn' : base.startsWith('pnpm-lock') ? 'pnpm' : 'npm';
  return { path: p, type };
}

function loadDeps(input) {
  const { path: p, type } = resolveLockfile(input);
  const text = fs.readFileSync(p, 'utf8');
  const deps = type === 'yarn' ? parseYarnLock(text)
    : type === 'pnpm' ? parsePnpmLock(text)
      : collectNpmDeps(JSON.parse(text));
  return { lockPath: p, type, deps };
}

module.exports = { LOCKFILE_NAMES, collectNpmDeps, parseYarnLock, parsePnpmLock, resolveLockfile, loadDeps };
