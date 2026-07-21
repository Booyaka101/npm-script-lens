'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Lockfiles we can read, in the order a directory is searched.
const LOCKFILE_NAMES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'];

// Every parser returns { deps: [{name, version}], edges: Map<name, Set<depName>> }.
// Edges are name-level (versions collapse) — enough for "via" chains, not for
// exact resolution, which the audit itself doesn't need.
const addEdge = (edges, from, to) => {
  if (!from || !to || from === to) return;
  if (!edges.has(from)) edges.set(from, new Set());
  edges.get(from).add(to);
};

// Unique name@version pairs from a package-lock.json / npm-shrinkwrap.json
// object (v2/v3 "packages" map, with a v1 "dependencies" fallback). Root
// project and link: entries skipped.
function collectNpmDeps(lock) {
  const deps = new Map();
  const edges = new Map();
  if (lock.packages) {
    for (const [key, entry] of Object.entries(lock.packages)) {
      // no node_modules/ prefix = the root project or a local workspace package
      if (!key.includes('node_modules/') || !entry.version || entry.link) continue;
      const name = entry.name || key.split('node_modules/').pop();
      if (!name || name.startsWith('.')) continue;
      // first occurrence wins so lockKey points at the shallowest install path
      const mapKey = `${name}@${entry.version}`;
      if (!deps.has(mapKey)) deps.set(mapKey, { name, version: entry.version, lockKey: key });
      for (const dep of Object.keys({ ...entry.dependencies, ...entry.optionalDependencies })) {
        addEdge(edges, name, dep);
      }
    }
  } else if (lock.dependencies) {
    const visit = (obj, parent) => {
      for (const [name, entry] of Object.entries(obj)) {
        if (entry.version) deps.set(`${name}@${entry.version}`, { name, version: entry.version });
        if (parent) addEdge(edges, parent, name);
        for (const dep of Object.keys(entry.requires || {})) addEdge(edges, name, dep);
        if (entry.dependencies) visit(entry.dependencies, name);
      }
    };
    visit(lock.dependencies, null);
  }
  return { deps: [...deps.values()], edges };
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
  const edges = new Map();
  let selectors = [];
  let entryName = null;
  let inDeps = false;
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(raw)) {
      selectors = raw.replace(/:\s*$/, '').split(',').map((s) => s.trim().replace(/^"|"$/g, ''));
      entryName = selectors.length > 0 ? yarnSelectorName(selectors[0]) : null;
      inDeps = false;
      continue;
    }
    if (/^\s{2}(optionalD|d)ependencies:\s*$/.test(raw)) { inDeps = true; continue; }
    if (/^\s{2}\S/.test(raw)) inDeps = false;
    const dep = inDeps && raw.match(/^\s{4}"?((?:@[^/"]+\/)?[^"\s]+)"?\s/);
    if (dep) { addEdge(edges, entryName, dep[1]); continue; }
    const m = raw.match(/^\s+version:?\s+"?([^"\s]+)"?/);
    if (m && selectors.length > 0) {
      for (const sel of selectors) {
        const name = yarnSelectorName(sel);
        if (name) deps.set(`${name}@${m[1]}`, { name, version: m[1] });
      }
      selectors = [];
    }
  }
  return { deps: [...deps.values()], edges };
}

// Berry lockfiles carry an exact "resolution: name@npm:version" per entry —
// use it and accept only the npm: protocol (workspace:/patch:/portal: entries
// are local code, not registry tarballs). Within an entry, resolution always
// precedes dependencies, so edges attribute to the right package.
function parseYarnBerry(text) {
  const deps = new Map();
  const edges = new Map();
  let entryName = null;
  let inDeps = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) { entryName = null; inDeps = false; continue; }
    const res = line.match(/^\s+resolution:\s*"?([^"]+?)"?\s*$/);
    if (res) {
      const at = res[1].indexOf('@', 1);
      if (at < 0) continue;
      const name = res[1].slice(0, at);
      const rest = res[1].slice(at + 1);
      if (!rest.startsWith('npm:')) continue;
      const version = rest.slice(4).split('::')[0]; // strip ::__archiveUrl=…
      if (version) {
        deps.set(`${name}@${version}`, { name, version });
        entryName = name;
      }
      continue;
    }
    if (/^\s{2}(optionalD|d)ependencies:\s*$/.test(line)) { inDeps = true; continue; }
    if (/^\s{2}\S/.test(line)) { inDeps = false; continue; }
    const dep = inDeps && line.match(/^\s{4}"?((?:@[^/"]+\/)?[^"\s:]+)"?:/);
    if (dep) addEdge(edges, entryName, dep[1]);
  }
  return { deps: [...deps.values()], edges };
}

const parseYarnLock = (text) => (text.includes('__metadata:') ? parseYarnBerry(text) : parseYarnClassic(text));

// pnpm-lock.yaml package keys across format generations:
//   v5  /name/1.2.3_peerstuff        v6  /name@1.2.3(peer@2.0.0)
//   v9  name@1.2.3   (quoted when scoped)
function splitPnpmKey(rawKey) {
  let key = rawKey.replace(/\([^)]*\)/g, '');
  // v5 peer suffix ("/name/1.2.3_peer@2.0.0") can itself contain @ — strip
  // it before locating the name/version split
  key = key.replace(/(\/\d+\.\d+\.\d+[^_/]*)_[^/]*$/, '$1');
  if (NON_REGISTRY.test(key)) return null;
  if (key.startsWith('/')) key = key.slice(1);
  let name, version;
  const at = key.lastIndexOf('@');
  if (at > 0) {
    name = key.slice(0, at);
    version = key.slice(at + 1);
  } else {
    const slash = key.lastIndexOf('/');
    if (slash < 0) return null;
    name = key.slice(0, slash);
    version = key.slice(slash + 1);
  }
  version = version.split('_')[0]; // v5 peer suffix
  // registry versions are semver; git hashes and tarball keys are not
  if (!name || !/^\d+\.\d+\.\d+/.test(version)) return null;
  return { name, version };
}

// Deps come from the "packages:" section; edges from the per-entry
// dependencies sub-maps in "packages:" (v5/v6) or "snapshots:" (v9).
function parsePnpmLock(text) {
  const deps = new Map();
  const edges = new Map();
  let section = null;
  let entryName = null;
  let inDeps = false;
  for (const line of text.split(/\r?\n/)) {
    const top = line.match(/^(\w+):\s*$/);
    if (top) { section = top[1]; entryName = null; inDeps = false; continue; }
    if (/^\S/.test(line)) { section = null; continue; }
    if (section !== 'packages' && section !== 'snapshots') continue;
    // entry keys sit at exactly 2 spaces — [^\s'"] keeps deeper-indented
    // property lines (resolution:, dependencies:) from matching
    const entry = line.match(/^  ['"]?([^\s'"][^'"]*?)['"]?:\s*(\{\})?\s*$/);
    if (entry) {
      const split = splitPnpmKey(entry[1]);
      entryName = split ? split.name : null;
      inDeps = false;
      if (split && section === 'packages') deps.set(`${split.name}@${split.version}`, split);
      continue;
    }
    if (/^\s{4}(optionalD|d)ependencies:\s*$/.test(line)) { inDeps = true; continue; }
    if (/^\s{4}\S/.test(line)) { inDeps = false; continue; }
    const dep = inDeps && line.match(/^\s{6}['"]?((?:@[^/'"]+\/)?[^'"\s:]+)['"]?:/);
    if (dep) addEdge(edges, entryName, dep[1]);
  }
  return { deps: [...deps.values()], edges };
}

// bun.lock is JSONC: strip comments and trailing commas, then JSON. Package
// values are arrays whose first element is "name@version" and whose first
// object element carries the dependency maps. (bun.lockb is binary — ask for
// the text lockfile instead.)
function stripJsonc(text) {
  let out = '';
  let inStr = false, inLine = false, inBlock = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i], next = text[i + 1];
    if (inLine) { if (ch === '\n') { inLine = false; out += ch; } continue; }
    if (inBlock) { if (ch === '*' && next === '/') { inBlock = false; i++; } continue; }
    if (inStr) {
      out += ch;
      if (ch === '\\') { out += next; i++; } else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; out += ch; continue; }
    if (ch === '/' && next === '/') { inLine = true; continue; }
    if (ch === '/' && next === '*') { inBlock = true; i++; continue; }
    out += ch;
  }
  return out.replace(/,\s*([}\]])/g, '$1');
}

function parseBunLock(text) {
  const deps = new Map();
  const edges = new Map();
  let lock;
  try { lock = JSON.parse(stripJsonc(text)); } catch { return { deps: [], edges }; }
  for (const value of Object.values(lock.packages || {})) {
    const spec = Array.isArray(value) ? value[0] : value;
    if (typeof spec !== 'string' || NON_REGISTRY.test(spec)) continue;
    const at = spec.lastIndexOf('@');
    if (at <= 0) continue;
    const name = spec.slice(0, at);
    const version = spec.slice(at + 1);
    if (!/^\d+\.\d+\.\d+/.test(version)) continue;
    deps.set(`${name}@${version}`, { name, version });
    const meta = Array.isArray(value) ? value.find((v) => v && typeof v === 'object' && !Array.isArray(v)) : null;
    if (meta) {
      for (const dep of Object.keys({ ...meta.dependencies, ...meta.optionalDependencies })) {
        addEdge(edges, name, dep);
      }
    }
  }
  return { deps: [...deps.values()], edges };
}

// Accepts a directory (searched in LOCKFILE_NAMES order) or a lockfile path;
// returns { path, type: 'npm' | 'yarn' | 'pnpm' | 'bun' }.
function resolveLockfile(input) {
  let p = path.resolve(input);
  if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
    const found = LOCKFILE_NAMES.map((n) => path.join(p, n)).find((f) => fs.existsSync(f));
    if (!found) {
      const hint = fs.existsSync(path.join(p, 'bun.lockb'))
        ? ' — found binary bun.lockb; run `bun install --save-text-lockfile` to get a readable bun.lock'
        : '';
      throw new Error(`lockfile not found in ${p} (looked for ${LOCKFILE_NAMES.join(', ')})${hint}`);
    }
    p = found;
  } else if (!fs.existsSync(p)) {
    throw new Error(`lockfile not found: ${p} (run npm install --package-lock-only)`);
  }
  const base = path.basename(p);
  const type = base === 'yarn.lock' ? 'yarn'
    : base.startsWith('pnpm-lock') ? 'pnpm'
      : base === 'bun.lock' ? 'bun' : 'npm';
  return { path: p, type };
}

function loadDeps(input) {
  const { path: p, type } = resolveLockfile(input);
  const text = fs.readFileSync(p, 'utf8');
  const { deps, edges } = type === 'yarn' ? parseYarnLock(text)
    : type === 'pnpm' ? parsePnpmLock(text)
      : type === 'bun' ? parseBunLock(text)
        : collectNpmDeps(JSON.parse(text));
  return { lockPath: p, type, deps, edges };
}

// Shortest chain from a top-level package down to `name`, walking reverse
// edges until a parentless package. Empty when `name` is itself top-level
// (or edges are unavailable for this lockfile).
function viaChain(edges, name, maxDepth = 8) {
  const parentsOf = (n) => {
    const out = [];
    for (const [from, tos] of edges) if (tos.has(n)) out.push(from);
    return out;
  };
  const seen = new Set([name]);
  let frontier = [[name]];
  let best = null;
  for (let depth = 0; depth < maxDepth && frontier.length > 0; depth++) {
    const next = [];
    for (const chainPath of frontier) {
      const parents = parentsOf(chainPath[0]);
      if (parents.length === 0) {
        if (chainPath.length > 1) return chainPath.slice(0, -1);
        continue;
      }
      let extended = false;
      for (const parent of parents) {
        if (seen.has(parent)) continue;
        seen.add(parent);
        next.push([parent, ...chainPath]);
        extended = true;
      }
      // all parents already visited = a cycle; remember the deepest dead end
      if (!extended && chainPath.length > 1 && (!best || chainPath.length > best.length)) best = chainPath;
    }
    frontier = next;
  }
  if (frontier.length > 0) best = frontier[0]; // depth cap hit mid-walk
  return best ? best.slice(0, -1) : [];
}

module.exports = {
  LOCKFILE_NAMES, collectNpmDeps, parseYarnLock, parsePnpmLock, parseBunLock,
  resolveLockfile, loadDeps, viaChain,
};
