'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Lockfiles we can read, in the order a directory is searched.
const LOCKFILE_NAMES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'];

// Every parser returns { deps: [{name, version}], edges: Map<name, Set<depName>> }.
// Edges are name-level (versions collapse), enough for "via" chains, not for
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

// Selectors whose range points outside the registry, the tarball we would
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

// Berry lockfiles carry an exact "resolution: name@npm:version" per entry
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
  // v5 peer suffix ("/name/1.2.3_peer@2.0.0") can itself contain @, strip
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
    // entry keys sit at exactly 2 spaces, [^\s'"] keeps deeper-indented
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
// object element carries the dependency maps. (bun.lockb is binary, ask for
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

const typeOf = (p) => {
  const base = path.basename(p);
  return base === 'yarn.lock' ? 'yarn'
    : base.startsWith('pnpm-lock') ? 'pnpm'
      : base === 'bun.lock' ? 'bun' : 'npm';
};

const lockfileIn = (dir) => LOCKFILE_NAMES.map((n) => path.join(dir, n)).find((f) => fs.existsSync(f));

// A tree of checkouts is deeper than one project but never unbounded, and the
// exclusions match hooks' walker so both commands agree on what a project is.
const MAX_DISCOVERY_DEPTH = 6;

// Every project at or below `root`, nearest first. node_modules is skipped
// because a dependency's own lockfile is not a project the caller owns.
function discoverLockfiles(root, maxDepth = MAX_DISCOVERY_DEPTH) {
  const out = [];
  const visit = (dir, depth) => {
    const found = lockfileIn(dir);
    if (found) out.push(found);
    if (depth >= maxDepth) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (!e.isDirectory() || e.name === 'node_modules' || e.name.startsWith('.')) continue;
      visit(path.join(dir, e.name), depth + 1);
    }
  };
  visit(path.resolve(root), 0);
  return out;
}

// Nearest lockfile at or above `dir`, so the tool works from a subdirectory the
// way npm itself does. Stops at the filesystem root.
function nearestLockfileUp(dir) {
  let cur = path.resolve(dir);
  for (;;) {
    const found = lockfileIn(cur);
    if (found) return found;
    const parent = path.dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
}

const notFound = (p) => {
  const hint = fs.existsSync(path.join(p, 'bun.lockb'))
    ? ', found binary bun.lockb; run `bun install --save-text-lockfile` to get a readable bun.lock'
    : '';
  return new Error(`lockfile not found in ${p} or any directory above it (looked for ${LOCKFILE_NAMES.join(', ')})${hint}`);
};

// Accepts a directory (searched in LOCKFILE_NAMES order, then upward) or a
// lockfile path; returns { path, type: 'npm' | 'yarn' | 'pnpm' | 'bun' }.
function resolveLockfile(input) {
  let p = path.resolve(input);
  if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
    const found = lockfileIn(p) || nearestLockfileUp(p);
    if (!found) throw notFound(p);
    p = found;
  } else if (!fs.existsSync(p)) {
    throw new Error(`lockfile not found: ${p} (run npm install --package-lock-only)`);
  }
  return { path: p, type: typeOf(p) };
}

// Every project `input` refers to: the path itself, else the nearest one above
// it, else every project underneath. Returns them with how they were found, so
// callers can say "audited 4 projects under ." rather than pretending the user
// asked for each one.
function findProjects(input) {
  const p = path.resolve(input);
  if (fs.existsSync(p) && !fs.statSync(p).isDirectory()) return { how: 'exact', lockfiles: [{ path: p, type: typeOf(p) }] };
  if (!fs.existsSync(p)) throw new Error(`lockfile not found: ${p} (run npm install --package-lock-only)`);
  const here = lockfileIn(p);
  if (here) return { how: 'exact', lockfiles: [{ path: here, type: typeOf(here) }] };
  const up = nearestLockfileUp(p);
  if (up) return { how: 'up', lockfiles: [{ path: up, type: typeOf(up) }] };
  const down = discoverLockfiles(p);
  if (down.length) return { how: 'down', lockfiles: down.map((f) => ({ path: f, type: typeOf(f) })) };
  throw notFound(p);
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

// --- non-registry (git / remote-URL) dependencies --------------------------
// npm v12 also flips `allow-git` and `allow-remote` to 'none': git and
// remote-tarball dependencies stop resolving unless opted in. This collector
// finds them in every lockfile dialect we read. It is a SEPARATE pass, the
// NON_REGISTRY skip in the registry-deps parsers above stays exactly as-is,
// so audit output does not change.
//
// Classification is by the DECLARED SPEC (what a package.json/dependency map
// asked for), never by a `resolved` URL alone: registry deps also resolve to
// https tarball URLs, so a spec is the only unambiguous discriminator for
// kind 'remote'. (A git+… `resolved` IS unambiguous, and is used as a
// fallback for git deps whose declaring spec we cannot see.)

// git = git+ssh / git+https / git:// (any git+ protocol) and the
// github:/gitlab:/bitbucket: shorthands; remote = http(s) tarball URLs.
// pnpm records git resolutions as bare `github.com/owner/repo/sha` paths, and
// yarn berry as `https://….git#commit=…`, both are still git deps.
function classifySourceSpec(spec) {
  if (typeof spec !== 'string' || spec === '') return null;
  if (/^(git(\+[a-z]+)?:|github:|gitlab:|bitbucket:)/i.test(spec)) return 'git';
  if (/^(github|gitlab|bitbucket)\.com\//i.test(spec)) return 'git';
  if (/^https?:\/\//i.test(spec)) return /\.git(#|$)|#commit=/i.test(spec) ? 'git' : 'remote';
  return null;
}

// one record per package name: {name, spec, kind, resolved, parents}
const sourceRecs = () => {
  const recs = new Map();
  const get = (name) => {
    if (!recs.has(name)) recs.set(name, { name, spec: null, kind: null, resolved: null, parents: new Set() });
    return recs.get(name);
  };
  const list = () => [...recs.values()]
    .map((r) => ({ name: r.name, spec: r.spec, kind: r.kind, resolved: r.resolved, parents: [...r.parents].sort() }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return { get, has: (name) => recs.has(name), list };
};

const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

function nonRegistryFromNpm(lock) {
  const { get, has, list } = sourceRecs();
  if (lock.packages) {
    // pass 1, declaration sites: the root importer (""), workspace importers,
    // and every installed package's dependency maps carry the original specs
    for (const [key, entry] of Object.entries(lock.packages)) {
      const isRoot = key === '';
      const parentName = isRoot ? null
        : (entry.name || (key.includes('node_modules/') ? key.split('node_modules/').pop() : key.split('/').pop()));
      for (const field of DEP_FIELDS) {
        for (const [depName, spec] of Object.entries(entry[field] || {})) {
          const kind = classifySourceSpec(spec);
          if (!kind) continue;
          const rec = get(depName);
          rec.kind = rec.kind || kind;
          if (isRoot) rec.spec = spec; // the root declaration is what the user wrote, prefer it for display
          else {
            if (!rec.spec) rec.spec = spec;
            // a workspace-package declaration is conservatively NOT root (npm
            // resolves allow-*=root against the ROOT package.json only), but a
            // workspace importer is not a lockfile package either, only real
            // package parents contribute to via-chains
            if (key.includes('node_modules/') && parentName && parentName !== depName) rec.parents.add(parentName);
          }
        }
      }
    }
    // pass 2, resolved URLs: fill in resolution for known deps, and catch git
    // deps whose declaring spec was not visible (git+… is unambiguous; https
    // resolved URLs are NOT, every registry dep has one)
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (!key.includes('node_modules/') || !entry.resolved) continue;
      const name = entry.name || key.split('node_modules/').pop();
      if (has(name)) {
        const rec = get(name);
        if (!rec.resolved) rec.resolved = entry.resolved;
      } else if (classifySourceSpec(entry.resolved) === 'git') {
        const rec = get(name);
        rec.kind = 'git';
        rec.spec = entry.resolved;
        rec.resolved = entry.resolved;
      }
    }
  } else if (lock.dependencies) {
    // v1 fallback: git/remote deps carry the URL in `version`; `requires`
    // maps carry the declaring specs
    const visit = (obj, parent) => {
      for (const [name, entry] of Object.entries(obj)) {
        const kind = classifySourceSpec(entry.version);
        if (kind) {
          const rec = get(name);
          rec.kind = rec.kind || kind;
          if (!rec.spec) rec.spec = entry.from || entry.version;
          if (!rec.resolved) rec.resolved = entry.resolved || entry.version;
          if (parent && parent !== name) rec.parents.add(parent);
        }
        for (const [rn, rspec] of Object.entries(entry.requires || {})) {
          const rkind = classifySourceSpec(rspec);
          if (!rkind) continue;
          const rec = get(rn);
          rec.kind = rec.kind || rkind;
          if (!rec.spec) rec.spec = rspec;
          if (rn !== name) rec.parents.add(name);
        }
        if (entry.dependencies) visit(entry.dependencies, name);
      }
    };
    visit(lock.dependencies, null);
  }
  return list();
}

// yarn classic and berry share the selector shape ("name@range"): the range is
// the declared spec. Classic's `resolved`/berry's `resolution` fill in the
// resolution; dependency sub-blocks give parents (classic: `dep "spec"`,
// berry: `dep: spec`).
function nonRegistryFromYarn(text) {
  const { get, list } = sourceRecs();
  let current = null; // rec when the current entry is itself non-registry
  let currentName = null; // entry name, for parent attribution
  let inDeps = false;
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(raw)) {
      current = null; currentName = null; inDeps = false;
      const selectors = raw.replace(/:\s*$/, '').split(/,\s*(?=")|,\s+/).map((s) => s.trim().replace(/^"|"$/g, ''));
      for (const sel of selectors) {
        const at = sel.indexOf('@', 1);
        if (at < 0) continue;
        const name = sel.slice(0, at);
        if (!currentName) currentName = name;
        const kind = classifySourceSpec(sel.slice(at + 1));
        if (!kind) continue;
        const rec = get(name);
        rec.kind = rec.kind || kind;
        if (!rec.spec) rec.spec = sel.slice(at + 1);
        current = rec;
      }
      continue;
    }
    const res = raw.match(/^\s{2}(?:resolution|resolved):?\s+"?([^"]+?)"?\s*$/);
    if (res) {
      if (current && !current.resolved) {
        // berry's resolution is "name@<locator>", strip the name prefix
        current.resolved = res[1].startsWith(`${current.name}@`) ? res[1].slice(current.name.length + 1) : res[1];
      }
      continue;
    }
    if (/^\s{2}(optionalD|d)ependencies:\s*$/.test(raw)) { inDeps = true; continue; }
    if (/^\s{2}\S/.test(raw)) { inDeps = false; continue; }
    if (!inDeps) continue;
    const dep = raw.match(/^\s{4}"?((?:@[^/"]+\/)?[^"\s:]+)"?:?\s+"?([^"\n]+?)"?\s*$/);
    if (!dep) continue;
    const kind = classifySourceSpec(dep[2]);
    if (!kind) continue;
    const rec = get(dep[1]);
    rec.kind = rec.kind || kind;
    if (!rec.spec) rec.spec = dep[2];
    if (currentName && currentName !== dep[1]) rec.parents.add(currentName);
  }
  return list();
}

// pnpm: `importers:` blocks carry the declared specifier per dep (`.` is the
// root importer, others are workspace packages, NOT root); `packages:` keys
// name git/remote resolutions ("name@git+…", "name@https://…", or a bare
// URL/`github.com/…` key with a `name:` property); `snapshots:`/`packages:`
// dependency sub-maps give parents.
function nonRegistryFromPnpm(text) {
  const { get, has, list } = sourceRecs();
  let section = null;
  let importerPath = null;
  let depName = null;
  let entryName = null; // current packages/snapshots entry, for parents
  let pendingUrlEntry = null; // bare-URL package key awaiting its `name:` line
  let inDeps = false;
  const splitNonRegistryKey = (rawKey) => {
    const key = rawKey.trim().replace(/^['"]|['"]$/g, '');
    const wholeKind = classifySourceSpec(key.startsWith('/') ? key.slice(1) : key);
    if (wholeKind) return { name: null, rest: key.startsWith('/') ? key.slice(1) : key, kind: wholeKind };
    const at = key.indexOf('@', 1);
    if (at < 0) return null;
    const rest = key.slice(at + 1);
    const kind = classifySourceSpec(rest);
    return kind ? { name: key.slice(0, at), rest, kind } : null;
  };
  for (const line of text.split(/\r?\n/)) {
    const top = line.match(/^(\w+):\s*$/);
    if (top) { section = top[1]; importerPath = null; depName = null; entryName = null; pendingUrlEntry = null; inDeps = false; continue; }
    if (/^\S/.test(line)) { section = null; continue; }
    if (section === 'importers') {
      const imp = line.match(/^  ['"]?([^\s'"][^'":]*?)['"]?:\s*$/);
      if (imp) { importerPath = imp[1]; depName = null; continue; }
      const dep = line.match(/^\s{6}['"]?((?:@[^/'"]+\/)?[^'"\s:]+)['"]?:\s*$/);
      if (dep) { depName = dep[1]; continue; }
      const specifier = line.match(/^\s{8}specifier:\s*['"]?(.+?)['"]?\s*$/);
      if (specifier && depName) {
        const kind = classifySourceSpec(specifier[1]);
        if (kind) {
          const rec = get(depName);
          rec.kind = rec.kind || kind;
          if (importerPath === '.') rec.spec = specifier[1];
          else if (!rec.spec) rec.spec = specifier[1];
        }
        continue;
      }
      const version = line.match(/^\s{8}version:\s*['"]?(.+?)['"]?\s*$/);
      if (version && depName && has(depName)) {
        const rec = get(depName);
        if (!rec.resolved) rec.resolved = version[1].replace(/\([^)]*\)/g, '');
      }
      continue;
    }
    if (section !== 'packages' && section !== 'snapshots') continue;
    const entry = line.match(/^  (['"]?[^\s'"].*?['"]?):\s*(\{\})?\s*$/);
    if (entry) {
      inDeps = false;
      pendingUrlEntry = null;
      const nr = splitNonRegistryKey(entry[1]);
      if (nr && nr.name) {
        entryName = nr.name;
        if (section === 'packages' || !has(nr.name)) {
          const rec = get(nr.name);
          rec.kind = rec.kind || nr.kind;
          if (!rec.spec) rec.spec = nr.rest;
          if (!rec.resolved) rec.resolved = nr.rest;
        }
      } else if (nr) {
        entryName = null;
        pendingUrlEntry = nr; // wait for the entry's `name:` property
      } else {
        const split = splitPnpmKey(entry[1].replace(/^['"]|['"]$/g, ''));
        entryName = split ? split.name : null;
      }
      continue;
    }
    const nameProp = line.match(/^\s{4}name:\s*['"]?(.+?)['"]?\s*$/);
    if (nameProp && pendingUrlEntry) {
      const rec = get(nameProp[1]);
      rec.kind = rec.kind || pendingUrlEntry.kind;
      if (!rec.spec) rec.spec = pendingUrlEntry.rest;
      if (!rec.resolved) rec.resolved = pendingUrlEntry.rest;
      entryName = nameProp[1];
      pendingUrlEntry = null;
      continue;
    }
    if (/^\s{4}(optionalD|d)ependencies:\s*$/.test(line)) { inDeps = true; continue; }
    if (/^\s{4}\S/.test(line)) { inDeps = false; continue; }
    if (!inDeps) continue;
    const dep = line.match(/^\s{6}['"]?((?:@[^/'"]+\/)?[^'"\s:]+)['"]?:\s*['"]?(.+?)['"]?\s*$/);
    if (!dep) continue;
    const kind = classifySourceSpec(dep[2].replace(/\([^)]*\)/g, ''));
    if (!kind) continue;
    const rec = get(dep[1]);
    rec.kind = rec.kind || kind;
    if (!rec.spec) rec.spec = dep[2].replace(/\([^)]*\)/g, '');
    if (!rec.resolved) rec.resolved = dep[2].replace(/\([^)]*\)/g, '');
    if (entryName && entryName !== dep[1]) rec.parents.add(entryName);
  }
  return list();
}

// bun.lock: `workspaces` blocks carry declared specs ("" is the root
// importer); `packages` values are ["name@<locator>", …, {deps}, …], a
// non-semver locator after the name is the resolution, and each entry's
// dependency maps give parents.
function nonRegistryFromBun(lock) {
  const { get, list } = sourceRecs();
  for (const [wsPath, ws] of Object.entries(lock.workspaces || {})) {
    for (const field of DEP_FIELDS) {
      for (const [name, spec] of Object.entries((ws || {})[field] || {})) {
        const kind = classifySourceSpec(spec);
        if (!kind) continue;
        const rec = get(name);
        rec.kind = rec.kind || kind;
        if (wsPath === '') rec.spec = spec;
        else if (!rec.spec) rec.spec = spec;
      }
    }
  }
  for (const value of Object.values(lock.packages || {})) {
    const spec = Array.isArray(value) ? value[0] : value;
    if (typeof spec !== 'string') continue;
    const at = spec.indexOf('@', 1);
    if (at <= 0) continue;
    const name = spec.slice(0, at);
    const rest = spec.slice(at + 1);
    const kind = classifySourceSpec(rest);
    const meta = Array.isArray(value) ? value.find((v) => v && typeof v === 'object' && !Array.isArray(v)) : null;
    if (meta) {
      for (const field of ['dependencies', 'optionalDependencies']) {
        for (const [dn, dspec] of Object.entries(meta[field] || {})) {
          const dkind = classifySourceSpec(dspec);
          if (!dkind) continue;
          const rec = get(dn);
          rec.kind = rec.kind || dkind;
          if (!rec.spec) rec.spec = dspec;
          if (name !== dn) rec.parents.add(name);
        }
      }
    }
    if (kind) {
      const rec = get(name);
      rec.kind = rec.kind || kind;
      if (!rec.spec) rec.spec = rest;
      if (!rec.resolved) rec.resolved = rest;
    }
  }
  return list();
}

// Every git/remote dependency in a lockfile: [{name, spec, kind, resolved,
// parents}]. `lock` is the lockfile text (or, for npm/bun, the parsed
// object); `type` is resolveLockfile's 'npm' | 'yarn' | 'pnpm' | 'bun'.
function collectNonRegistryDeps(lock, type) {
  if (type === 'yarn') return nonRegistryFromYarn(String(lock));
  if (type === 'pnpm') return nonRegistryFromPnpm(String(lock));
  if (type === 'bun') {
    let obj = lock;
    if (typeof lock === 'string') {
      try { obj = JSON.parse(stripJsonc(lock)); } catch { return []; }
    }
    return nonRegistryFromBun(obj);
  }
  return nonRegistryFromNpm(typeof lock === 'string' ? JSON.parse(lock) : lock);
}

module.exports = {
  LOCKFILE_NAMES, collectNpmDeps, parseYarnLock, parsePnpmLock, parseBunLock,
  resolveLockfile, loadDeps, viaChain, classifySourceSpec, collectNonRegistryDeps,
  findProjects, discoverLockfiles, nearestLockfileUp,
};
