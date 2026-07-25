'use strict';
// The install-script allowlist is no longer an npm-only idea: every major
// package manager now ships the same "scripts are opt-in, keep an allowlist"
// model, each with its own native format. This module is the cross-ecosystem
// contract — one adapter per manager describing where its allowlist lives, how
// a package is keyed, how to render the block, and how to merge decisions in.
// The behavioral risk analysis upstream is identical for all four; only this
// write/render surface differs.
//
// Formats verified against authoritative docs (2026-07-24):
//   npm 12   — allowScripts   { "pkg@1.2.3": true }        in package.json
//   pnpm 11  — allowBuilds     { pkg: true }                in pnpm-workspace.yaml
//              (pnpm 10.0–10.25 used the onlyBuiltDependencies array)
//   yarn B.  — dependenciesMeta.<pkg>.built: true           in package.json
//              (+ enableScripts: false in .yarnrc.yml to make it an allowlist)
//   bun      — trustedDependencies: ["pkg"]                 in package.json
//              (NB: defining it REPLACES bun's built-in trusted list)
const fs = require('node:fs');
const path = require('node:path');

// --- shared package.json IO (indentation-preserving, like cli.js) ----------
function readPkg(dir) {
  const pkgPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) throw new Error(`package.json not found in ${dir}`);
  const raw = fs.readFileSync(pkgPath, 'utf8');
  return { pkgPath, raw, pkg: JSON.parse(raw) };
}
function writePkg(pkgPath, raw, pkg) {
  const indent = raw.match(/^([ \t]+)"/m);
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, indent ? indent[1] : 2) + (raw.endsWith('\n') ? '\n' : ''));
}
const sortedMap = (obj) => Object.fromEntries(Object.entries(obj).sort(([a], [b]) => a.localeCompare(b)));
const names = (approved) => [...new Set(approved.map((d) => d.name))].sort();

// --- pnpm-workspace.yaml: scoped flat-map merge, no YAML dependency --------
// allowBuilds is a flat `name: bool` map; we read/merge/rewrite ONLY that
// block and leave the rest of the file byte-for-byte untouched. Keys that
// aren't plain scalars (scoped names begin with '@', a YAML reserved
// indicator) are double-quoted.
const yamlKey = (k) => (/^[A-Za-z0-9._-]+$/.test(k) ? k : JSON.stringify(k));
const unquote = (s) => (s.startsWith('"') ? JSON.parse(s) : s);

function readAllowBuilds(dir) {
  const file = path.join(dir, 'pnpm-workspace.yaml');
  if (!fs.existsSync(file)) return {};
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  const out = {};
  const start = lines.findIndex((l) => /^allowBuilds:\s*$/.test(l));
  if (start === -1) return out;
  for (let i = start + 1; i < lines.length; i++) {
    if (!/^\s+\S/.test(lines[i])) break; // dedent → block ended
    const m = lines[i].match(/^\s+("(?:[^"\\]|\\.)*"|[^:]+?):\s*(true|false)\s*$/);
    if (m) out[unquote(m[1].trim())] = m[2] === 'true';
  }
  return { file, entries: out, start, lines };
}

// entries: { name: boolean }. Merged into allowBuilds, or (replace:true) used
// as the complete block — sync uses replace to drop stale entries.
function writeAllowBuilds(dir, entries, { replace = false } = {}) {
  const file = path.join(dir, 'pnpm-workspace.yaml');
  const existing = readAllowBuilds(dir);
  const merged = replace ? { ...entries } : { ...(existing.entries || {}), ...entries };
  const block = ['allowBuilds:', ...Object.keys(merged).sort()
    .map((k) => `  ${yamlKey(k)}: ${merged[k]}`)];
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, `${block.join('\n')}\n`);
    return { file, note: `created ${path.basename(file)} with an allowBuilds block` };
  }
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  const start = lines.findIndex((l) => /^allowBuilds:\s*$/.test(l));
  if (start === -1) {
    // no block yet — append one (safe: no existing key touched)
    const sep = lines.length && lines[lines.length - 1] === '' ? '' : '\n';
    fs.appendFileSync(file, `${sep}${block.join('\n')}\n`);
    return { file, note: `appended an allowBuilds block to ${path.basename(file)}` };
  }
  // replace the existing block in place, preserving everything around it
  let end = start + 1;
  while (end < lines.length && /^\s+\S/.test(lines[end])) end++;
  lines.splice(start, end - start, ...block);
  fs.writeFileSync(file, `${lines.join('\n')}`);
  return { file, note: `merged into the existing allowBuilds block in ${path.basename(file)}` };
}

// --- .yarnrc.yml enableScripts:false (append-if-missing, safe) -------------
function ensureYarnScriptsDisabled(dir) {
  const file = path.join(dir, '.yarnrc.yml');
  const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  if (/^enableScripts:\s*false\s*$/m.test(text)) return null;
  if (/^enableScripts:/m.test(text)) return `.yarnrc.yml sets enableScripts to a non-false value — set it to false to make dependenciesMeta an allowlist`;
  fs.writeFileSync(file, `${text}${text && !text.endsWith('\n') ? '\n' : ''}enableScripts: false\n`);
  return `set enableScripts: false in .yarnrc.yml`;
}

// best-effort read of a package.json field
const pkgField = (dir, field) => {
  try { return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'))[field]; } catch { return undefined; }
};

// --- the manager registry --------------------------------------------------
// Each adapter: detect (via managerFor) · render/key (allow output) · write /
// writeDecisions (allow / review) · readExisting + covers (review / sync
// coverage). renderValue takes approved [{name,version}]; writeDecisions takes
// [{name,version,allow}] so review can record denials where the format allows.
const MANAGERS = {
  npm: {
    id: 'npm', label: 'npm', allowlistFile: 'package.json', nativeKey: 'allowScripts',
    keyOf: (name, version) => `${name}@${version}`,
    renderValue: (approved) => sortedMap(Object.fromEntries(approved.map((d) => [`${d.name}@${d.version}`, true]))),
    renderDecisions: (decisions) => sortedMap(Object.fromEntries(decisions.map((d) => [`${d.name}@${d.version}`, d.allow]))),
    readExisting: (dir) => pkgField(dir, 'allowScripts') || {},
    covers: (existing, name, version) => name in existing || `${name}@${version}` in existing,
    writeDecisions(dir, decisions) {
      const { pkgPath, raw, pkg } = readPkg(dir);
      const add = Object.fromEntries(decisions.map((d) => [`${d.name}@${d.version}`, d.allow]));
      pkg.allowScripts = sortedMap({ ...(pkg.allowScripts || {}), ...add });
      writePkg(pkgPath, raw, pkg);
      return { file: pkgPath, note: null };
    },
    write(dir, approved) { return this.writeDecisions(dir, approved.map((d) => ({ ...d, allow: true }))); },
    writeFull(dir, entries) {
      const { pkgPath, raw, pkg } = readPkg(dir);
      pkg.allowScripts = sortedMap(entries);
      writePkg(pkgPath, raw, pkg);
      return { file: pkgPath };
    },
  },
  pnpm: {
    id: 'pnpm', label: 'pnpm', allowlistFile: 'pnpm-workspace.yaml', nativeKey: 'allowBuilds',
    note: 'pnpm keys the allowlist by package name in pnpm-workspace.yaml (allowBuilds, pnpm ≥ 10.26 / v11; older pnpm 10 uses the onlyBuiltDependencies array).',
    keyOf: (name) => name,
    renderValue: (approved) => sortedMap(Object.fromEntries(names(approved).map((n) => [n, true]))),
    renderDecisions: (decisions) => sortedMap(Object.fromEntries(decisions.map((d) => [d.name, d.allow]))),
    readExisting: (dir) => readAllowBuilds(dir).entries || {},
    covers: (existing, name) => name in existing,
    writeDecisions: (dir, decisions) => writeAllowBuilds(dir, Object.fromEntries(decisions.map((d) => [d.name, d.allow]))),
    write(dir, approved) { return this.writeDecisions(dir, approved.map((d) => ({ ...d, allow: true }))); },
    writeFull: (dir, entries) => writeAllowBuilds(dir, entries, { replace: true }),
  },
  yarn: {
    id: 'yarn', label: 'yarn (Berry)', allowlistFile: 'package.json', nativeKey: 'dependenciesMeta',
    note: 'yarn keys by package name via dependenciesMeta.<pkg>.built. This is an allowlist only when enableScripts is false in .yarnrc.yml (yarn Berry / v2+; Yarn Classic has no per-package control).',
    keyOf: (name) => name,
    renderValue: (approved) => sortedMap(Object.fromEntries(names(approved).map((n) => [n, { built: true }]))),
    renderDecisions: (decisions) => sortedMap(Object.fromEntries(decisions.map((d) => [d.name, { built: d.allow }]))),
    readExisting: (dir) => {
      const m = pkgField(dir, 'dependenciesMeta') || {};
      return Object.fromEntries(Object.entries(m).filter(([, v]) => v && v.built === true));
    },
    covers: (existing, name) => name in existing,
    writeDecisions(dir, decisions) {
      const { pkgPath, raw, pkg } = readPkg(dir);
      const meta = { ...(pkg.dependenciesMeta || {}) };
      for (const d of decisions) meta[d.name] = { ...(meta[d.name] || {}), built: d.allow };
      pkg.dependenciesMeta = sortedMap(meta);
      writePkg(pkgPath, raw, pkg);
      return { file: pkgPath, note: ensureYarnScriptsDisabled(dir) };
    },
    write(dir, approved) { return this.writeDecisions(dir, approved.map((d) => ({ ...d, allow: true }))); },
    writeFull(dir, entries) {
      const { pkgPath, raw, pkg } = readPkg(dir);
      const meta = { ...(pkg.dependenciesMeta || {}) };
      for (const [name, v] of Object.entries(meta)) {
        if (v && 'built' in v && !(name in entries)) { // drop stale built flags, keep other metadata
          const { built, ...rest } = v;
          if (Object.keys(rest).length) meta[name] = rest; else delete meta[name];
        }
      }
      for (const [name, allow] of Object.entries(entries)) meta[name] = { ...(meta[name] || {}), built: allow };
      pkg.dependenciesMeta = sortedMap(meta);
      writePkg(pkgPath, raw, pkg);
      return { file: pkgPath, note: ensureYarnScriptsDisabled(dir) };
    },
  },
  bun: {
    id: 'bun', label: 'bun', allowlistFile: 'package.json', nativeKey: 'trustedDependencies',
    note: 'bun keys by package name in trustedDependencies. ⚠️ Defining this field REPLACES bun\'s built-in trusted list — packages bun trusted by default (e.g. esbuild, sharp) will stop running scripts unless you add them here too.',
    keyOf: (name) => name,
    renderValue: (approved) => names(approved),
    renderDecisions: (decisions) => names(decisions.filter((d) => d.allow)),
    readExisting: (dir) => { const t = pkgField(dir, 'trustedDependencies'); return Array.isArray(t) ? t : []; },
    covers: (existing, name) => existing.includes(name),
    write(dir, approved) {
      const { pkgPath, raw, pkg } = readPkg(dir);
      const set = new Set([...(Array.isArray(pkg.trustedDependencies) ? pkg.trustedDependencies : []), ...names(approved)]);
      pkg.trustedDependencies = [...set].sort();
      writePkg(pkgPath, raw, pkg);
      return { file: pkgPath, note: 'trustedDependencies replaces bun\'s default trusted list — verify no default-trusted scripted deps were dropped' };
    },
    // bun has no way to record a denial (it is presence = trust); only trusts
    // are written, denials become untrusted-by-omission.
    writeDecisions(dir, decisions) {
      const denied = decisions.filter((d) => !d.allow).length;
      const res = this.write(dir, decisions.filter((d) => d.allow));
      return { ...res, note: `${res.note}${denied ? `; ${denied} denial(s) can't be recorded in bun — left untrusted by omission` : ''}` };
    },
    writeFull(dir, entries) {
      const { pkgPath, raw, pkg } = readPkg(dir);
      pkg.trustedDependencies = Object.keys(entries).filter((n) => entries[n]).sort();
      writePkg(pkgPath, raw, pkg);
      return { file: pkgPath };
    },
  },
};

// resolveLockfile returns exactly these type strings.
const managerFor = (type) => MANAGERS[type] || MANAGERS.npm;
const managerById = (id) => {
  if (!MANAGERS[id]) throw new Error(`unknown package manager '${id}' (expected: ${Object.keys(MANAGERS).join(', ')})`);
  return MANAGERS[id];
};

module.exports = { MANAGERS, managerFor, managerById };
