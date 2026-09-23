'use strict';
// Runtime code: what a package runs when it is required or its bin is
// invoked, as opposed to what its lifecycle scripts run at install time. The
// btree campaign (Checkmarx, 2026-09-17) had no install script at all; the
// loader sat in BTree.prototype.set and fired on the hundredth insert.
const { walkFiles, resolveFile, STRING_ARRAY_ROTATION } = require('./analyzer');

// Not code, or a pattern: "./feature/*" and the legacy folder form "./".
const SKIP_TARGET = /\.d\.[cm]?ts$|\.json$|\.node$|\.map$|\*|\/$/;
// One budget across every entry point, and no depth limit under it: a
// library's require chain runs deeper than an install script's (axios reaches
// its http adapter four requires down). A package with hundreds of exports
// subpaths (date-fns) still comes up partial, and says so.
const RUNTIME_MAX_FILES = 200;

// Every string target in an exports tree: the string shorthand, subpath
// keys, and nested conditions (require/import/node/default/...). null marks
// a blocked subpath and is skipped.
function exportTargets(exp, out = []) {
  if (typeof exp === 'string') out.push(exp);
  else if (Array.isArray(exp)) for (const e of exp) exportTargets(e, out);
  else if (exp && typeof exp === 'object') {
    for (const [key, value] of Object.entries(exp)) {
      if (key === './package.json') continue;
      exportTargets(value, out);
    }
  }
  return out;
}

// manifest: parsed package.json. files: the tarball index; skipped/capped
// say what the index left out. Returns the tarball paths of main, every
// exports target and every bin, in that order, plus the declared ones that
// could not be read and why.
function runtimeEntries(manifest, files, { skipped = [], capped = false } = {}) {
  const oversize = new Map(skipped.map((p) => [p, true]));
  const declared = [];
  if (typeof manifest.main === 'string' && manifest.main) declared.push({ from: 'main', target: manifest.main });
  for (const t of exportTargets(manifest.exports)) declared.push({ from: 'exports', target: t });
  const bin = typeof manifest.bin === 'string' ? { _: manifest.bin } : (manifest.bin || {});
  for (const t of Object.values(bin)) if (typeof t === 'string') declared.push({ from: 'bin', target: t });

  const entries = [];
  const missing = [];
  for (const { from, target } of declared) {
    if (SKIP_TARGET.test(target)) continue;
    const spec = `./${target.replace(/^\.?\//, '')}`;
    const resolved = resolveFile(files, 'x', spec);
    if (resolved) {
      if (!entries.includes(resolved)) entries.push(resolved);
      continue;
    }
    const why = resolveFile(oversize, 'x', spec) ? 'over 2 MB, not read'
      : capped ? 'past the offline file limit, not read' : 'not in the package';
    const line = `${from}: ${target} (${why})`;
    if (!missing.includes(line)) missing.push(line);
  }
  // Node's own fallback when main names nothing it can load and there are no
  // exports.
  const mainMissing = missing.some((m) => m.startsWith('main: '));
  if (manifest.exports === undefined && (!manifest.main || mainMissing) && files.has('index.js') && !entries.includes('index.js')) {
    entries.unshift('index.js');
  }
  return { entries, missing };
}

// pkg: { files } from fetchPackage(..., { forceTarball: true }) or
// loadLocalPackage(..., { forceFiles: true }). Signals are sorted, 'ref:'
// breadcrumbs stripped, and byFile maps each analyzed file to its own.
function runtimeSignals(pkg) {
  const files = pkg.files || new Map();
  let manifest = {};
  try { manifest = JSON.parse(files.get('package.json') || '{}'); } catch { /* treated as no manifest */ }
  const { entries, missing } = runtimeEntries(manifest, files, pkg);
  const all = new Set();
  const byFile = new Map();
  // Entry by entry, so main's own requires are read before the budget goes
  // on the fortieth exports subpath. Once it is spent, each later entry
  // comes back partial.
  const seen = new Set();
  let partial = false;
  for (const entry of entries) {
    if (walkFiles(files, [entry], all, byFile, { seen, maxFiles: RUNTIME_MAX_FILES, maxDepth: Infinity }).partial) partial = true;
  }
  const keep = (set) => [...set].filter((s) => !s.startsWith('ref: ')).sort();
  const perFile = new Map();
  for (const [file, set] of byFile) {
    const kept = keep(set);
    if (kept.length > 0) perFile.set(file, kept);
  }
  return {
    signals: keep(all),
    byFile: perFile,
    entries,
    missing,
    partial,
  };
}

// A signal with content hashes in its file names blanked, so a bundler's
// worker.3f9a1c2b.js -> worker.8e41d0aa.js rename is not a gained spawn.
const signalKey = (s) => s.replace(/([.-])(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{8,}(?=\.[cm]?[jt]s\b)/gi, '$1#');

// The analyzed files a signal came from.
const filesWith = (rt, signal) => [...rt.byFile].filter(([, sigs]) => sigs.includes(signal)).map(([f]) => f);

const IOC_KINDS = new Set(['c2', 'exfil', 'exec-local']);
const isIoc = (s) => IOC_KINDS.has(s.split(':')[0]) || s === STRING_ARRAY_ROTATION;

// RUNTIME_PAYLOAD for audit --runtime: only the three payload-shaped kinds,
// never plain exec/net/fs, which most libraries have. Of obf, only the
// obfuscator.io string-array prelude counts: bundlers emit eval and atob,
// they do not emit that, and it is what hides the c2 and exfil literals.
// A lone RPC host (any web3 client) or a lone local spawn (a worker pool) is
// MEDIUM; an exfil endpoint, or two kinds together, is HIGH. Returns null
// when nothing hits.
function runtimePayloadFinding(rt) {
  const hits = rt.signals.filter(isIoc).map((signal) => ({ signal, files: filesWith(rt, signal) }));
  if (hits.length === 0) return null;
  const kinds = new Set(hits.map((h) => h.signal.split(':')[0]));
  const risk = kinds.has('exfil') || kinds.size > 1 ? 'HIGH' : 'MEDIUM';
  return { risk, hits, partial: rt.partial };
}

// The payload-shaped signals in `rt` that `baseRt` did not have.
function gainedIocs(baseRt, rt) {
  const had = new Set(baseRt.signals.map(signalKey));
  return rt.signals.filter((s) => isIoc(s) && !had.has(signalKey(s)));
}

module.exports = {
  runtimeEntries, runtimeSignals, runtimePayloadFinding, gainedIocs, exportTargets, filesWith, signalKey, RUNTIME_MAX_FILES,
};
