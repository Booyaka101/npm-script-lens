'use strict';
// Runtime code: what a package runs when it is required or its bin is
// invoked, as opposed to what its lifecycle scripts run at install time. The
// btree campaign (Checkmarx, 2026-09-17) had no install script at all; the
// loader sat in BTree.prototype.set and fired on the hundredth insert.
const { walkFiles, resolveFile, MAX_FILES, STRING_ARRAY_ROTATION } = require('./analyzer');

const SKIP_TARGET = /\.d\.[cm]?ts$|\.json$|\.node$|\*/;

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

// manifest: parsed package.json. files: the tarball index. Returns the tarball
// paths of main, every exports target and every bin, in that order, plus the
// declared ones that are not in the tarball.
function runtimeEntries(manifest, files) {
  const declared = [];
  if (typeof manifest.main === 'string' && manifest.main) declared.push({ from: 'main', target: manifest.main });
  for (const t of exportTargets(manifest.exports)) declared.push({ from: 'exports', target: t });
  const bin = typeof manifest.bin === 'string' ? { _: manifest.bin } : (manifest.bin || {});
  for (const t of Object.values(bin)) if (typeof t === 'string') declared.push({ from: 'bin', target: t });

  const entries = [];
  const missing = [];
  for (const { from, target } of declared) {
    if (SKIP_TARGET.test(target)) continue;
    const resolved = resolveFile(files, 'x', `./${target.replace(/^\.?\//, '')}`);
    if (!resolved) missing.push(`${from}: ${target}`);
    else if (!entries.includes(resolved)) entries.push(resolved);
  }
  // Node's own fallback when nothing names an entry point.
  if (manifest.main === undefined && manifest.exports === undefined && files.has('index.js') && !entries.includes('index.js')) {
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
  const { entries, missing } = runtimeEntries(manifest, files);
  const walked = entries.slice(0, MAX_FILES);
  const all = new Set();
  const byFile = new Map();
  const { partial } = walkFiles(files, walked, all, byFile);
  const keep = (set) => [...set].filter((s) => !s.startsWith('ref: ')).sort();
  const perFile = new Map();
  for (const [file, set] of byFile) {
    const kept = keep(set);
    if (kept.length > 0) perFile.set(file, kept);
  }
  return {
    signals: keep(all),
    byFile: perFile,
    entries: walked,
    missing,
    partial: partial || entries.length > walked.length,
  };
}

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

module.exports = { runtimeEntries, runtimeSignals, runtimePayloadFinding, exportTargets, filesWith };
