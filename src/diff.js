'use strict';
// `diff` subcommand: compare the install-time lifecycle scripts of one package
// at two versions, so an upgrade reviewer can see exactly which
// preinstall/install/postinstall behavior (and implicit node-gyp build) was
// added or changed before bumping a pin. Reuses registry.fetchPackage, which
// already downloads the tarball and indexes binding.gyp.
const { fetchPackage, LIFECYCLE } = require('./registry');
const { collectGypFindings } = require('./gyp');

// Split "<pkg>@<version>" into { name, version }. Handles scoped names
// (@scope/pkg@1.2.3) by splitting on the LAST '@'.
function parseSpec(spec) {
  const at = spec.lastIndexOf('@');
  if (at <= 0) throw new Error(`expected <package>@<version>, got "${spec}"`);
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

// Pull the lifecycle scripts + binding.gyp CONTENT for one version.
// forceTarball makes fetchPackage download even scriptless packages so
// binding.gyp is always checked. We read the raw scripts from allScripts
// (fetchPackage synthesizes scripts.install for implicit-gyp packages, which
// we don't want to conflate with a real install script here).
//
// gypText, not a boolean: a version that REWRITES an existing binding.gyp
// changes what runs at install time while `files.has('binding.gyp')` stays
// true in both versions — the false negative that let the June 2026 Miasma
// wave-2 releases diff as "UNCHANGED: implicit node-gyp rebuild".
async function fetchScripts(name, version) {
  const { allScripts, files } = await fetchPackage(name, version, { forceTarball: true });
  const scripts = {};
  for (const k of LIFECYCLE) if (typeof allScripts[k] === 'string') scripts[k] = allScripts[k];
  const gypText = files.has('binding.gyp') ? files.get('binding.gyp') : null;
  const gypFindings = gypText === null ? [] : collectGypFindings(files).findings;
  return { name, version, scripts, gypText, gypFindings };
}

// Minimal LCS line diff → array of { t: ' '|'-'|'+', line }.
function lineDiff(a, b) {
  const A = a.split('\n');
  const B = b.split('\n');
  const m = A.length;
  const n = B.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (A[i] === B[j]) { out.push({ t: ' ', line: A[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ t: '-', line: A[i] }); i++; }
    else { out.push({ t: '+', line: B[j] }); j++; }
  }
  while (i < m) out.push({ t: '-', line: A[i++] });
  while (j < n) out.push({ t: '+', line: B[j++] });
  return out;
}

// Pure diff of two fetchScripts() results. Returns the four buckets, an
// overall `changed` flag (any ADDED or MODIFIED — the exit-1 condition), and a
// JSON-serializable view.
function computeScriptDiff(oldPkg, newPkg) {
  const unchanged = [];
  const added = [];
  const removed = [];
  const modified = [];
  for (const key of LIFECYCLE) {
    const o = oldPkg.scripts[key];
    const n = newPkg.scripts[key];
    if (o === undefined && n === undefined) continue;
    if (o === undefined) added.push({ key, script: n });
    else if (n === undefined) removed.push({ key });
    else if (o === n) unchanged.push({ key });
    else modified.push({ key, old: o, new: n, diff: lineDiff(o, n) });
  }
  // npm runs an implicit `node-gyp rebuild` when a package ships a root
  // binding.gyp without its own install script — treat gaining one as an
  // added install-time behavior. Keeping one but REWRITING it is equally an
  // install-time change: gyp executes `<!(...)` command expansions during
  // configure, so new bytes in binding.gyp are new commands. (`hasGyp` is
  // still honored so callers holding only the old boolean shape keep working.)
  const gypTextOf = (p) => (typeof p.gypText === 'string' ? p.gypText : null);
  const hasGypOf = (p) => (gypTextOf(p) !== null || p.hasGyp === true);
  const channelsOf = (p) => new Set((p.gypFindings || []).map((f) => f.channel));
  let gypChanged = false;
  let gainedChannels = [];
  if (hasGypOf(newPkg) && !hasGypOf(oldPkg)) {
    added.push({ key: 'binding.gyp', script: 'node-gyp rebuild', implicit: true });
    gypChanged = true;
    gainedChannels = [...channelsOf(newPkg)].sort();
  } else if (hasGypOf(oldPkg) && !hasGypOf(newPkg)) {
    removed.push({ key: 'binding.gyp', implicit: true });
  } else if (hasGypOf(oldPkg) && hasGypOf(newPkg)) {
    const o = gypTextOf(oldPkg);
    const n = gypTextOf(newPkg);
    if (o !== null && n !== null && o !== n) {
      const oldChannels = channelsOf(oldPkg);
      gainedChannels = [...channelsOf(newPkg)].filter((c) => !oldChannels.has(c)).sort();
      modified.push({ key: 'binding.gyp', old: o, new: n, diff: lineDiff(o, n), implicit: true, gainedChannels });
      gypChanged = true;
    } else {
      unchanged.push({ key: 'binding.gyp', implicit: true });
    }
  }
  const changed = added.length > 0 || modified.length > 0;
  const json = {
    unchanged: unchanged.map((e) => e.key),
    added: added.map((e) => (e.implicit ? { key: e.key, script: e.script, implicit: true } : { key: e.key, script: e.script })),
    removed: removed.map((e) => e.key),
    modified: modified.map((e) => (e.implicit
      ? { key: e.key, old: e.old, new: e.new, implicit: true, gainedChannels: e.gainedChannels }
      : { key: e.key, old: e.old, new: e.new })),
    // `changed` here means the gyp was ADDED or REWRITTEN (both grow the
    // install surface and both exit 1); a pure removal shows up in `removed`.
    gyp: { changed: gypChanged, gainedChannels },
  };
  return { unchanged, added, removed, modified, changed, json };
}

const CODES = { green: 32, red: 31, yellow: 33, dim: 90, bold: 1 };
function makeColor(enabled) {
  return (s, name) => (enabled ? `\x1b[${CODES[name]}m${s}\x1b[0m` : s);
}

// Human-readable colored output. `color` defaults to auto (TTY && !NO_COLOR).
function renderDiff(oldPkg, newPkg, result, { color = process.stdout.isTTY && !process.env.NO_COLOR } = {}) {
  const c = makeColor(color);
  const out = [];
  const label = (p) => `${p.name}@${p.version}`;
  out.push(c(`${label(oldPkg)} → ${label(newPkg)}`, 'bold'));
  for (const e of result.unchanged) {
    out.push(c(`UNCHANGED: ${e.implicit ? 'implicit node-gyp rebuild (binding.gyp)' : e.key}`, 'green'));
  }
  for (const e of result.removed) {
    out.push(c(`REMOVED: ${e.implicit ? 'implicit node-gyp rebuild (binding.gyp)' : e.key}`, 'yellow'));
  }
  for (const e of result.added) {
    if (e.implicit) out.push(c('ADDED: implicit node-gyp rebuild (binding.gyp)', 'red'));
    else out.push(c(`ADDED: ${e.key}: ${e.script}`, 'red'));
  }
  for (const e of result.modified) {
    out.push(c(`MODIFIED: ${e.implicit ? 'binding.gyp (implicit node-gyp rebuild — contents changed)' : e.key}`, 'red'));
    if (e.gainedChannels && e.gainedChannels.length > 0) {
      out.push(c(`    gained gyp execution channel(s): ${e.gainedChannels.join(', ')}`, 'red'));
    }
    for (const d of e.diff) {
      if (d.t === ' ') out.push(c(`    ${d.t} ${d.line}`, 'dim'));
      else if (d.t === '-') out.push(c(`    - ${d.line}`, 'yellow'));
      else out.push(c(`    + ${d.line}`, 'red'));
    }
  }
  if (result.unchanged.length && !result.changed && !result.removed.length) {
    out.push(c('no install-time script changes', 'green'));
  }
  return out.join('\n');
}

module.exports = { parseSpec, fetchScripts, computeScriptDiff, renderDiff, lineDiff };
