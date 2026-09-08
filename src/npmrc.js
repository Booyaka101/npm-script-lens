'use strict';
// Minimal .npmrc (ini) round-tripper for the allow-git / allow-remote keys.
// npm's ini dialect: `key=value` pairs, `#`/`;` comments, and a bare `key`
// line meaning `key=true`, which for these strict-enum keys is INVALID, so
// the parser surfaces it rather than normalizing it away. mergeNpmrc mirrors
// the comment-preserving pnpm-workspace.yaml merge in pm-contract.js: every
// other key, comment, and line keeps its exact bytes and order.
const fs = require('node:fs');
const path = require('node:path');
const { SOURCES } = require('./npm-contract');

// Line-preserving parse: [{type: 'blank'|'comment'|'pair', key?, value?,
// comment?, bare?, raw}]. A pair's value keeps npm's semantics (bare key ⇒
// 'true'); no unescaping, these keys only ever hold plain enum words.
//
// An inline comment is split off the value because npm's own ini does that,
// verified against npm 11.19.1: `min-release-age=3 # note` reads as 3, and so
// does `3#note`. Treating the comment as part of the value would report a
// perfectly good setting as unreadable. `comment` keeps the original text so a
// rewrite can put it back.
function parseNpmrc(text) {
  return String(text).split(/\r?\n/).map((raw) => {
    const t = raw.trim();
    if (t === '') return { type: 'blank', raw };
    if (t.startsWith('#') || t.startsWith(';')) return { type: 'comment', raw };
    const eq = raw.indexOf('=');
    if (eq === -1) return { type: 'pair', key: t, value: 'true', bare: true, raw };
    const rest = raw.slice(eq + 1);
    const hash = rest.search(/[#;]/);
    const pair = {
      type: 'pair',
      key: raw.slice(0, eq).trim(),
      value: (hash === -1 ? rest : rest.slice(0, hash)).trim(),
      raw,
    };
    // present only when there is one, so a plain pair parses to exactly the
    // shape it always has
    if (hash !== -1) pair.comment = rest.slice(hash).replace(/\r?\n$/, '');
    return pair;
  });
}

// Raw values for `keys` from <dir>/.npmrc: { file, exists, values, multi,
// lines }. `values` is last-occurrence-wins, like npm's ini; `multi` keeps
// every occurrence in order, which is how npm reads a repeatable key such as
// min-release-age-exclude; `lines` is the 1-based line of the occurrence that
// wins, for anchoring a finding.
function readNpmrcKeys(dir, keys) {
  const file = path.join(dir, '.npmrc');
  const out = { file, exists: false, values: {}, multi: {}, lines: {} };
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return out; }
  out.exists = true;
  const want = new Set(keys);
  parseNpmrc(text).forEach((line, i) => {
    if (line.type !== 'pair' || !want.has(line.key)) return;
    out.values[line.key] = line.value;
    (out.multi[line.key] = out.multi[line.key] || []).push(line.value);
    out.lines[line.key] = i + 1;
  });
  return out;
}

// The project's committed allow-git / allow-remote values from <dir>/.npmrc:
// { file, exists, git, remote }, git/remote are the raw string values (which
// may be OUT of the enum, e.g. 'true'; the caller validates) or null when the
// key (or the file) is absent. Last occurrence wins, like npm's ini.
function readSourceConfig(dir) {
  const keys = { git: SOURCES.git.key, remote: SOURCES.remote.key };
  const cfg = readNpmrcKeys(dir, Object.values(keys));
  const out = { file: cfg.file, exists: cfg.exists, git: null, remote: null };
  for (const kind of ['git', 'remote']) {
    if (cfg.values[keys[kind]] !== undefined) out[kind] = cfg.values[keys[kind]];
  }
  return out;
}

// Set/replace keys in .npmrc text, preserving every other key, comment, blank
// line, order, and each line's own EOL style. Every occurrence of a managed
// key is rewritten (npm's ini is last-wins, leaving a stale duplicate behind
// would silently override the fix); missing keys are appended at the end.
// updates: { 'allow-git': 'all', … }, null/undefined values are ignored.
// An ARRAY value marks a repeatable key (npm reads min-release-age-exclude
// that way): the existing lines are consumed in order and any spare ones are
// dropped, so the committed list is exactly the list passed in.
function mergeNpmrc(text, updates) {
  const sets = Object.entries(updates || {}).filter(([, v]) => v !== null && v !== undefined);
  if (sets.length === 0) return text;
  const byKey = new Map(sets.map(([k, v]) => [k, { multi: Array.isArray(v), queue: Array.isArray(v) ? [...v] : [v] }]));
  const missing = new Set(byKey.keys());
  const parts = String(text).length > 0 ? String(text).split(/(?<=\n)/) : [];
  const out = parts.map((part) => {
    const eolMatch = part.match(/\r?\n$/);
    const eol = eolMatch ? eolMatch[0] : '';
    const body = eol ? part.slice(0, -eol.length) : part;
    const t = body.trim();
    if (t === '' || t.startsWith('#') || t.startsWith(';')) return part;
    const eq = body.indexOf('=');
    const key = eq === -1 ? t : body.slice(0, eq).trim();
    const set = byKey.get(key);
    if (!set) return part;
    missing.delete(key);
    // whatever the author wrote after the value is theirs, and it may be the
    // only record of WHY the value is what it is
    const trailing = eq === -1 ? '' : (body.slice(eq + 1).match(/\s*[#;].*$/) || [''])[0];
    if (!set.multi) return `${key}=${set.queue[0]}${trailing}${eol || '\n'}`;
    if (set.queue.length === 0) return '';
    return `${key}=${set.queue.shift()}${trailing}${eol || '\n'}`;
  });
  let result = out.join('');
  const leftovers = sets.flatMap(([key]) => {
    const set = byKey.get(key);
    if (missing.has(key)) return set.multi ? set.queue.map((v) => [key, v]) : [[key, set.queue[0]]];
    return set.multi ? set.queue.map((v) => [key, v]) : [];
  });
  if (leftovers.length > 0) {
    if (result !== '' && !result.endsWith('\n')) result += '\n';
    for (const [key, value] of leftovers) result += `${key}=${value}\n`;
  }
  return result;
}

module.exports = { parseNpmrc, readSourceConfig, readNpmrcKeys, mergeNpmrc };
