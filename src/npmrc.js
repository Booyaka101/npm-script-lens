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
// lines }. `lines` is the 1-based line of the occurrence that wins.
//
// npm's repeat semantics are not what they look like, and getting them wrong
// silently drops entries. Verified against npm 11.19.1:
//
//   key=alpha            key=beta        -> beta          (last wins, scalar)
//   key[]=alpha          key[]=beta      -> alpha,beta    (appends)
//   key=alpha            key[]=beta      -> alpha,beta
//   key[]=alpha          key=beta        -> alpha,beta
//
// So repeating a PLAIN key does not build a list, it overwrites. Once any
// occurrence uses the `[]` form, every occurrence accumulates in source order.
// `multi` follows that rule exactly; `values` is the scalar reading.
const ARRAY_SUFFIX = '[]';
const baseKey = (k) => (k.endsWith(ARRAY_SUFFIX) ? k.slice(0, -ARRAY_SUFFIX.length) : k);

function readNpmrcKeys(dir, keys) {
  const file = path.join(dir, '.npmrc');
  const out = { file, exists: false, values: {}, multi: {}, lines: {} };
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return out; }
  out.exists = true;
  const want = new Set(keys);
  const seen = new Map();
  parseNpmrc(text).forEach((line, i) => {
    if (line.type !== 'pair') return;
    const key = baseKey(line.key);
    if (!want.has(key)) return;
    const hits = seen.get(key) || [];
    hits.push({ value: line.value, array: line.key !== key });
    seen.set(key, hits);
    out.values[key] = line.value;
    out.lines[key] = i + 1;
  });
  for (const [key, hits] of seen) {
    out.multi[key] = hits.some((h) => h.array)
      ? hits.map((h) => h.value)
      : [hits[hits.length - 1].value];
  }
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
// An ARRAY value marks a repeatable key such as min-release-age-exclude, and
// is written in npm's `key[]=value` form. Repeating a plain `key=value` would
// NOT build a list, npm keeps only the last one, so writing it that way would
// commit an exemption list that silently holds a single entry. Every existing
// occurrence in either form is replaced by the new list.
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
    const base = baseKey(key);
    const set = byKey.get(base);
    if (!set) return part;
    missing.delete(base);
    // whatever the author wrote after the value is theirs, and it may be the
    // only record of WHY the value is what it is
    const trailing = eq === -1 ? '' : (body.slice(eq + 1).match(/\s*[#;].*$/) || [''])[0];
    if (!set.multi) return `${base}=${set.queue[0]}${trailing}${eol || '\n'}`;
    // the whole list lands at the first occurrence; later ones go away, so a
    // stale entry cannot survive alongside the new list
    if (set.done) return '';
    set.done = true;
    const nl = eol || '\n';
    return set.queue.map((v, i) => `${base}[]=${v}${i === 0 ? trailing : ''}${nl}`).join('');
  });
  let result = out.join('');
  const leftovers = sets.flatMap(([key]) => {
    const set = byKey.get(key);
    if (!missing.has(key)) return [];
    return set.multi ? set.queue.map((v) => [`${key}${ARRAY_SUFFIX}`, v]) : [[key, set.queue[0]]];
  });
  if (leftovers.length > 0) {
    if (result !== '' && !result.endsWith('\n')) result += '\n';
    for (const [key, value] of leftovers) result += `${key}=${value}\n`;
  }
  return result;
}

module.exports = { parseNpmrc, readSourceConfig, readNpmrcKeys, mergeNpmrc };
