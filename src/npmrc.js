'use strict';
// Minimal .npmrc (ini) round-tripper for the allow-git / allow-remote keys.
// npm's ini dialect: `key=value` pairs, `#`/`;` comments, and a bare `key`
// line meaning `key=true` — which for these strict-enum keys is INVALID, so
// the parser surfaces it rather than normalizing it away. mergeNpmrc mirrors
// the comment-preserving pnpm-workspace.yaml merge in pm-contract.js: every
// other key, comment, and line keeps its exact bytes and order.
const fs = require('node:fs');
const path = require('node:path');
const { SOURCES } = require('./npm-contract');

// Line-preserving parse: [{type: 'blank'|'comment'|'pair', key?, value?,
// bare?, raw}]. A pair's value keeps npm's semantics (bare key ⇒ 'true');
// no unescaping — these keys only ever hold plain enum words.
function parseNpmrc(text) {
  return String(text).split(/\r?\n/).map((raw) => {
    const t = raw.trim();
    if (t === '') return { type: 'blank', raw };
    if (t.startsWith('#') || t.startsWith(';')) return { type: 'comment', raw };
    const eq = raw.indexOf('=');
    if (eq === -1) return { type: 'pair', key: t, value: 'true', bare: true, raw };
    return { type: 'pair', key: raw.slice(0, eq).trim(), value: raw.slice(eq + 1).trim(), raw };
  });
}

// The project's committed allow-git / allow-remote values from <dir>/.npmrc:
// { file, exists, git, remote } — git/remote are the raw string values (which
// may be OUT of the enum, e.g. 'true'; the caller validates) or null when the
// key (or the file) is absent. Last occurrence wins, like npm's ini.
function readSourceConfig(dir) {
  const file = path.join(dir, '.npmrc');
  const out = { file, exists: false, git: null, remote: null };
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return out; }
  out.exists = true;
  for (const line of parseNpmrc(text)) {
    if (line.type !== 'pair') continue;
    for (const kind of ['git', 'remote']) {
      if (line.key === SOURCES[kind].key) out[kind] = line.value;
    }
  }
  return out;
}

// Set/replace keys in .npmrc text, preserving every other key, comment, blank
// line, order, and each line's own EOL style. Every occurrence of a managed
// key is rewritten (npm's ini is last-wins — leaving a stale duplicate behind
// would silently override the fix); missing keys are appended at the end.
// updates: { 'allow-git': 'all', … } — null/undefined values are ignored.
function mergeNpmrc(text, updates) {
  const sets = Object.entries(updates || {}).filter(([, v]) => v !== null && v !== undefined);
  if (sets.length === 0) return text;
  const byKey = new Map(sets);
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
    if (!byKey.has(key)) return part;
    missing.delete(key);
    return `${key}=${byKey.get(key)}${eol || '\n'}`;
  });
  let result = out.join('');
  if (missing.size > 0) {
    if (result !== '' && !result.endsWith('\n')) result += '\n';
    for (const [key, value] of sets) {
      if (missing.has(key)) result += `${key}=${value}\n`;
    }
  }
  return result;
}

module.exports = { parseNpmrc, readSourceConfig, mergeNpmrc };
