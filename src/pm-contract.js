'use strict';
// The install-script allowlist is no longer an npm-only idea: every major
// package manager now ships the same "scripts are opt-in, keep an allowlist"
// model, each with its own native format. This module is the cross-ecosystem
// contract: one adapter per manager describing where its allowlist lives, how
// a package is keyed, how to render the block, and how to merge decisions in.
// The behavioral risk analysis upstream is identical for all four; only this
// write/render surface differs.
//
// Formats verified against authoritative docs (2026-07-24):
//   npm 12, allowScripts   { "pkg@1.2.3": true }        in package.json
//   pnpm 11, allowBuilds     { pkg: true }                in pnpm-workspace.yaml
//              (pnpm 10.0–10.25 used the onlyBuiltDependencies array)
//   yarn B., dependenciesMeta.<pkg>.built: true           in package.json
//              (+ enableScripts: false in .yarnrc.yml to make it an allowlist)
//   bun: trustedDependencies: ["pkg"]                 in package.json
//              (NB: defining it REPLACES bun's built-in trusted list)
const fs = require('node:fs');
const path = require('node:path');
const { readNpmrcKeys, mergeNpmrc } = require('./npmrc');

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

// --- top-level YAML block merge, no YAML dependency ------------------------
// pnpm-workspace.yaml and .yarnrc.yml are both plain top-level maps, and every
// key this tool owns (allowBuilds, enableScripts, the COOLDOWN keys) is edited
// the same way: find the top-level key, replace its block (the key line plus
// the indented lines under it) in place, or append one at the end. Everything
// else, other keys, comments, blank lines, and each line's own EOL, keeps its
// exact bytes, so a write shows up in git as only the managed keys.
const yamlKey = (k) => (/^[A-Za-z0-9._-]+$/.test(k) ? k : JSON.stringify(k));
const unquote = (s) => (s.startsWith('"') ? JSON.parse(s) : s);

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const yamlParts = (text) => (text.length > 0 ? text.split(/(?<=\n)/) : []);
const yamlBody = (part) => part.replace(/\r?\n$/, '');
const eolOf = (part) => (part.match(/\r?\n$/) || [''])[0];
const dominantEol = (text) => (text.includes('\r\n') ? '\r\n' : '\n');

// [start, end) of `key`'s block: the key line, then every indented line under
// it. A blank line ends the block, matching how the allowBuilds reader has
// always drawn it.
function yamlBlockSpan(parts, key) {
  const head = new RegExp(`^${esc(key)}\\s*:`);
  const start = parts.findIndex((p) => head.test(yamlBody(p)));
  if (start === -1) return null;
  let end = start + 1;
  while (end < parts.length && /^\s+\S/.test(yamlBody(parts[end]))) end++;
  return { start, end };
}

// blocks: [{ key, lines }], lines[0] being the `key:` line itself. Returns the
// new text plus which keys were replaced and which had to be appended.
function mergeYamlBlocks(text, blocks) {
  const eol = dominantEol(text);
  const parts = yamlParts(text);
  const appended = [];
  const replaced = [];
  for (const { key, lines } of blocks) {
    const span = yamlBlockSpan(parts, key);
    // A one-line key replacing a one-line key keeps its trailing comment: that
    // comment may be the only record of why the value is what it is. A block
    // replacing a block has no single line to carry one.
    const kept = span && lines.length === 1 && span.end - span.start === 1
      ? (yamlBody(parts[span.start]).match(/\s+#.*$/) || [''])[0]
      : '';
    const body = [...lines];
    body[body.length - 1] += kept;
    const rendered = body.map((l) => l + eol);
    if (span) {
      // the replaced block's last line keeps the EOL it had, so a file with no
      // trailing newline does not silently gain one
      rendered[rendered.length - 1] = body[body.length - 1] + eolOf(parts[span.end - 1]);
      parts.splice(span.start, span.end - span.start, ...rendered);
      replaced.push(key);
    } else {
      if (parts.length > 0 && !eolOf(parts[parts.length - 1])) parts[parts.length - 1] += eol;
      parts.push(...rendered);
      appended.push(key);
    }
  }
  return { text: parts.join(''), appended, replaced };
}

// The scalar after a top-level `key:`, unquoted, or null when the key is
// absent or opens a block. line is 1-based.
function readYamlScalar(parts, key) {
  const head = new RegExp(`^${esc(key)}\\s*:\\s*(.*)$`);
  for (let i = 0; i < parts.length; i++) {
    const m = yamlBody(parts[i]).match(head);
    if (!m) continue;
    const raw = m[1].replace(/\s+#.*$/, '').trim();
    return { raw: raw === '' ? null : unquoteScalar(raw), line: i + 1 };
  }
  return null;
}

const unquoteScalar = (s) => ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))
  ? s.slice(1, -1) : s);

// A top-level sequence, either the block form (`- item` lines) or the inline
// flow form (`[a, b]`). null when the key is absent.
function readYamlList(parts, key) {
  const span = yamlBlockSpan(parts, key);
  if (!span) return null;
  const first = yamlBody(parts[span.start]).slice(yamlBody(parts[span.start]).indexOf(':') + 1).trim();
  if (first.startsWith('[')) {
    const inner = first.replace(/^\[/, '').replace(/\]$/, '');
    const values = inner.split(',').map((s) => unquoteScalar(s.trim())).filter(Boolean);
    return { values, line: span.start + 1 };
  }
  const values = [];
  for (let i = span.start + 1; i < span.end; i++) {
    const m = yamlBody(parts[i]).match(/^\s+-\s*(.*)$/);
    if (m) values.push(unquoteScalar(m[1].replace(/\s+#.*$/, '').trim()));
  }
  return { values, line: span.start + 1 };
}

function readAllowBuilds(dir) {
  const file = path.join(dir, 'pnpm-workspace.yaml');
  if (!fs.existsSync(file)) return {};
  const parts = yamlParts(fs.readFileSync(file, 'utf8'));
  const out = {};
  const span = yamlBlockSpan(parts, 'allowBuilds');
  if (!span) return out;
  for (let i = span.start + 1; i < span.end; i++) {
    const m = yamlBody(parts[i]).match(/^\s+("(?:[^"\\]|\\.)*"|[^:]+?):\s*(true|false)\s*$/);
    if (m) out[unquote(m[1].trim())] = m[2] === 'true';
  }
  return { file, entries: out, start: span.start, lines: parts.map(yamlBody) };
}

// entries: { name: boolean }. Merged into allowBuilds, or (replace:true) used
// as the complete block, sync uses replace to drop stale entries.
function writeAllowBuilds(dir, entries, { replace = false } = {}) {
  const existing = readAllowBuilds(dir);
  const merged = replace ? { ...entries } : { ...(existing.entries || {}), ...entries };
  const block = ['allowBuilds:', ...Object.keys(merged).sort()
    .map((k) => `  ${yamlKey(k)}: ${merged[k]}`)];
  return writeYamlFile(dir, 'pnpm-workspace.yaml', [{ key: 'allowBuilds', lines: block }]);
}

// Merge blocks into <dir>/<name>, creating the file when it does not exist.
// The note names what happened to the first block, which is what every
// caller reports.
function writeYamlFile(dir, name, blocks) {
  const file = path.join(dir, name);
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, `${blocks.flatMap((b) => b.lines).join('\n')}\n`);
    return { file, note: `created ${name} with ${blocks.map((b) => b.key).join(' and ')}` };
  }
  const before = fs.readFileSync(file, 'utf8');
  const { text, appended, replaced } = mergeYamlBlocks(before, blocks);
  if (text !== before) fs.writeFileSync(file, text);
  const note = replaced.length > 0
    ? `merged into the existing ${replaced.join(' and ')} block in ${name}`
    : `appended ${appended.map((k) => `an ${k}`).join(' and ')} block to ${name}`;
  return { file, note, changed: text !== before };
}

// --- .yarnrc.yml enableScripts:false ---------------------------------------
// Only ever added, never flipped: a non-false value is somebody's deliberate
// choice, so it is reported back rather than overwritten. The write goes
// through the same block merge as everything else in this file.
function ensureYarnScriptsDisabled(dir) {
  const file = path.join(dir, '.yarnrc.yml');
  const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
  if (/^enableScripts:\s*false\s*$/m.test(text)) return null;
  if (/^enableScripts:/m.test(text)) return `.yarnrc.yml sets enableScripts to a non-false value. Set it to false to make dependenciesMeta an allowlist`;
  writeYamlFile(dir, '.yarnrc.yml', [{ key: 'enableScripts', lines: ['enableScripts: false'] }]);
  return `set enableScripts: false in .yarnrc.yml`;
}

// --- the cooldown contract -------------------------------------------------
// Every manager now ships a minimum-release-age setting, and no two of them
// agree on the unit. This table is the only place any of those strings, keys
// or conversions appears, exactly as SOURCES in npm-contract.js owns npm's
// allow-git/allow-remote couplings.
//
// Verified against the authoritative sources (2026-09-08):
//   npm   docs.npmjs.com/cli/v11/using-npm/config
//         "If set, npm will build the npm tree such that only versions that
//          were available more than the given number of DAYS ago will be
//          installed."  Default null. Exclude: "a list of package names or
//          `minimatch` glob patterns".
//   pnpm  pnpm.io/settings/dependency-resolution
//         "minimumReleaseAge defines the minimum number of MINUTES that must
//          pass after a version is published before pnpm will install it."
//         Default 1440 (since v11), 0 before it. Exclude: string[], and the
//         docs show names, `@myorg/*` patterns and versions joined with `||`.
//   yarn  packages/plugin-npm/sources/index.ts
//         type SettingsType.DURATION, unit DurationUnit.MINUTES, default `1d`,
//         so a BARE NUMBER means minutes and a duration string is parsed by
//         miscUtils.parseDuration: /^(\d*\.?\d+)(ms|s|m|h|d|w)?$/.
//   bun   bun.com/docs/runtime/bunfig
//         [install] minimumReleaseAge in SECONDS, default null, documented
//         example 259200 (3 days). Excludes are package names only.
const UNIT_HOURS = { seconds: 1 / 3600, minutes: 1 / 60, hours: 1, days: 24 };

// Yarn's gate has moved four times, and the differences are load-bearing:
// before 4.11.0 the setting was SettingsType.NUMBER, so parseInt('7d') === 7
// and a documented duration string silently gated SEVEN MINUTES. That is what
// yarnpkg/berry#6991 hit; it was closed 2025-11-26 by the reporter with "the
// days formatting has been added in a later versions of Yarn".
const YARN_GATE = {
  introduced: '4.10.0', // #6901, SettingsType.NUMBER, default 0, minutes only
  duration: '4.11.0', // #6942 created SettingsType.DURATION
  defaultGate: '4.15.0', // #7135 made `1d` the default
  perScope: '4.17.0', // #7156 allowed the gate inside an npmScopes entry
  issue: 'yarnpkg/berry#6991',
};

const COOLDOWN = {
  npm: {
    id: 'npm',
    file: '.npmrc',
    key: 'min-release-age',
    excludeKey: 'min-release-age-exclude',
    unit: 'days',
    default: null,
    defaultText: 'null (no gate)',
    defaultNote: 'npm has no built-in cooldown; without this key nothing is gated',
    excludeForms: ['name', 'glob'],
    excludeNote: 'package names or minimatch glob patterns',
  },
  pnpm: {
    id: 'pnpm',
    file: 'pnpm-workspace.yaml',
    key: 'minimumReleaseAge',
    excludeKey: 'minimumReleaseAgeExclude',
    unit: 'minutes',
    default: 1440,
    defaultText: '1440 (1 day)',
    defaultNote: 'the 1440 default arrived in pnpm 11; pnpm 10 and earlier default to 0',
    excludeForms: ['name', 'glob', 'descriptor'],
    excludeNote: 'package names, patterns such as @myorg/*, and specific versions combinable with ||',
  },
  yarn: {
    id: 'yarn',
    file: '.yarnrc.yml',
    key: 'npmMinimalAgeGate',
    excludeKey: 'npmPreapprovedPackages',
    scopeKey: 'npmScopes',
    unit: 'minutes',
    duration: true,
    default: '1d',
    defaultText: '1d (1 day)',
    defaultNote: `the 1d default arrived in Yarn ${YARN_GATE.defaultGate}; earlier Yarn defaults to 0`,
    excludeForms: ['name', 'glob', 'descriptor'],
    excludeNote: 'package descriptors or package name glob patterns',
    versions: YARN_GATE,
  },
  bun: {
    id: 'bun',
    file: 'bunfig.toml',
    key: 'minimumReleaseAge',
    excludeKey: 'minimumReleaseAgeExcludes',
    section: 'install',
    unit: 'seconds',
    default: null,
    defaultText: 'null (no gate)',
    defaultNote: 'bun has no built-in cooldown; without this key nothing is gated',
    excludeForms: ['name'],
    excludeNote: 'package names only',
  },
};

const toHours = (row, value) => value * UNIT_HOURS[row.unit];
const toValue = (row, hours) => hours / UNIT_HOURS[row.unit];

// Yarn's own duration grammar, from miscUtils.parseDuration. A bare number is
// the setting's declared unit (minutes here); anything else is unparseable and
// is reported rather than guessed at.
const DURATION_MINUTES = { ms: 1 / 60000, s: 1 / 60, m: 1, h: 60, d: 1440, w: 10080 };
function parseYarnDuration(raw) {
  const m = /^(\d*\.?\d+)(ms|s|m|h|d|w)?$/.exec(String(raw).trim());
  if (!m) return null;
  return { minutes: parseFloat(m[1]) * (m[2] ? DURATION_MINUTES[m[2]] : 1), bare: m[2] === undefined };
}

// Yarn's own default is written as a duration string, so ours is too: the
// largest whole unit that divides the interval evenly.
function yarnDuration(hours) {
  if (hours === 0) return '0';
  if (hours % 168 === 0) return `${hours / 168}w`;
  if (hours % 24 === 0) return `${hours / 24}d`;
  if (Number.isInteger(hours)) return `${hours}h`;
  return `${trimNumber(hours * 60)}m`;
}

const trimNumber = (n) => (Number.isInteger(n) ? String(n) : String(Number(n.toFixed(6))));

// The value to commit for `hours`, in this manager's own unit and notation.
// `duration` overrides the row's notation: a Yarn older than 4.11.0 reads the
// setting with parseInt, so writing its own `3d` idiom there would commit a
// three-MINUTE gate. Callers that know the pinned Yarn pass duration: false.
function cooldownValue(row, hours, { duration = row.duration } = {}) {
  return duration ? yarnDuration(hours) : trimNumber(toValue(row, hours));
}

// Which of the three exemption shapes an entry is. Order matters: a scoped
// name starts with '@' but only a SECOND '@' makes it a version descriptor.
function excludeForm(entry) {
  if (/[*?[\]]/.test(entry)) return 'glob';
  if (/.@/.test(entry.startsWith('@') ? entry.slice(1) : entry) || entry.includes('||')) return 'descriptor';
  return 'name';
}

// --- bunfig.toml: tolerant, line-preserving [install] reader/writer ---------
// bunfig is the one file with no existing writer here, so this is deliberately
// the narrowest thing that can round-trip it: `[section]` headers, `key =
// value` pairs, `#` comments, blank lines. Anything else inside [install] is
// reported as `partial` and never rewritten, in the same spirit as the GYP and
// JSONC readers: a file we cannot round-trip gets a finding, not a guess and
// not a crash.
function readBunfig(dir) {
  const file = path.join(dir, 'bunfig.toml');
  const out = { file, exists: false, partial: null, entries: {}, section: null };
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return out; }
  out.exists = true;
  const parts = yamlParts(text);
  let inInstall = false;
  let start = -1;
  let end = -1;
  for (let i = 0; i < parts.length; i++) {
    const body = yamlBody(parts[i]);
    const t = body.trim();
    // [section] and TOML's array-of-tables [[section]] both close [install]
    const header = t.match(/^\[\s*([^\[\]]*?)\s*\]$|^\[\[\s*([^\[\]]*?)\s*\]\]$/);
    if (header) {
      if (inInstall) { end = i; inInstall = false; }
      if ((header[1] || header[2]) === 'install') { inInstall = true; start = i; }
      continue;
    }
    if (!inInstall || t === '' || t.startsWith('#')) continue;
    const pair = body.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$/);
    if (!pair) {
      if (!out.partial) out.partial = `bunfig.toml:${i + 1} is not a \`key = value\` line inside [install] and was left untouched: ${t.slice(0, 60)}`;
      continue;
    }
    out.entries[pair[1]] = { raw: pair[2].replace(/\s+#.*$/, '').trim(), line: i + 1 };
  }
  out.section = start === -1 ? null : { start, end: end === -1 ? parts.length : end };
  return out;
}

const tomlString = (s) => JSON.stringify(String(s));
const parseTomlArray = (raw) => {
  const m = String(raw).trim().match(/^\[(.*)\]$/s);
  if (!m) return null;
  const inner = m[1].trim();
  if (inner === '') return [];
  const items = inner.split(',').map((s) => s.trim()).filter((s) => s !== '');
  if (!items.every((s) => /^(".*"|'.*')$/s.test(s))) return null;
  return items.map((s) => s.slice(1, -1));
};

// updates: { key: renderedValue }. Sets each key inside [install], preserving
// every other line and each line's own EOL; creates the section (or the whole
// file) when it is missing.
function writeBunfig(dir, updates) {
  const file = path.join(dir, 'bunfig.toml');
  const pairs = Object.entries(updates);
  const render = (k, v) => `${k} = ${v}`;
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, `[install]\n${pairs.map(([k, v]) => render(k, v)).join('\n')}\n`);
    return { file, note: 'created bunfig.toml with an [install] section', changed: true };
  }
  const before = fs.readFileSync(file, 'utf8');
  const eol = dominantEol(before);
  const parts = yamlParts(before);
  const existing = readBunfig(dir);
  if (!existing.section) {
    if (parts.length > 0 && !eolOf(parts[parts.length - 1])) parts[parts.length - 1] += eol;
    parts.push(`[install]${eol}`, ...pairs.map(([k, v]) => `${render(k, v)}${eol}`));
    const text = parts.join('');
    fs.writeFileSync(file, text);
    return { file, note: 'appended an [install] section to bunfig.toml', changed: text !== before };
  }
  // last non-blank line of [install], so a new key lands with the others
  let insertAt = existing.section.start + 1;
  for (let i = existing.section.start + 1; i < existing.section.end; i++) {
    if (yamlBody(parts[i]).trim() !== '') insertAt = i + 1;
  }
  for (const [k, v] of pairs) {
    const at = existing.entries[k] ? existing.entries[k].line - 1 : null;
    if (at === null) {
      parts.splice(insertAt, 0, `${render(k, v)}${eol}`);
      insertAt++;
      continue;
    }
    const old = yamlBody(parts[at]);
    const indent = (old.match(/^\s*/) || [''])[0];
    const had = (old.match(/\s+#.*$/) || [''])[0];
    parts[at] = `${indent}${render(k, v)}${had}${eolOf(parts[at]) || eol}`;
  }
  const text = parts.join('');
  if (text !== before) fs.writeFileSync(file, text);
  return { file, note: `set ${pairs.map(([k]) => k).join(' and ')} in bunfig.toml [install]`, changed: text !== before };
}

// --- per-manager cooldown IO -----------------------------------------------
// readCooldown(dir) -> { row, file, exists, raw, line, hours, unparseable,
//                        exclude, excludeLine, scopes, partial }
// A missing file is `exists: false`, never a throw: MISSING is a finding, not
// an error. `hours` is null whenever the raw value could not be read as a
// number in this manager's unit.
const configRecord = (row, dir, extra = {}) => ({
  row,
  file: path.join(dir, row.file),
  exists: false,
  raw: null,
  line: null,
  hours: null,
  unparseable: null,
  exclude: [],
  excludeLine: null,
  scopes: [],
  misplaced: null,
  partial: null,
  ...extra,
});

// Shared by the two YAML managers: read the scalar gate and the exempt list
// out of an already-parsed file. Yarn adds duration strings and npmScopes on
// top of this; pnpm has neither.
function readYamlCooldown(row, dir, parseScalar) {
  const file = path.join(dir, row.file);
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return configRecord(row, dir); }
  const parts = yamlParts(text);
  const scalar = readYamlScalar(parts, row.key);
  const list = readYamlList(parts, row.excludeKey);
  const parsed = scalar && scalar.raw !== null ? parseScalar(scalar.raw) : null;
  return configRecord(row, dir, {
    exists: true,
    raw: scalar ? scalar.raw : null,
    line: scalar ? scalar.line : null,
    hours: parsed ? parsed.hours : null,
    unparseable: scalar && scalar.raw !== null && !parsed ? scalar.raw : null,
    bare: parsed ? parsed.bare : undefined,
    exclude: list ? list.values : [],
    excludeLine: list ? list.line : null,
    parts,
  });
}

const plainNumber = (row) => (raw) => {
  const n = Number(raw);
  return Number.isFinite(n) ? { hours: toHours(row, n), bare: true } : null;
};

const COOLDOWN_IO = {
  npm: {
    read(dir) {
      const row = COOLDOWN.npm;
      const cfg = readNpmrcKeys(dir, [row.key, row.excludeKey]);
      const raw = cfg.values[row.key];
      const n = raw === undefined ? null : Number(raw);
      return configRecord(row, dir, {
        exists: cfg.exists,
        raw: raw === undefined ? null : raw,
        line: cfg.lines[row.key] || null,
        hours: n !== null && Number.isFinite(n) ? toHours(row, n) : null,
        unparseable: raw !== undefined && !Number.isFinite(n) ? raw : null,
        exclude: cfg.multi[row.excludeKey] || [],
        excludeLine: cfg.lines[row.excludeKey] || null,
      });
    },
    write(dir, { hours, exclude, value }) {
      const row = COOLDOWN.npm;
      const file = path.join(dir, row.file);
      const before = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
      const updates = { [row.key]: value !== undefined ? value : cooldownValue(row, hours) };
      if (exclude.length > 0) updates[row.excludeKey] = exclude;
      const text = mergeNpmrc(before, updates);
      if (text !== before) fs.writeFileSync(file, text);
      return { file, note: `set ${row.key}=${updates[row.key]} in ${row.file}`, changed: text !== before };
    },
  },
  pnpm: {
    read(dir) {
      const row = COOLDOWN.pnpm;
      const cfg = readYamlCooldown(row, dir, plainNumber(row));
      if (cfg.raw === null) cfg.misplaced = misplacedInNpmrc(dir, row);
      return cfg;
    },
    write(dir, { hours, exclude, value }) {
      const row = COOLDOWN.pnpm;
      const blocks = [{ key: row.key, lines: [`${row.key}: ${value !== undefined ? value : cooldownValue(row, hours)}`] }];
      if (exclude.length > 0) {
        blocks.push({ key: row.excludeKey, lines: [`${row.excludeKey}:`, ...exclude.map((e) => `  - ${yamlKey(e)}`)] });
      }
      return writeYamlFile(dir, row.file, blocks);
    },
  },
  yarn: {
    read(dir) {
      const row = COOLDOWN.yarn;
      const cfg = readYamlCooldown(row, dir, (raw) => {
        const d = parseYarnDuration(raw);
        return d ? { hours: d.minutes / 60, bare: d.bare } : null;
      });
      if (cfg.parts) cfg.scopes = readYarnScopeGates(cfg.parts, row);
      return cfg;
    },
    write(dir, { hours, exclude, value }) {
      const row = COOLDOWN.yarn;
      const blocks = [{ key: row.key, lines: [`${row.key}: ${value !== undefined ? value : cooldownValue(row, hours)}`] }];
      if (exclude.length > 0) {
        blocks.push({ key: row.excludeKey, lines: [`${row.excludeKey}:`, ...exclude.map((e) => `  - ${yamlKey(e)}`)] });
      }
      // npmScopes is never in `blocks`, so a per-scope gate (berry#7156) keeps
      // its bytes: mergeYamlBlocks only ever touches the keys it is handed.
      return writeYamlFile(dir, row.file, blocks);
    },
  },
  bun: {
    read(dir) {
      const row = COOLDOWN.bun;
      const cfg = readBunfig(dir);
      if (!cfg.exists) return configRecord(row, dir);
      const gate = cfg.entries[row.key];
      const n = gate ? Number(gate.raw) : null;
      const ex = cfg.entries[row.excludeKey];
      const list = ex ? parseTomlArray(ex.raw) : null;
      return configRecord(row, dir, {
        exists: true,
        raw: gate ? gate.raw : null,
        line: gate ? gate.line : null,
        hours: n !== null && Number.isFinite(n) ? toHours(row, n) : null,
        unparseable: gate && !Number.isFinite(n) ? gate.raw : null,
        exclude: list || [],
        excludeLine: ex ? ex.line : null,
        partial: cfg.partial
          || (ex && list === null ? `bunfig.toml:${ex.line} has a ${row.excludeKey} value this reader cannot round-trip: ${ex.raw.slice(0, 60)}` : null),
      });
    },
    write(dir, { hours, exclude, value }) {
      const row = COOLDOWN.bun;
      const cfg = readBunfig(dir);
      if (cfg.partial) throw new Error(`${cfg.partial}. Fix the file by hand, then re-run \`cooldown --write\``);
      const updates = { [row.key]: value !== undefined ? value : cooldownValue(row, hours) };
      if (exclude.length > 0) updates[row.excludeKey] = `[${exclude.map(tomlString).join(', ')}]`;
      return writeBunfig(dir, updates);
    },
  },
};

// A pnpm setting parked in .npmrc, where pnpm no longer looks for it.
function misplacedInNpmrc(dir, row) {
  const cfg = readNpmrcKeys(dir, [row.key]);
  const raw = cfg.values[row.key];
  if (raw === undefined) return null;
  return { file: '.npmrc', key: row.key, raw, line: cfg.lines[row.key] || null };
}

// Per-scope gates from an npmScopes map (yarnpkg/berry#7156, Yarn 4.17.0).
// Read-only: a scope gate is reported, never rewritten.
function readYarnScopeGates(parts, row) {
  const span = yamlBlockSpan(parts, row.scopeKey);
  if (!span) return [];
  const out = [];
  let scope = null;
  for (let i = span.start + 1; i < span.end; i++) {
    const body = yamlBody(parts[i]);
    const head = body.match(/^ {2}("[^"]+"|[^:\s]+)\s*:\s*$/);
    if (head) { scope = unquoteScalar(head[1]); continue; }
    const gate = body.match(new RegExp(`^\\s{3,}${esc(row.key)}\\s*:\\s*(.+?)\\s*$`));
    if (gate && scope) {
      const raw = unquoteScalar(gate[1].replace(/\s+#.*$/, '').trim());
      const d = parseYarnDuration(raw);
      out.push({ scope, raw, line: i + 1, hours: d ? d.minutes / 60 : null, bare: d ? d.bare : false });
    }
  }
  return out;
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
    id: 'npm',
    readCooldown: (dir) => COOLDOWN_IO.npm.read(dir),
    writeCooldown: (dir, opts) => COOLDOWN_IO.npm.write(dir, opts),
    cooldown: COOLDOWN.npm, label: 'npm', allowlistFile: 'package.json', nativeKey: 'allowScripts',
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
    id: 'pnpm',
    readCooldown: (dir) => COOLDOWN_IO.pnpm.read(dir),
    writeCooldown: (dir, opts) => COOLDOWN_IO.pnpm.write(dir, opts),
    cooldown: COOLDOWN.pnpm, label: 'pnpm', allowlistFile: 'pnpm-workspace.yaml', nativeKey: 'allowBuilds',
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
    id: 'yarn',
    readCooldown: (dir) => COOLDOWN_IO.yarn.read(dir),
    writeCooldown: (dir, opts) => COOLDOWN_IO.yarn.write(dir, opts),
    cooldown: COOLDOWN.yarn, label: 'yarn (Berry)', allowlistFile: 'package.json', nativeKey: 'dependenciesMeta',
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
    id: 'bun',
    readCooldown: (dir) => COOLDOWN_IO.bun.read(dir),
    writeCooldown: (dir, opts) => COOLDOWN_IO.bun.write(dir, opts),
    cooldown: COOLDOWN.bun, label: 'bun', allowlistFile: 'package.json', nativeKey: 'trustedDependencies',
    note: 'bun keys by package name in trustedDependencies. ⚠️ Defining this field REPLACES bun\'s built-in trusted list, so packages bun trusted by default (e.g. esbuild, sharp) will stop running scripts unless you add them here too.',
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
      return { file: pkgPath, note: 'trustedDependencies replaces bun\'s default trusted list, so verify no default-trusted scripted deps were dropped' };
    },
    // bun has no way to record a denial (it is presence = trust); only trusts
    // are written, denials become untrusted-by-omission.
    writeDecisions(dir, decisions) {
      const denied = decisions.filter((d) => !d.allow).length;
      const res = this.write(dir, decisions.filter((d) => d.allow));
      return { ...res, note: `${res.note}${denied ? `; ${denied} denial(s) can't be recorded in bun, left untrusted by omission` : ''}` };
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

// YARN_GATE reaches callers as COOLDOWN.yarn.versions; the unit conversions,
// the YAML block merge and the bunfig writer are this module's own plumbing.
module.exports = {
  MANAGERS, managerFor, managerById,
  COOLDOWN, UNIT_HOURS, cooldownValue, yarnDuration, parseYarnDuration,
  excludeForm, readBunfig,
};
