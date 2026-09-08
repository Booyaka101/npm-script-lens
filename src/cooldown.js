'use strict';
// Version cooldown: refuse dependency versions that are too young to have been
// caught yet.
//
// Every recent npm worm, Shai-Hulud, Mini Shai-Hulud (keyv/cacheable, Aug 4
// 2026), was identified and unpublished within hours of the poisoned versions
// going live. The install that hurts you is the one that happens inside that
// window. A cooldown does not try to detect anything: it just declines to be
// first, which sits out the whole event.
//
// This is the one check here that says nothing about what a package DOES. A
// package can be perfectly clean and still fail cooldown; that is the point.
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_HOURS = 72;

// Age in hours from the absolute publish timestamp, never from trust.ageDays.
// fetchTrust() computes ageDays once and caches the whole object for 24h, so a
// row pulled from cache can claim an age that is up to a day stale. For a
// 24-72h gate that error is the same size as the gate, and it fails OPEN
// (reporting a package as older, therefore safer, than it is). Always derive
// from publishedAt at evaluation time.
function ageHours(trust, now = Date.now()) {
  if (!trust || !trust.publishedAt) return null;
  const t = Date.parse(trust.publishedAt);
  if (Number.isNaN(t)) return null;
  return Math.max(0, (now - t) / 3600000);
}

function fmtAge(hours) {
  if (hours === null) return 'unknown age';
  if (hours < 1) return `${Math.round(hours * 60)}m old`;
  if (hours < 48) return `${hours.toFixed(1)}h old`;
  return `${(hours / 24).toFixed(1)}d old`;
}

// rows: [{ name, version, trust }], the audit rows, already trust-enriched.
// Returns blocked (too young), unknown (no publish date available) and the
// threshold, so the caller decides how loud to be about each.
function evaluateCooldown(rows, { hours = DEFAULT_HOURS, allow = [], now = Date.now() } = {}) {
  const exempt = new Set(allow);
  const blocked = [];
  const unknown = [];
  let checked = 0;
  for (const r of rows || []) {
    if (exempt.has(r.name) || exempt.has(`${r.name}@${r.version}`)) continue;
    const age = ageHours(r.trust, now);
    if (age === null) {
      // No publish date means we could not prove the version is old enough.
      // Reported separately rather than blocked: --offline and private
      // registries legitimately have no packument, and failing those closed
      // would make the gate unusable in exactly the setups that most want it.
      unknown.push({ name: r.name, version: r.version });
      continue;
    }
    checked++;
    if (age < hours) {
      blocked.push({
        name: r.name,
        version: r.version,
        ageHours: age,
        publishedAt: r.trust.publishedAt,
        releasesAt: new Date(Date.parse(r.trust.publishedAt) + hours * 3600000).toISOString(),
        label: fmtAge(age),
      });
    }
  }
  blocked.sort((a, b) => a.ageHours - b.ageHours);
  return { hours, blocked, unknown, checked, ok: checked - blocked.length };
}

function cooldownReport(result) {
  const { hours, blocked, unknown, ok } = result;
  const lines = [];
  if (blocked.length === 0) {
    lines.push(`✓ cooldown ${hours}h: all ${ok} dated package(s) are old enough to have been caught.`);
  } else {
    lines.push(`✗ cooldown ${hours}h: ${blocked.length} package version(s) published too recently:`);
    for (const b of blocked) {
      lines.push(`  ${b.name}@${b.version}  ${b.label}  (clears ${b.releasesAt.replace('T', ' ').slice(0, 16)}Z)`);
    }
    lines.push('');
    lines.push('These may be perfectly fine. Cooldown does not inspect them. It declines to be');
    lines.push('among the first to install a version, because npm worms are typically caught');
    lines.push('within hours. Wait, pin to an older version, or exempt with --cooldown-allow.');
  }
  if (unknown.length > 0) {
    lines.push('');
    lines.push(`${unknown.length} package(s) had no publish date and were not checked (offline or private registry):`);
    lines.push(`  ${unknown.slice(0, 8).map((u) => `${u.name}@${u.version}`).join(', ')}${unknown.length > 8 ? ', …' : ''}`);
  }
  return lines.join('\n');
}

// ===========================================================================
// Config reconciliation: the cooldown the PACKAGE MANAGER applies on every
// local install, against the one --cooldown enforces in CI.
//
// evaluateCooldown above judges lockfile ages at CI time and knows nothing
// about the setting a contributor's `pnpm install` actually honours. All four
// managers now ship that setting, in four different units (see COOLDOWN in
// pm-contract.js), and getting the unit wrong is silent: the install succeeds,
// the gate is simply not there. yarnpkg/berry#6991 is that failure reported by
// a real user. Both halves live here because they answer one question, "is
// this project actually waiting?", from two different files.

const {
  COOLDOWN, UNIT_HOURS, managerFor, cooldownValue, excludeForm,
} = require('./pm-contract');

// A cooldown between an hour and a month is a deliberate choice in any unit,
// so a value that lands inside this band is never second-guessed.
const SANE_MIN_HOURS = 1;
const SANE_MAX_HOURS = 30 * 24;

const STATUS = {
  OK: 'OK',
  MISSING: 'MISSING',
  SUSPECT: 'UNIT-SUSPECT',
  DRIFT: 'DRIFT',
  PARTIAL: 'PARTIAL',
  UNSUPPORTED: 'UNSUPPORTED',
};
const FAILING = new Set([STATUS.MISSING, STATUS.SUSPECT, STATUS.DRIFT, STATUS.PARTIAL]);

// The statuses that make --check exit 1. UNSUPPORTED and OK are reported but
// never fail: neither is something the project got wrong.
const isFailing = (id) => FAILING.has(id);

// Hours are the unit --cooldown speaks, so they stay the default. A misread
// unit produces intervals hours cannot express legibly (4320 DAYS is 103680h),
// so the two extremes switch to days and seconds rather than print a wall.
function fmtHours(h) {
  if (h === null || h === undefined) return 'unknown';
  if (h >= SANE_MAX_HOURS) return `${Number((h / 24).toFixed(1))}d`;
  if (h >= 0.01) return `${Number(h.toFixed(2))}h`;
  return `${Number((h * 3600).toFixed(0))}s`;
}

const singular = { seconds: 'second', minutes: 'minute', hours: 'hour', days: 'day' };
const plural = (n, unit) => `${n} ${singular[unit] || unit}${n === 1 ? '' : 's'}`;

// Is this number almost certainly written in the wrong unit for this manager?
// Only when it reads as an absurd interval AS WRITTEN *and* the very same
// number is a sensible cooldown under one of the other managers' units. A
// value with no sane alternative reading is a deliberate extreme, not a unit
// mistake, and is reported as OK with its converted hours.
function unitSuspicion(row, value) {
  if (!Number.isFinite(value) || value <= 0) return null;
  const hours = value * UNIT_HOURS[row.unit];
  if (hours >= SANE_MIN_HOURS && hours <= SANE_MAX_HOURS) return null;
  const alternatives = Object.entries(UNIT_HOURS)
    .filter(([unit]) => unit !== row.unit)
    .map(([unit, per]) => ({ unit, hours: value * per }))
    .filter((a) => a.hours >= SANE_MIN_HOURS && a.hours <= SANE_MAX_HOURS);
  if (alternatives.length === 0) return null;
  // the largest sane reading: for a value that gates nothing it is what the
  // author meant, and for one that gates years it is the mildest correction
  const likely = alternatives.reduce((best, a) => (a.hours > best.hours ? a : best));
  return { hours, likely };
}

// Which Yarn this project pins, from committed evidence only: `packageManager`
// in package.json, then `yarnPath` in .yarnrc.yml. No live probe, so the
// report stays byte-stable for CI diffing.
function resolveYarnVersion(dir) {
  try {
    const pm = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).packageManager;
    const m = /^yarn@(\d+\.\d+\.\d+)/.exec(String(pm || ''));
    if (m) return { version: m[1], via: 'packageManager in package.json' };
  } catch { /* no package.json, or not JSON */ }
  try {
    const m = /^yarnPath:\s*["']?\S*?yarn-(\d+\.\d+\.\d+)\.cjs/m.exec(fs.readFileSync(path.join(dir, '.yarnrc.yml'), 'utf8'));
    if (m) return { version: m[1], via: 'yarnPath in .yarnrc.yml' };
  } catch { /* no .yarnrc.yml */ }
  return null;
}

// The same dotted numeric compare `sources` already does for npm versions,
// pointed at Yarn's.
const versionLt = (a, b) => !require('./sources').versionGte(a, b);

// --- what CI actually enforces ---------------------------------------------
// The committed `--cooldown` threshold, found in the repo's own CI configs.
// This is the number the manager config has to keep up with: without it,
// MISSING and DRIFT have nothing to be measured against.
const CI_FILES = ['.gitlab-ci.yml', '.circleci/config.yml'];
const CI_SEARCH_LEVELS = 6;

function ciConfigFilesIn(dir) {
  const { workflowFiles } = require('./v12gaps');
  const extra = CI_FILES.map((f) => path.join(dir, f)).filter((f) => fs.existsSync(f));
  return [...workflowFiles(dir), ...extra];
}

// In a monorepo the CI configs sit at the repo root, not next to each
// package's lockfile, so the search walks up. The FIRST level holding any CI
// config wins, whether or not it mentions --cooldown: that is the CI this
// project runs under, and finding none there means nothing is enforced. The
// walk stops at the git root either way.
function ciConfigFiles(projectDir) {
  let dir = projectDir;
  for (let i = 0; i < CI_SEARCH_LEVELS; i++) {
    const found = ciConfigFilesIn(dir);
    if (found.length > 0) return found;
    if (fs.existsSync(path.join(dir, '.git'))) return [];
    const up = path.dirname(dir);
    if (up === dir) return [];
    dir = up;
  }
  return [];
}

// Package names stop at the next flag or shell operator, matching how
// commander consumes a variadic option.
function parseAllowRun(rest) {
  const out = [];
  for (const tok of rest.trim().split(/\s+/)) {
    if (tok === '' || tok.startsWith('-') || /^[|&;]/.test(tok)) break;
    out.push(tok.replace(/^["']|["']$/g, ''));
  }
  return out;
}

// Every `--cooldown [hours]` site in the CI configs, with its --cooldown-allow
// list. `hours` follows the CLI: a bare --cooldown means DEFAULT_HOURS.
function findEnforcedCooldown(projectDir) {
  const sites = [];
  for (const file of ciConfigFiles(projectDir)) {
    const rel = path.relative(projectDir, file).replace(/\\/g, '/');
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    text.split(/\r?\n/).forEach((line, idx) => {
      if (/^\s*#/.test(line)) return;
      const m = /--cooldown(?![-\w])(?:[ \t=]+(\d+(?:\.\d+)?))?/.exec(line);
      if (!m) return;
      const allowMatch = /--cooldown-allow[ \t=]+(.*)$/.exec(line);
      sites.push({
        file: rel,
        line: idx + 1,
        hours: m[1] === undefined ? DEFAULT_HOURS : Number(m[1]),
        allow: allowMatch ? parseAllowRun(allowMatch[1]) : [],
      });
    });
  }
  if (sites.length === 0) return null;
  // the strictest site is the bar the committed config has to clear
  const strictest = sites.reduce((best, s) => (s.hours > best.hours ? s : best));
  return { ...strictest, sites };
}

// --- the classifier --------------------------------------------------------
// config: a MANAGERS[x].readCooldown(dir) result. enforced: findEnforcedCooldown
// output, or an explicit { hours, allow } from the CLI.
function classifyCooldown(config, { enforced = null, allow = null } = {}) {
  const row = config.row;
  const statuses = [];
  const at = (extra) => ({ file: config.file, line: config.line, ...extra });
  // An exempt list is only comparable when one side actually states one: the
  // user passing --cooldown-allow, or a CI site whose command line is the
  // authority on what CI exempts. A bare `--cooldown 72` says nothing about
  // exemptions, so the committed list is not drift against it.
  const statedAllow = allow !== null ? allow
    : enforced && enforced.source === 'ci' ? enforced.allow || []
      : null;

  let silentIgnoreHours = null;

  if (config.partial) statuses.push(at({ id: STATUS.PARTIAL, line: null, message: config.partial }));

  if (config.unparseable !== null) {
    statuses.push(at({
      id: STATUS.SUSPECT,
      message: `${assignment(row, config.unparseable)}  → not a value ${row.id} can read`,
      detail: row.duration
        ? 'Yarn parses this setting with /^(\\d*\\.?\\d+)(ms|s|m|h|d|w)?$/ and throws on anything else, so the install errors instead of gating'
        : `${row.id} expects a number of ${row.unit}`,
    }));
  } else if (config.raw === null) {
    if (config.misplaced) {
      statuses.push({
        file: path.join(path.dirname(config.file), config.misplaced.file),
        line: config.misplaced.line,
        id: STATUS.MISSING,
        message: `${row.key} is in ${config.misplaced.file} (${config.misplaced.raw}), not ${row.file}, so ${row.id} never reads it`,
        detail: `${row.id} takes only auth and registry settings from .npmrc; everything else has to be in ${row.file}. Move the line and the value takes effect.`,
      });
    } else if (enforced) {
      statuses.push(at({
        id: STATUS.MISSING,
        line: null,
        message: `no ${row.key} in ${row.file}  → CI waits ${fmtHours(enforced.hours)}, local installs wait ${row.default === null ? 'nothing' : `whatever this ${row.id} defaults to`}`,
        detail: `${row.id}'s own default is ${row.defaultText}; ${row.defaultNote}. Only CI is protected until the value is committed.`,
      }));
    }
  } else {
    const yarnSilent = yarnSilentIgnore(row, config);
    if (yarnSilent && yarnSilent.effectiveHours !== undefined) silentIgnoreHours = yarnSilent.effectiveHours;
    const suspicion = row.duration && config.bare === false
      ? null
      : unitSuspicion(row, Number(config.raw));
    if (yarnSilent) statuses.push(at(yarnSilent));
    else if (suspicion) {
      const n = Number(config.raw);
      statuses.push(at({
        id: STATUS.SUSPECT,
        message: `${assignment(row, config.raw)}  → ${plural(n, row.unit)} (${row.id} counts ${row.unit.toUpperCase()}), not ${plural(n, suspicion.likely.unit)}`,
        detail: `${row.id}'s own default is ${row.defaultText}; ${config.raw} gates ${suspicion.hours < SANE_MIN_HOURS ? 'essentially nothing' : fmtHours(suspicion.hours)}`,
      }));
    }
  }

  // What the manager ACTUALLY gates, which is not what the file says when an
  // old Yarn is truncating a duration string.
  const effective = silentIgnoreHours !== null ? silentIgnoreHours : config.hours;
  if (enforced && effective !== null && effective < enforced.hours) {
    statuses.push(at({
      id: STATUS.DRIFT,
      message: `configured ${fmtHours(effective)} < enforced ${fmtHours(enforced.hours)} (--cooldown in ${enforced.file})`
        + (silentIgnoreHours !== null ? `, because ${row.id} truncates ${config.raw} here` : ''),
      detail: 'A version this project\'s own CI would block still installs on a contributor\'s machine.',
    }));
  }

  // Only exemptions this manager can express are compared. bun takes package
  // names only, so a `pkg@1.2.3` in CI is not drift against a bunfig that
  // could never have carried it; it is reported once, on its own line.
  const { accepted, rejected } = splitExclude(row, statedAllow || []);
  if (rejected.length > 0) {
    statuses.push(at({
      id: STATUS.UNSUPPORTED,
      line: config.excludeLine,
      message: `${rejected.join(', ')} cannot be exempted in ${row.file}: ${row.excludeKey} accepts ${row.excludeNote}`,
    }));
  }
  const excludeDrift = statedAllow === null ? null : diffExclude(config.exclude, accepted);
  if (excludeDrift) {
    statuses.push(at({
      id: STATUS.DRIFT,
      line: config.excludeLine,
      message: `exempt lists disagree: ${excludeDrift}`,
      detail: `${row.excludeKey} in ${row.file} accepts ${row.excludeNote}.`,
    }));
  }

  return {
    manager: row.id,
    file: config.file,
    exists: config.exists,
    key: row.key,
    unit: row.unit,
    raw: config.raw,
    line: config.line,
    hours: config.hours,
    exclude: config.exclude,
    excludeKey: row.excludeKey,
    scopes: config.scopes || [],
    enforced: enforced
      ? { hours: enforced.hours, file: enforced.file, line: enforced.line, allow: enforced.allow || [] }
      : null,
    statuses,
    ok: !statuses.some((s) => FAILING.has(s.id)),
  };
}

// The one classification that depends on the manager's VERSION, not its value.
// Before Yarn 4.11.0 npmMinimalAgeGate was SettingsType.NUMBER, so parseInt ate
// the suffix and `7d` gated seven MINUTES with no error. That is what
// yarnpkg/berry#6991 reported; the reporter closed it 2025-11-26 with "the days
// formatting has been added in a later versions of Yarn". So this is only ever
// reported against a resolved Yarn version, never as a blanket warning that
// duration strings are unreliable, because on current Yarn they are exact.
function yarnSilentIgnore(row, config) {
  if (!row.duration || config.bare !== false) return null;
  const asParseInt = parseInt(config.raw, 10);
  const yarn = resolveYarnVersion(path.dirname(config.file));
  if (!yarn) {
    return {
      id: STATUS.OK,
      message: `${assignment(row, config.raw)}  → ${fmtHours(config.hours)} on Yarn ${row.versions.duration} or newer`,
      detail: `This project pins no Yarn version (no packageManager field, no yarnPath), so the duration string cannot be checked against one. Yarn below ${row.versions.duration} reads this setting with parseInt and would gate ${plural(asParseInt, 'minutes')} instead (${row.versions.issue}).`,
    };
  }
  if (!versionLt(yarn.version, row.versions.duration)) return null;
  return {
    id: STATUS.SUSPECT,
    effectiveHours: asParseInt / 60,
    message: `${assignment(row, config.raw)}  → gates ${plural(asParseInt, 'minutes')} on Yarn ${yarn.version}, not ${fmtHours(config.hours)}`,
    detail: `Duration strings arrived in Yarn ${row.versions.duration}; this project pins ${yarn.version} (${yarn.via}), where the setting is still SettingsType.NUMBER and parseInt("${config.raw}") is ${asParseInt}. Nothing errors, the gate simply is not there. That is ${row.versions.issue}. Upgrade Yarn, or write ${Math.round(config.hours * 60)} instead.`,
  };
}

// Human summary of two exempt lists that are not the same set, or null.
function diffExclude(committed, enforcedAllow) {
  const a = new Set(committed || []);
  const b = new Set(enforcedAllow || []);
  const onlyCommitted = [...a].filter((x) => !b.has(x)).sort();
  const onlyEnforced = [...b].filter((x) => !a.has(x)).sort();
  if (onlyCommitted.length === 0 && onlyEnforced.length === 0) return null;
  const bits = [];
  if (onlyCommitted.length > 0) bits.push(`${onlyCommitted.join(', ')} exempt locally but not in CI`);
  if (onlyEnforced.length > 0) bits.push(`${onlyEnforced.join(', ')} exempt in CI but not locally`);
  return bits.join('; ');
}

// --- reading a project -----------------------------------------------------
// `hours`/`allow` override what CI enforces; without them the CI configs are
// the source of truth, because they are what the repo actually runs.
function readCooldownConfig(lockPath, type, { hours = null, allow = null } = {}) {
  const dir = path.dirname(lockPath);
  const manager = managerFor(type);
  const found = hours !== null ? null : findEnforcedCooldown(dir);
  const stated = hours !== null
    ? { hours, allow: allow || [], file: '--cooldown', line: null, sites: [], source: 'flag' }
    : found && { ...found, source: 'ci' };
  // A zero threshold is a cooldown switched off, so there is no bar for the
  // committed config to fall short of and nothing MISSING about not setting one.
  const enforced = stated && stated.hours > 0 ? stated : null;
  const report = classifyCooldown(manager.readCooldown(dir), { enforced, allow });
  report.projectDir = dir;
  return report;
}

// The value `cooldown --write` would commit, and where that number came from.
// Yarn gets its own duration idiom (`3d`, the notation its own default uses)
// only on a Yarn that parses one. On a pinned Yarn below 4.11.0 that string
// would be eaten by parseInt, so the bare minute count goes in instead.
function writeTarget(report, { hours = null } = {}) {
  const chosen = hours !== null ? hours : report.enforced ? report.enforced.hours : DEFAULT_HOURS;
  const row = COOLDOWN[report.manager];
  let duration = row.duration;
  let note = null;
  if (row.duration) {
    const yarn = resolveYarnVersion(path.dirname(report.file));
    if (yarn && versionLt(yarn.version, row.versions.duration)) {
      duration = false;
      note = `written as bare minutes: this project pins Yarn ${yarn.version}, which predates duration strings (${row.versions.duration})`;
    }
  }
  return { hours: chosen, value: cooldownValue(row, chosen, { duration }), row, note };
}

// Only exemptions this manager can actually honour are written. bun matches
// package names only, so a version descriptor handed to it would be a gate the
// user believes in and bun ignores.
function splitExclude(row, allow) {
  const accepted = [];
  const rejected = [];
  for (const entry of allow || []) {
    (row.excludeForms.includes(excludeForm(entry)) ? accepted : rejected).push(entry);
  }
  return { accepted, rejected };
}

const PAD = STATUS.SUSPECT.length;
const label = (s) => s.padEnd(PAD);

// How the managed value looks committed, so the fix line shows the real edit.
const assignment = (row, value) => (row.file === '.npmrc' ? `${row.key}=${value}`
  : row.section ? `[${row.section}] ${row.key} = ${value}`
    : `${row.key}: ${value}`);

function renderCooldownConfig(report, { hours = null } = {}) {
  const row = COOLDOWN[report.manager];
  const lines = [`cooldown config — ${report.manager} (${row.file})`];
  // The OK line carries the converted hours, which is the number the whole
  // command exists to show, so a report that passes always gets one. Unless a
  // status is already saying it: the unpinned-Yarn note is its own OK line.
  if (report.ok && !report.statuses.some((s) => s.id === STATUS.OK)) {
    lines.push(`  ${label(STATUS.OK)}  ${report.raw === null
      ? `no ${row.key}, and no --cooldown enforced in CI, so nothing is out of step`
      : `${assignment(row, report.raw)}  → ${fmtHours(report.hours)}${report.enforced ? `, meeting the enforced ${fmtHours(report.enforced.hours)}` : ''}`}`);
  }
  for (const s of report.statuses) {
    lines.push(`  ${label(s.id)}  ${s.message}`);
    if (s.detail) lines.push(`  ${label('')}  ${s.detail}`);
  }
  for (const scope of report.scopes) {
    lines.push(`  ${label('scope')}  ${row.scopeKey}.${scope.scope}: ${row.key} ${scope.raw} → ${fmtHours(scope.hours)} (read, never rewritten)`);
  }
  if (report.exclude.length > 0) {
    lines.push(`  ${label('exempt')}  ${row.excludeKey}: ${report.exclude.join(', ')}`);
  }
  if (!report.ok) {
    const target = writeTarget(report, { hours });
    if (report.statuses.some((s) => s.id === STATUS.PARTIAL)) {
      lines.push(`  fix:  edit ${row.file} by hand, then re-run. --write refuses a file it cannot round-trip`);
      lines.push(`        wants   ${assignment(row, target.value)}`);
    } else {
      lines.push(`  fix:  npm-script-lens cooldown --write --cooldown ${target.hours}`);
      lines.push(`        writes  ${assignment(row, target.value)}`);
    }
  }
  return lines.join('\n');
}

function cooldownConfigJson(report) {
  return {
    manager: report.manager,
    file: path.basename(report.file),
    key: report.key,
    unit: report.unit,
    raw: report.raw,
    line: report.line,
    hours: report.hours,
    exclude: report.exclude,
    excludeKey: report.excludeKey,
    scopes: report.scopes,
    enforced: report.enforced,
    ok: report.ok,
    statuses: report.statuses.map((s) => ({ id: s.id, message: s.message, detail: s.detail || null, line: s.line || null })),
  };
}

// SARIF-ready findings (rule cooldown-config), the generic shape
// reporter.buildSarif consumes for the gap/publish/hook rules. error for
// MISSING / UNIT-SUSPECT under --check, warning otherwise, anchored to the real
// config line. A finding about a file that does not exist carries no `file`, so
// the alert lands on the lockfile instead of on a path the repo has not got.
function cooldownFindings(reports, { check = false } = {}) {
  const out = [];
  for (const report of reports) {
    for (const s of report.statuses.filter((st) => FAILING.has(st.id))) {
      const hard = check && (s.id === STATUS.MISSING || s.id === STATUS.SUSPECT);
      const finding = {
        id: 'cooldown-config',
        level: hard ? 'error' : 'warning',
        package: report.manager,
        fix: `${s.id}: ${s.message}${s.detail ? `. ${s.detail}` : ''}`,
        fingerprint: `cooldown-config:${report.manager}:${s.id}:${path.basename(report.file)}:${s.line || 0}`,
      };
      if (report.exists && s.line) {
        const rel = path.relative(process.cwd(), report.file).replace(/\\/g, '/');
        if (!rel.startsWith('..')) {
          finding.file = rel;
          finding.line = s.line;
        }
      }
      out.push(finding);
    }
  }
  return out;
}

module.exports = {
  evaluateCooldown, cooldownReport, ageHours, fmtAge, DEFAULT_HOURS,
  STATUS, isFailing, classifyCooldown, readCooldownConfig, findEnforcedCooldown,
  renderCooldownConfig, cooldownConfigJson, cooldownFindings, writeTarget,
  splitExclude, unitSuspicion, resolveYarnVersion, fmtHours, diffExclude,
};
