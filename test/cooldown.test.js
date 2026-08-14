'use strict';
// Version cooldown: block dependency versions too young to have been caught.
// The gate is only worth anything if it is exact at the boundary and if it
// never reads a stale cached age, so both are pinned here.
const { test } = require('node:test');
const assert = require('node:assert');
const { evaluateCooldown, ageHours, fmtAge, DEFAULT_HOURS } = require('../src/cooldown');

const NOW = Date.parse('2026-08-05T12:00:00Z');
const agoH = (h) => new Date(NOW - h * 3600000).toISOString();
const row = (name, version, hoursOld, extra = {}) => ({
  name, version,
  trust: hoursOld === null ? null : { publishedAt: agoH(hoursOld), ...extra },
});

test('ageHours derives from publishedAt, ignoring a stale cached ageDays', () => {
  // fetchTrust caches its whole object for 24h, so ageDays can be a day behind
  // and always errs toward "older", i.e. it fails OPEN on a young package.
  const trust = { publishedAt: agoH(2), ageDays: 30 };
  assert.strictEqual(Math.round(ageHours(trust, NOW)), 2, 'must not trust the cached ageDays');
  assert.strictEqual(ageHours(null, NOW), null);
  assert.strictEqual(ageHours({ publishedAt: 'not-a-date' }, NOW), null);
  assert.strictEqual(ageHours({}, NOW), null);
});

test('blocks younger than the threshold, passes at and above it', () => {
  const rows = [
    row('fresh-poison', '9.9.9', 0.5),
    row('borderline', '1.0.0', 71.9),
    row('exactly-at', '1.0.0', 72),
    row('old-and-boring', '4.5.4', 24 * 400),
  ];
  const r = evaluateCooldown(rows, { hours: 72, now: NOW });
  assert.deepStrictEqual(r.blocked.map((b) => b.name), ['fresh-poison', 'borderline'],
    'exactly-at the threshold is allowed: the gate is "younger than", not "younger or equal"');
  assert.strictEqual(r.checked, 4);
  assert.strictEqual(r.ok, 2);
  assert.strictEqual(r.hours, 72);
});

test('blocked entries carry when the version clears, sorted youngest first', () => {
  const r = evaluateCooldown([row('a', '1.0.0', 10), row('b', '2.0.0', 1)], { hours: 24, now: NOW });
  assert.deepStrictEqual(r.blocked.map((b) => b.name), ['b', 'a'], 'youngest first, that is the riskiest');
  assert.strictEqual(r.blocked[0].releasesAt, new Date(NOW - 1 * 3600000 + 24 * 3600000).toISOString());
  assert.match(r.blocked[0].label, /h old$/);
});

test('missing publish date is reported as unknown, never silently blocked or passed', () => {
  const r = evaluateCooldown([row('private-pkg', '1.0.0', null), row('ok', '1.0.0', 500)], { hours: 72, now: NOW });
  assert.deepStrictEqual(r.unknown, [{ name: 'private-pkg', version: '1.0.0' }]);
  assert.strictEqual(r.blocked.length, 0);
  assert.strictEqual(r.checked, 1, 'undated packages are not counted as checked');
});

test('--cooldown-allow exempts by name and by exact name@version', () => {
  const rows = [row('urgent-fix', '2.0.1', 1), row('other', '1.0.0', 1), row('pinned', '3.0.0', 1)];
  const r = evaluateCooldown(rows, { hours: 72, now: NOW, allow: ['urgent-fix', 'pinned@3.0.0'] });
  assert.deepStrictEqual(r.blocked.map((b) => b.name), ['other']);
  const wrongVersion = evaluateCooldown([row('pinned', '3.0.1', 1)], { hours: 72, now: NOW, allow: ['pinned@3.0.0'] });
  assert.strictEqual(wrongVersion.blocked.length, 1, 'an exact-version exemption must not cover another version');
});

test('empty and absent input do not throw', () => {
  assert.strictEqual(evaluateCooldown([], { now: NOW }).blocked.length, 0);
  assert.strictEqual(evaluateCooldown(undefined, { now: NOW }).blocked.length, 0);
  assert.strictEqual(evaluateCooldown([], { now: NOW }).hours, DEFAULT_HOURS);
});

test('fmtAge switches units at sensible points', () => {
  assert.strictEqual(fmtAge(0.5), '30m old');
  assert.strictEqual(fmtAge(3), '3.0h old');
  assert.strictEqual(fmtAge(96), '4.0d old');
  assert.strictEqual(fmtAge(null), 'unknown age');
});

test('the real Mini Shai-Hulud window: a 72h gate sits out an attack caught in 6h', () => {
  // keyv and friends, poisoned 2026-08-04, identified the same day.
  const poisoned = row('keyv', '5.5.5', 6);
  const safe = row('keyv', '4.5.4', 24 * 300);
  const r = evaluateCooldown([poisoned, safe], { hours: 72, now: NOW });
  assert.deepStrictEqual(r.blocked.map((b) => `${b.name}@${b.version}`), ['keyv@5.5.5']);
});
