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
    lines.push(`✓ cooldown ${hours}h — all ${ok} dated package(s) are old enough to have been caught.`);
  } else {
    lines.push(`✗ cooldown ${hours}h — ${blocked.length} package version(s) published too recently:`);
    for (const b of blocked) {
      lines.push(`  ${b.name}@${b.version}  ${b.label}  (clears ${b.releasesAt.replace('T', ' ').slice(0, 16)}Z)`);
    }
    lines.push('');
    lines.push('These may be perfectly fine. Cooldown does not inspect them — it declines to be');
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

module.exports = { evaluateCooldown, cooldownReport, ageHours, fmtAge, DEFAULT_HOURS };
