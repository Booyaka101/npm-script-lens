'use strict';
// The trust-downgrade check npm and Yarn were asked for and pnpm shipped:
// flag a resolved version whose trust tier is LOWER than the highest tier any
// earlier version of the same package reached. A stolen npm token can publish,
// but it cannot run the maintainer's CI, so the malicious release drops from
// provenance (or trusted publisher) to none, which is exactly how the axios
// 1.14.1 / 0.30.4 releases looked. pnpm >= 10.21 refuses these installs under
// trust-policy=no-downgrade; npm/cli#9242 and yarnpkg/berry#7101 are still
// open, so the policy keys here reuse #9242's names (trust-policy,
// trust-policy-exclude, trust-policy-ignore-after) for a config that carries
// over if npm ever ships it.
const { fetchPackument } = require('./registry');
const { trustGet, trustSet } = require('./cache');

// #9242's ladder: trusted publisher > provenance > none.
const TIERS = ['none', 'provenance', 'trusted-publisher'];
const ISSUE_URL = 'https://github.com/npm/cli/issues/9242';
const PNPM_LINE = 'pnpm >= 10.21 would refuse this install under trust-policy=no-downgrade';

// The tier of one packument version doc. A trusted-publisher (OIDC) publish
// stamps _npmUser.trustedPublisher (verified live on npm-script-lens@1.13.1
// and axios@1.14.0); dist.attestations always carries the SLSA provenance
// predicate alongside npm's publish attestation, so its presence is the
// provenance tier without pinning one predicateType string (early attested
// versions predate SLSA v1, and a stricter match here could misread them as
// none and manufacture a downgrade). Absent attestations is none.
function versionTier(doc) {
  if (!doc || typeof doc !== 'object') return 0;
  if (doc._npmUser && doc._npmUser.trustedPublisher) return 2;
  if (doc.dist && doc.dist.attestations) return 1;
  return 0;
}

// Per-version { tier, publishedAt } for one package, from a single packument
// GET, cached 24h (same drift contract as fetchTrust). Iterates versions{},
// never time{}: an unpublished version keeps its time entry but loses its
// version doc, and a gap in the record is not evidence of anything. Null on
// any fetch failure, which callers must treat as unknowable, not as none.
async function tierHistory(name, { cache = true } = {}) {
  const cached = cache ? trustGet(`downgrade~${name}`, 'v1') : null;
  if (cached) return cached;
  let packument;
  try { packument = await fetchPackument(name); } catch { return null; }
  const versions = {};
  for (const [v, doc] of Object.entries(packument.versions || {})) {
    const publishedAt = packument.time && packument.time[v];
    if (!publishedAt) continue;
    versions[v] = { tier: versionTier(doc), publishedAt };
  }
  const history = { versions };
  if (cache) trustSet(`downgrade~${name}`, 'v1', history);
  return history;
}

// One resolved version against its package's history. Only versions published
// BEFORE the resolved one count toward the historical max (a later adoption of
// provenance says nothing about the version you locked), deprecated versions
// still count, and a package whose resolved version is its first publish can
// never downgrade.
function assess(history, version, { now = Date.now(), ignoreAfter = null } = {}) {
  const resolved = history.versions[version];
  if (!resolved) return { status: 'unlisted' };
  const resolvedTime = Date.parse(resolved.publishedAt);
  let best = null;
  let priors = 0;
  for (const [v, e] of Object.entries(history.versions)) {
    if (v === version) continue;
    const t = Date.parse(e.publishedAt);
    if (!(t < resolvedTime)) continue;
    priors++;
    if (!best || e.tier > best.tier || (e.tier === best.tier && t > Date.parse(best.publishedAt))) {
      best = { version: v, tier: e.tier, publishedAt: e.publishedAt };
    }
  }
  if (priors === 0) return { status: 'first' };
  if (best.tier <= resolved.tier) return { status: 'ok' };
  const finding = {
    from: TIERS[best.tier],
    to: TIERS[resolved.tier],
    priorVersion: best.version,
    priorPublishedAt: best.publishedAt,
    resolvedPublishedAt: resolved.publishedAt,
  };
  // trust-policy-ignore-after (minutes): provenance evidence older than the
  // window no longer anchors a refusal, #9242's escape hatch for packages
  // whose maintainer genuinely stopped publishing from CI long ago.
  if (ignoreAfter !== null && ignoreAfter !== undefined
    && now - Date.parse(best.publishedAt) > ignoreAfter * 60000) {
    return { status: 'ignored', ...finding };
  }
  return { status: 'downgrade', ...finding };
}

// Check every locked {name, version} pair. skipNames holds packages resolved
// from git/remote sources (their lockfile version is not a registry version,
// and a same-named registry package would be the wrong history); exclude is
// trust-policy-exclude ('pkg@version'); ignoreAfter is minutes.
async function checkDowngrades(deps, {
  cache = true, exclude = [], ignoreAfter = null, skipNames = new Set(),
  concurrency = 6, now = Date.now(), log = () => {},
} = {}) {
  const excludeSet = new Set(exclude);
  const out = { downgrades: [], checked: 0, skipped: [], excluded: [], ignored: [], unreachable: [], unlisted: [] };
  const queue = [];
  const seen = new Set();
  for (const d of deps) {
    const key = `${d.name}@${d.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (skipNames.has(d.name)) { out.skipped.push(key); continue; }
    if (excludeSet.has(key)) { out.excluded.push(key); continue; }
    queue.push(d);
  }
  const names = [...new Set(queue.map((d) => d.name))];
  const histories = new Map();
  let i = 0;
  let done = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, names.length) }, async () => {
    while (i < names.length) {
      const name = names[i++];
      histories.set(name, await tierHistory(name, { cache }));
      if (++done % 25 === 0) log(`  ${done}/${names.length}`);
    }
  }));
  for (const d of queue) {
    const key = `${d.name}@${d.version}`;
    const history = histories.get(d.name);
    if (!history) { out.unreachable.push(key); continue; }
    const a = assess(history, d.version, { now, ignoreAfter });
    if (a.status === 'unlisted') { out.unlisted.push(key); continue; }
    out.checked++;
    const { status, ...finding } = a;
    if (status === 'downgrade') out.downgrades.push({ name: d.name, version: d.version, ...finding });
    else if (status === 'ignored') out.ignored.push({ name: d.name, version: d.version, ...finding });
  }
  out.downgrades.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}

const detailLine = (d) => (d.to === 'none'
  ? 'resolved version has no attestations'
  : 'resolved version has provenance but was not published by a trusted publisher');

// The `trust` subcommand's text report.
function renderTrustReport(result) {
  const lines = [`npm-script-lens trust: provenance downgrade check (npm/cli#9242, trusted publisher > provenance > none)`];
  const counted = [
    `checked ${result.checked} registry package(s)`,
    result.skipped.length > 0 ? `${result.skipped.length} skipped (git/remote source)` : null,
    result.unlisted.length > 0 ? `${result.unlisted.length} skipped (version not in the registry)` : null,
    result.excluded.length > 0 ? `${result.excluded.length} excluded by trustPolicyExclude` : null,
    result.ignored.length > 0 ? `${result.ignored.length} ignored (prior trust older than trustPolicyIgnoreAfter)` : null,
    result.unreachable.length > 0 ? `${result.unreachable.length} unreachable (never treated as a downgrade)` : null,
  ].filter(Boolean);
  lines.push(counted.join(', '));
  if (result.downgrades.length === 0) {
    lines.push('', '🟢 no trust downgrade: every resolved version matches or exceeds the highest trust its package previously reached');
    return lines.join('\n');
  }
  lines.push('', `TRUST DOWNGRADE (${result.downgrades.length})`);
  for (const d of result.downgrades) {
    lines.push(`  ${d.name}@${d.version}  ${d.from} -> ${d.to}`);
    lines.push(`    highest prior trust: ${d.from} (${d.name}@${d.priorVersion}, published ${d.priorPublishedAt.slice(0, 10)})`);
    lines.push(`    ${detailLine(d)}`);
    lines.push(`    ${PNPM_LINE}`);
  }
  return lines.join('\n');
}

// Downgrades in the gap-finding shape buildSarif already renders (rule
// trust-downgrade, anchored to the package's lockfile line).
function trustSarifFindings(downgrades) {
  return downgrades.map((d) => ({
    id: 'trust-downgrade',
    level: 'error',
    package: d.name,
    version: d.version,
    fix: `trust tier dropped ${d.from} -> ${d.to} (highest prior: ${d.from} at ${d.name}@${d.priorVersion}, published ${d.priorPublishedAt.slice(0, 10)}); `
      + `${PNPM_LINE}. If the drop is intentional, exclude it with trustPolicyExclude: ["${d.name}@${d.version}"]`,
    fingerprint: `trust-downgrade:${d.name}@${d.version}`,
  }));
}

module.exports = { versionTier, tierHistory, assess, checkDowngrades, renderTrustReport, trustSarifFindings, TIERS, ISSUE_URL, PNPM_LINE };
