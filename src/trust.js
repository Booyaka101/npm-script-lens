'use strict';
const { REGISTRY } = require('./registry');
const { trustGet, trustSet } = require('./cache');

const OSV_API = process.env.NPM_SCRIPT_LENS_OSV_API || 'https://api.osv.dev';
const DL_API = process.env.NPM_SCRIPT_LENS_DL_API || 'https://api.npmjs.org';
const TIMEOUT = 10000;

async function getJson(url, init) {
  const res = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT), ...init });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return res.json();
}

// One OSV querybatch call per 500 packages -> Map "name@version" -> [advisory
// ids]. MAL-* ids are confirmed-malicious packages; GHSA vulns are ordinary
// CVEs and deliberately ignored here (this tool judges install scripts, not
// runtime vulnerabilities). Returns an empty map on any failure — the audit
// must not break because an enrichment API is down.
async function osvMalicious(deps) {
  const out = new Map();
  try {
    for (let i = 0; i < deps.length; i += 500) {
      const chunk = deps.slice(i, i + 500);
      const body = JSON.stringify({
        queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: 'npm' }, version: d.version })),
      });
      const res = await getJson(`${OSV_API}/v1/querybatch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
      });
      (res.results || []).forEach((r, j) => {
        const mal = (r.vulns || []).map((v) => v.id).filter((id) => id.startsWith('MAL-'));
        if (mal.length > 0) out.set(`${chunk[j].name}@${chunk[j].version}`, mal);
      });
    }
  } catch { /* enrichment only */ }
  return out;
}

// Publish age, weekly downloads, maintainer count, provenance attestation.
// Cached on disk for 24h (these drift, unlike analysis rows). Null on failure.
async function fetchTrust(name, version) {
  const cached = trustGet(name, version);
  if (cached !== null) return cached;
  try {
    const [packument, dl] = await Promise.all([
      getJson(`${REGISTRY}/${name.replace('/', '%2f')}`, { headers: { accept: 'application/json' } }),
      getJson(`${DL_API}/downloads/point/last-week/${name}`).catch(() => null),
    ]);
    const publishedAt = packument.time && packument.time[version];
    const verDoc = (packument.versions || {})[version] || {};
    const trust = {
      publishedAt: publishedAt || null,
      ageDays: publishedAt ? Math.max(0, Math.floor((Date.now() - Date.parse(publishedAt)) / 86400000)) : null,
      weeklyDownloads: dl && typeof dl.downloads === 'number' ? dl.downloads : null,
      maintainers: Array.isArray(packument.maintainers) ? packument.maintainers.length : null,
      provenance: Boolean(verDoc.dist && verDoc.dist.attestations),
    };
    trustSet(name, version, trust);
    return trust;
  } catch {
    return null;
  }
}

// Human-readable one-liner for reports: "4d old · 12 dl/wk · 1 maintainer" is
// the profile that should give a reviewer pause; age + volume + provenance is
// the profile that says "boring native build".
function trustLabel(t) {
  if (!t) return null;
  const parts = [];
  if (t.ageDays !== null) parts.push(t.ageDays < 30 ? `⚠️ published ${t.ageDays}d ago` : `${(t.ageDays / 365).toFixed(1)}y old`);
  if (t.weeklyDownloads !== null) {
    const dl = t.weeklyDownloads;
    parts.push(`${dl >= 1e6 ? `${(dl / 1e6).toFixed(1)}M` : dl >= 1e3 ? `${(dl / 1e3).toFixed(0)}k` : dl} dl/wk`);
  }
  if (t.maintainers !== null) parts.push(`${t.maintainers} maintainer${t.maintainers === 1 ? '' : 's'}`);
  parts.push(t.provenance ? 'provenance ✓' : 'no provenance');
  return parts.join(' · ');
}

module.exports = { osvMalicious, fetchTrust, trustLabel };
