'use strict';
const { REGISTRY, fetchPackument } = require('./registry');
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
// runtime vulnerabilities). Returns an empty map on any failure, the audit
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

// Any repository reference (packument repository.url, attestation
// workflow.repository) to "host/owner/repo". Anything past owner/repo is
// dropped, since one repo publishing many packages is normal.
function normalizeRepo(repo) {
  let s = typeof repo === 'string' ? repo : repo && typeof repo.url === 'string' ? repo.url : null;
  if (!s) return null;
  s = s.trim().replace(/^git\+/, '').replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/^git@/, '');
  s = s.replace(/^[^@/]*@/, '').replace(':', '/').replace(/#.*$/, '');
  const parts = s.split('/').filter(Boolean);
  if (parts.length < 3) return null;
  const [host, owner, repoName] = parts;
  return `${host}/${owner}/${repoName.replace(/\.git$/, '')}`;
}

const SLSA_PREDICATE = 'https://slsa.dev/provenance/v1';

// What the registry's attestation for name@version claims: repository,
// workflow, ref, commit and builder from the SLSA predicate. These are claims
// read over TLS, the same trust boundary as the tarball; no signature is
// verified. 404 (no attestations) is { present: false }, a shape this build
// does not understand is { present: true } with no identity, and an
// unreachable endpoint is null. An unexpected shape never changes a verdict.
async function resolveProvenance(name, version) {
  let doc;
  try {
    doc = await getJson(`${REGISTRY}/-/npm/v1/attestations/${name.replace('/', '%2f')}@${encodeURIComponent(version)}`);
  } catch (err) {
    return /HTTP 404 /.test(String(err.message)) ? { present: false } : null;
  }
  const out = { present: true };
  try {
    const slsa = (doc.attestations || []).find((a) => a.predicateType === SLSA_PREDICATE);
    if (!slsa) return out;
    const payload = JSON.parse(Buffer.from(slsa.bundle.dsseEnvelope.payload, 'base64').toString('utf8'));
    const p = payload.predicate || {};
    const bd = p.buildDefinition || {};
    const wf = (bd.externalParameters || {}).workflow || {};
    const dep0 = Array.isArray(bd.resolvedDependencies) ? bd.resolvedDependencies[0] : null;
    const repository = normalizeRepo(wf.repository);
    if (!repository) return out;
    out.repository = repository;
    out.workflow = typeof wf.path === 'string' ? wf.path : null;
    out.ref = typeof wf.ref === 'string' ? wf.ref : null;
    out.commit = dep0 && dep0.digest && typeof dep0.digest.gitCommit === 'string' ? dep0.digest.gitCommit : null;
    out.builder = p.runDetails && p.runDetails.builder && typeof p.runDetails.builder.id === 'string'
      ? p.runDetails.builder.id : null;
    return out;
  } catch {
    return out; // present, identity unresolvable: exactly the 1.10.0 boolean
  }
}

// Publish age, weekly downloads, maintainer count, provenance attestation and
// its build identity. Cached on disk for 24h (these drift, unlike analysis
// rows). Null on failure.
async function fetchTrust(name, version) {
  const cached = trustGet(name, version);
  // a pre-1.11.0 cache entry carries `provenance: true` with no identity:
  // treat it as a miss so the upgrade resolves identities without a 24h wait
  if (cached !== null && cached.provenance !== true) return cached;
  try {
    const [packument, dl] = await Promise.all([
      fetchPackument(name),
      getJson(`${DL_API}/downloads/point/last-week/${name}`).catch(() => null),
    ]);
    const publishedAt = packument.time && packument.time[version];
    const verDoc = (packument.versions || {})[version] || {};
    const present = Boolean(verDoc.dist && verDoc.dist.attestations);
    let provenance = { present };
    if (present) {
      const resolved = await resolveProvenance(name, version);
      if (resolved && resolved.present) provenance = resolved;
    }
    const trust = {
      publishedAt: publishedAt || null,
      ageDays: publishedAt ? Math.max(0, Math.floor((Date.now() - Date.parse(publishedAt)) / 86400000)) : null,
      weeklyDownloads: dl && typeof dl.downloads === 'number' ? dl.downloads : null,
      maintainers: Array.isArray(packument.maintainers) ? packument.maintainers.length : null,
      provenance,
      provenanceOk: present,
      declaredRepository: normalizeRepo(verDoc.repository || packument.repository),
    };
    trustSet(name, version, trust);
    return trust;
  } catch {
    return null;
  }
}

// Handles both the object shape and the pre-1.11.0 boolean still in caches.
function provenancePresent(t) {
  if (!t) return false;
  if (t.provenanceOk !== undefined) return Boolean(t.provenanceOk);
  const p = t.provenance;
  return p && typeof p === 'object' ? Boolean(p.present) : Boolean(p);
}

const provenanceIdentity = (t) => {
  const p = t && t.provenance;
  return p && typeof p === 'object' && p.present && p.repository ? p : null;
};

// Attested repository vs the packument's declared one. Informational only:
// npm requires the two to match at publish time, so a live mismatch is a
// later rename or transfer, not an attack signal.
function repoDrift(t) {
  const id = provenanceIdentity(t);
  if (!id || !t.declaredRepository) return null;
  if (id.repository.toLowerCase() === t.declaredRepository.toLowerCase()) return null;
  return { declared: t.declaredRepository, attested: id.repository };
}

function driftNote(t) {
  const d = repoDrift(t);
  return d ? `provenance repo drift: package declares ${d.declared}, attestation names ${d.attested}, likely a repo rename or transfer` : null;
}

// How the build identity moved between two versions: repository, workflow or
// ref, or provenance appearing/disappearing. An unresolved side is not
// comparable, so an enrichment failure cannot manufacture a finding. Commit
// is excluded, every release has a new one.
function identityChanges(base, next) {
  // legacy boolean shapes (a stale 24h cache entry) are not comparable
  if (!base || !next || typeof base !== 'object' || typeof next !== 'object') return [];
  if (base.present !== next.present) {
    return [{ field: 'provenance', from: base.present ? 'present' : 'absent', to: next.present ? 'present' : 'absent' }];
  }
  if (!base.repository || !next.repository) return [];
  const changes = [];
  if (base.repository.toLowerCase() !== next.repository.toLowerCase()) {
    changes.push({ field: 'repository', from: base.repository, to: next.repository });
  }
  if (base.workflow !== next.workflow) changes.push({ field: 'workflow', from: base.workflow, to: next.workflow });
  if (base.ref !== next.ref) changes.push({ field: 'ref', from: base.ref, to: next.ref });
  return changes;
}

// Where the build claims it came from, when the attestation resolved.
function provenanceLabel(t) {
  if (!provenancePresent(t)) return 'no provenance';
  const id = provenanceIdentity(t);
  if (!id) return 'provenance ✓ (identity unavailable)';
  const parts = ['provenance ✓', id.repository];
  if (id.workflow) parts.push(id.ref ? `${id.workflow}@${id.ref}` : id.workflow);
  if (id.commit) parts.push(id.commit.slice(0, 7));
  return parts.join(' ');
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
  parts.push(provenanceLabel(t));
  return parts.join(' · ');
}

module.exports = {
  osvMalicious, fetchTrust, trustLabel, resolveProvenance, normalizeRepo,
  provenancePresent, provenanceIdentity, repoDrift, driftNote, identityChanges,
};
