'use strict';
// Governance policy: turn the built-in "auto-approve SAFE/LOW" heuristic into
// something a team can codify and enforce. A `script-lens.policy.json` in the
// project root (or --policy <file>) controls what `allow`/`review`/`sync` will
// pre-approve, plus per-package waivers with a reason and an expiry. With no
// policy file present, behavior is exactly the built-in default.
const fs = require('node:fs');
const path = require('node:path');

const RANK = { HIGH: 0, MEDIUM: 1, LOW: 2, SAFE: 3, ERROR: 4 };
const POLICY_FILE = 'script-lens.policy.json';

const DEFAULT_POLICY = {
  // auto-approve a package only when ALL of these hold
  autoApprove: {
    maxRisk: 'LOW', // approve up to this behavioral risk (SAFE|LOW|MEDIUM|HIGH)
    denyCapabilities: [], // never auto-approve if a signal of these kinds is present (exec|net|fs|env|obf|bin|gyp)
    minAgeDays: 0, // require the version to be at least this old (needs trust data)
    requireProvenance: false, // require sigstore provenance to auto-approve (needs trust data)
  },
  // name -> { allow, reason, expires? }, an explicit human decision that
  // overrides the heuristic until it expires
  waivers: {},
};

const mergeDefaults = (p) => ({
  autoApprove: { ...DEFAULT_POLICY.autoApprove, ...(p.autoApprove || {}) },
  waivers: p.waivers || {},
});

// Returns { policy, source }. source is null when no file was found (built-in
// default). Throws only on a present-but-invalid file.
function loadPolicy(dir, explicitPath) {
  const file = explicitPath || path.join(dir, POLICY_FILE);
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); }
  catch { return { policy: mergeDefaults({}), source: null }; }
  let parsed;
  try { parsed = JSON.parse(raw); }
  catch (e) { throw new Error(`invalid policy JSON (${file}): ${e.message}`); }
  return { policy: mergeDefaults(parsed), source: file };
}

// the signal KINDS a package's install scripts exercise (exec/net/fs/env/obf/bin)
function capabilities(r) {
  const kinds = new Set();
  for (const row of r.rows || []) {
    for (const s of row.signals || []) {
      const k = s.split(':')[0];
      if (k !== 'ref') kinds.add(k);
    }
  }
  return kinds;
}

// Evaluate one audited package against the policy. packageRisk is injected to
// avoid a circular require; now is a ms timestamp (waiver expiry).
function evaluate(r, policy, packageRisk, now) {
  if (r.malicious) return { allow: false, reason: 'known-malicious (OSV)' };
  if (r.error) return { allow: false, reason: 'could not be analyzed' };
  const w = policy.waivers[r.name];
  if (w) {
    const expired = w.expires && Date.parse(w.expires) < now;
    if (!expired) return { allow: Boolean(w.allow), reason: `waiver${w.reason ? `: ${w.reason}` : ''}` };
    return { allow: false, reason: `waiver expired ${w.expires} — re-review` };
  }
  const ap = policy.autoApprove;
  const risk = packageRisk(r);
  if (RANK[risk] < RANK[ap.maxRisk]) return { allow: false, reason: `risk ${risk} exceeds policy maxRisk ${ap.maxRisk}` };
  const denied = (ap.denyCapabilities || []).find((c) => capabilities(r).has(c));
  if (denied) return { allow: false, reason: `capability '${denied}' denied by policy` };
  if (ap.minAgeDays > 0) {
    const age = r.trust ? r.trust.ageDays : null;
    if (age === null || age === undefined) return { allow: false, reason: `age unknown; policy requires ≥ ${ap.minAgeDays}d (run with trust enabled)` };
    if (age < ap.minAgeDays) return { allow: false, reason: `only ${age}d old; policy requires ≥ ${ap.minAgeDays}d` };
  }
  if (ap.requireProvenance && !(r.trust && r.trust.provenance)) {
    return { allow: false, reason: 'policy requires sigstore provenance' };
  }
  return { allow: true, reason: 'meets policy' };
}

module.exports = { loadPolicy, evaluate, capabilities, POLICY_FILE, DEFAULT_POLICY };
