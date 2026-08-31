'use strict';
// Governance policy: turn the built-in "auto-approve SAFE/LOW" heuristic into
// something a team can codify and enforce. A `script-lens.policy.json` in the
// project root (or --policy <file>) controls what `allow`/`review`/`sync` will
// pre-approve, plus per-package waivers with a reason and an expiry. With no
// policy file present, behavior is exactly the built-in default.
const fs = require('node:fs');
const path = require('node:path');
const { provenancePresent, provenanceIdentity } = require('./trust');

const RANK = { HIGH: 0, MEDIUM: 1, LOW: 2, SAFE: 3, ERROR: 4 };
const POLICY_FILE = 'script-lens.policy.json';

const DEFAULT_POLICY = {
  // auto-approve a package only when ALL of these hold
  autoApprove: {
    maxRisk: 'LOW', // approve up to this behavioral risk (SAFE|LOW|MEDIUM|HIGH)
    denyCapabilities: [], // never auto-approve if a signal of these kinds is present (exec|net|fs|env|obf|bin|gyp)
    minAgeDays: 0, // require the version to be at least this old (needs trust data)
    requireProvenance: false, // require sigstore provenance to auto-approve (needs trust data)
    // name -> "owner/repo" or "owner/repo:workflow-path", pinning the attested
    // build identity. Presence alone (requireProvenance) is not a trust signal
    expectProvenance: {},
  },
  // name -> { allow, reason, expires? }, an explicit human decision that
  // overrides the heuristic until it expires
  waivers: {},
  // npm/cli#9242's proposed keys, camel-cased like the rest of this file so a
  // config carries over if npm ever ships trust-policy natively. 'off' by
  // default: no existing CI changes colour without opting in.
  trustPolicy: 'off', // 'no-downgrade' | 'off'
  trustPolicyExclude: [], // ['pkg@version'] allowed despite a downgrade
  trustPolicyIgnoreAfter: null, // minutes; prior trust older than this no longer anchors a finding
  // 'fail' exits audit 1 when install-time code fetches or installs another
  // JS runtime (RUNTIME_BOOTSTRAP, the ChainDrop pattern), same gate as
  // --fail-on-runtime-bootstrap but checked into the repo.
  runtimeBootstrapPolicy: 'off', // 'fail' | 'off'
};

// The trust-policy keys ride through only when the file sets them, so a
// policy without them keeps the pre-1.14.0 shape.
const mergeDefaults = (p) => ({
  autoApprove: { ...DEFAULT_POLICY.autoApprove, ...(p.autoApprove || {}) },
  waivers: p.waivers || {},
  ...(p.trustPolicy !== undefined ? { trustPolicy: p.trustPolicy } : {}),
  ...(p.trustPolicyExclude !== undefined ? { trustPolicyExclude: p.trustPolicyExclude } : {}),
  ...(p.trustPolicyIgnoreAfter !== undefined ? { trustPolicyIgnoreAfter: p.trustPolicyIgnoreAfter } : {}),
  ...(p.runtimeBootstrapPolicy !== undefined ? { runtimeBootstrapPolicy: p.runtimeBootstrapPolicy } : {}),
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
  if (parsed.trustPolicy !== undefined && !['no-downgrade', 'off'].includes(parsed.trustPolicy)) {
    throw new Error(`invalid policy (${file}): trustPolicy must be 'no-downgrade' or 'off', got ${JSON.stringify(parsed.trustPolicy)}`);
  }
  if (parsed.runtimeBootstrapPolicy !== undefined && !['fail', 'off'].includes(parsed.runtimeBootstrapPolicy)) {
    throw new Error(`invalid policy (${file}): runtimeBootstrapPolicy must be 'fail' or 'off', got ${JSON.stringify(parsed.runtimeBootstrapPolicy)}`);
  }
  return { policy: mergeDefaults(parsed), source: file };
}

// The trust-downgrade settings with defaults applied, whatever the file set.
const trustPolicyConfig = (policy) => ({
  mode: (policy && policy.trustPolicy) || DEFAULT_POLICY.trustPolicy,
  exclude: (policy && policy.trustPolicyExclude) || [],
  ignoreAfter: policy && policy.trustPolicyIgnoreAfter !== undefined ? policy.trustPolicyIgnoreAfter : null,
});

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
    return { allow: false, reason: `waiver expired ${w.expires}, re-review` };
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
  if (ap.requireProvenance && !provenancePresent(r.trust)) {
    return { allow: false, reason: 'policy requires sigstore provenance' };
  }
  const expected = (ap.expectProvenance || {})[r.name];
  if (expected) {
    const mismatch = expectationMismatch(expected, r.trust);
    if (mismatch) return { allow: false, reason: mismatch };
  }
  return { allow: true, reason: 'meets policy' };
}

// A policy expectation against the attested identity: the denial reason, or
// null on match. Fails closed, since an expectation the tool cannot confirm
// (no trust data, no provenance, unresolved identity) is not a match.
function expectationMismatch(expected, trust) {
  const colon = expected.indexOf(':');
  const expRepo = colon > 0 ? expected.slice(0, colon) : expected;
  const expWorkflow = colon > 0 ? expected.slice(colon + 1) : null;
  if (!trust) return `policy expects provenance from ${expected}, but trust data is unavailable (run with trust enabled)`;
  if (!provenancePresent(trust)) return `policy expects provenance from ${expected}, but this version has no attestation`;
  const id = provenanceIdentity(trust);
  if (!id) return `policy expects provenance from ${expected}, but the attested identity could not be resolved`;
  // the attested repository is host/owner/repo; the expectation is owner/repo
  const actualRepo = id.repository.split('/').slice(-2).join('/');
  if (actualRepo.toLowerCase() !== expRepo.toLowerCase().split('/').slice(-2).join('/')) {
    return `provenance identity mismatch: policy expects ${expected}, attestation names ${id.repository}${id.workflow ? ` ${id.workflow}` : ''}`;
  }
  if (expWorkflow && id.workflow !== expWorkflow) {
    return `provenance identity mismatch: policy expects workflow ${expWorkflow}, attestation names ${id.workflow || '(unknown workflow)'} in ${id.repository}`;
  }
  return null;
}

module.exports = { loadPolicy, evaluate, capabilities, trustPolicyConfig, POLICY_FILE, DEFAULT_POLICY };
