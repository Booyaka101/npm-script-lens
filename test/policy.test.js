'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadPolicy, evaluate, DEFAULT_POLICY } = require('../src/policy');
const { packageRisk } = require('../src/reporter');

const NOW = Date.UTC(2026, 6, 24);
const R = (over) => ({ name: 'p', version: '1.0.0', rows: [{ risk: 'LOW', signals: ['env: process.env'] }], ...over });
const merged = (over) => ({ autoApprove: { ...DEFAULT_POLICY.autoApprove, ...(over.autoApprove || {}) }, waivers: over.waivers || {} });
const allow = (r, pol) => evaluate(r, pol, packageRisk, NOW).allow;

test('default policy: SAFE/LOW approved; MEDIUM/HIGH/malicious/error denied', () => {
  const p = merged({});
  assert.strictEqual(allow(R({ rows: [{ risk: 'LOW', signals: ['fs: x'] }] }), p), true);
  assert.strictEqual(allow(R({ rows: [{ risk: 'SAFE', signals: [] }] }), p), true);
  assert.strictEqual(allow(R({ rows: [{ risk: 'MEDIUM', signals: ['net: fetch'] }] }), p), false);
  assert.strictEqual(allow(R({ rows: [{ risk: 'HIGH', signals: ['exec: y'] }] }), p), false);
  assert.strictEqual(allow(R({ malicious: true }), p), false);
  assert.strictEqual(allow(R({ error: 'boom', rows: [] }), p), false);
});

test('maxRisk raises the ceiling', () => {
  const p = merged({ autoApprove: { maxRisk: 'MEDIUM' } });
  assert.strictEqual(allow(R({ rows: [{ risk: 'MEDIUM', signals: ['net: fetch'] }] }), p), true);
  assert.strictEqual(allow(R({ rows: [{ risk: 'HIGH', signals: ['exec: y'] }] }), p), false);
});

test('denyCapabilities blocks a banned signal kind even within maxRisk', () => {
  const p = merged({ autoApprove: { denyCapabilities: ['fs'] } });
  assert.strictEqual(allow(R({ rows: [{ risk: 'LOW', signals: ['fs: writeFileSync'] }] }), p), false);
  assert.strictEqual(allow(R({ rows: [{ risk: 'LOW', signals: ['env: process.env'] }] }), p), true);
});

test('minAgeDays and requireProvenance need trust data and fail closed without it', () => {
  const p = merged({ autoApprove: { maxRisk: 'MEDIUM', minAgeDays: 30, requireProvenance: true } });
  assert.strictEqual(allow(R({}), p), false, 'no trust → denied');
  assert.strictEqual(allow(R({ trust: { ageDays: 5, provenance: true } }), p), false, 'too young');
  assert.strictEqual(allow(R({ trust: { ageDays: 400, provenance: false } }), p), false, 'no provenance');
  assert.strictEqual(allow(R({ trust: { ageDays: 400, provenance: true } }), p), true, 'old + provenance');
});

test('waivers override the heuristic and expire', () => {
  assert.strictEqual(allow(R({ rows: [{ risk: 'HIGH', signals: ['exec: y'] }] }),
    merged({ waivers: { p: { allow: true, reason: 'vetted', expires: '2027-01-01' } } })), true);
  assert.strictEqual(allow(R({ rows: [{ risk: 'HIGH', signals: ['exec: y'] }] }),
    merged({ waivers: { p: { allow: true, expires: '2020-01-01' } } })), false, 'expired waiver not applied');
  assert.strictEqual(allow(R({ rows: [{ risk: 'LOW', signals: ['env: x'] }] }),
    merged({ waivers: { p: { allow: false, reason: 'blocked' } } })), false, 'waiver can deny a LOW package');
});

test('loadPolicy: default when absent, parses when present, throws on bad JSON', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-pol-'));
  assert.strictEqual(loadPolicy(dir).source, null, 'no file → built-in default');
  fs.writeFileSync(path.join(dir, 'script-lens.policy.json'), JSON.stringify({ autoApprove: { maxRisk: 'HIGH' } }));
  const { policy, source } = loadPolicy(dir);
  assert.ok(source && source.endsWith('script-lens.policy.json'));
  assert.strictEqual(policy.autoApprove.maxRisk, 'HIGH');
  assert.strictEqual(policy.autoApprove.minAgeDays, 0, 'unspecified fields fall back to defaults');
  fs.writeFileSync(path.join(dir, 'bad.json'), 'not json');
  assert.throws(() => loadPolicy(dir, path.join(dir, 'bad.json')), /invalid policy JSON/);
});
