'use strict';
// Minimal MCP (Model Context Protocol) stdio server — newline-delimited
// JSON-RPC 2.0, no SDK dependency. Lets AI coding agents audit a package's
// install scripts BEFORE adding it as a dependency.
const readline = require('node:readline');
const { fetchPackage, REGISTRY } = require('./registry');
const { analyzePackage } = require('./analyzer');
const { osvMalicious, fetchTrust } = require('./trust');
const { packageRisk, buildAllowScripts } = require('./reporter');
const VERSION = require('../package.json').version;

const TOOLS = [
  {
    name: 'audit_package',
    description: 'Statically audit one npm package\'s install-time lifecycle scripts (preinstall/install/postinstall) ' +
      'for behavioral risks: process spawning, network access, filesystem writes, obfuscation. Also checks OSV for ' +
      'known-malicious advisories and reports publisher trust signals. Use before adding a dependency.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'npm package name' },
        version: { type: 'string', description: 'exact version; omit for the latest release' },
      },
      required: ['name'],
    },
  },
  {
    name: 'audit_lockfile',
    description: 'Audit every package in a lockfile (package-lock.json, npm-shrinkwrap.json, yarn.lock, ' +
      'pnpm-lock.yaml, bun.lock) and return per-package risks plus a suggested npm v12 allowScripts block.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'project directory or lockfile path' },
      },
      required: ['path'],
    },
  },
  {
    name: 'classify_allowscripts',
    description: 'Audit a lockfile and split every package with install-time scripts into a ready-to-commit ' +
      'npm v12 allowScripts decision: SAFE/LOW-risk packages are auto-approved (allowScripts: true), while ' +
      'MEDIUM/HIGH-risk, known-malicious, and un-fetchable packages are held in _review for a human. Use to ' +
      'generate the allowScripts block for a project non-interactively.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'project directory or lockfile path' },
      },
      required: ['path'],
    },
  },
];

async function auditPackageTool({ name, version }) {
  if (!version) {
    const res = await fetch(`${REGISTRY}/${name.replace('/', '%2f')}/latest`, {
      signal: AbortSignal.timeout(30000), headers: { accept: 'application/json' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} resolving latest version of ${name}`);
    version = (await res.json()).version;
  }
  const pkg = await fetchPackage(name, version);
  const rows = analyzePackage(pkg);
  // 'ref:' breadcrumbs are internal to --deep resolution; never expose them
  for (const row of rows) row.signals = row.signals.filter((s) => !s.startsWith('ref: '));
  const mal = await osvMalicious([{ name, version }]);
  const advisories = mal.get(`${name}@${version}`) || [];
  const trust = await fetchTrust(name, version);
  return {
    name,
    version,
    risk: packageRisk({ rows }),
    malicious: advisories.length > 0,
    advisories,
    scripts: rows,
    trust,
    verdict: advisories.length > 0
      ? 'DO NOT INSTALL: flagged as malicious by OSV'
      : rows.length === 0
        ? 'no install-time scripts — safe to install without allowScripts approval'
        : `install scripts present, worst risk ${packageRisk({ rows })} — review signals before approving`,
  };
}

async function auditLockfileTool({ path: target }) {
  const { runAudit } = require('./cli');
  const results = await runAudit(target, { log: () => {} });
  return {
    audited: results.length,
    packages: results
      .filter((r) => r.rows.length > 0 || r.error || r.malicious)
      .map((r) => ({
        name: r.name,
        version: r.version,
        risk: packageRisk(r),
        malicious: Boolean(r.malicious),
        advisories: r.advisories || [],
        via: r.via || [],
        signals: r.rows.flatMap((row) => row.signals),
        error: r.error,
      })),
    allowScripts: buildAllowScripts(results).allowScripts,
  };
}

// Non-interactive allowScripts split for agents: same auto-approve policy as
// the `allow` CLI (SAFE/LOW → true; MEDIUM/HIGH/malicious/error → _review).
async function classifyAllowScriptsTool({ path: target }) {
  const { runAudit, classifyForAllow } = require('./cli');
  const results = await runAudit(target, { log: () => {} });
  const { allowScripts, _review } = classifyForAllow(results);
  return {
    allowScripts,
    _review,
    summary: `${Object.keys(allowScripts).length} package(s) auto-approved (SAFE/LOW), ` +
      `${_review.length} need manual review (MEDIUM/HIGH/malicious/un-fetchable)`,
  };
}

/**
 * Handshake state, dual-era.
 *
 * 2025-11-25 clients send an `initialize` request once. 2026-07-28 removes that
 * handshake entirely and carries protocolVersion / clientInfo / capabilities in
 * `params._meta` on *every* request instead. Until every client we care about has
 * moved, both have to work — the spec date is a rollout window, not a kill switch.
 */
const peer = { protocolVersion: null, clientInfo: null, capabilities: null };

/** Absorb 2026-07-28 per-request handshake data. Older clients simply omit it. */
function absorbMeta(msg) {
  const meta = msg && msg.params && msg.params._meta;
  if (!meta || typeof meta !== 'object') return;
  if (meta.protocolVersion) peer.protocolVersion = meta.protocolVersion;
  if (meta.clientInfo) peer.clientInfo = meta.clientInfo;
  if (meta.capabilities) peer.capabilities = meta.capabilities;
}

function serve() {
  const send = (msg) => process.stdout.write(`${JSON.stringify(msg)}\n`);
  const rl = readline.createInterface({ input: process.stdin });
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    absorbMeta(msg); // 2026-07-28: handshake rides along on every request
    if (msg.id === undefined) return; // notification — nothing to answer
    try {
      // Deliberate dual-era support: 2026-07-28 drops this handshake, but removing
      // it would break every 2025-11-25 client still in the field. absorbMeta()
      // above implements the new path; this stays until the old one is retired.
      // mcp-vet-disable-next-line INITIALIZE_HANDLER
      if (msg.method === 'initialize') {
        send({
          jsonrpc: '2.0',
          id: msg.id,
          result: {
            protocolVersion: (msg.params && msg.params.protocolVersion) || peer.protocolVersion || '2024-11-05',
            capabilities: { tools: {} },
            serverInfo: { name: 'npm-script-lens', version: VERSION },
          },
        });
      } else if (msg.method === 'tools/list') {
        send({ jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } });
      } else if (msg.method === 'tools/call') {
        const { name, arguments: args } = msg.params || {};
        let payload;
        try {
          payload = name === 'audit_package' ? await auditPackageTool(args || {})
            : name === 'audit_lockfile' ? await auditLockfileTool(args || {})
              : name === 'classify_allowscripts' ? await classifyAllowScriptsTool(args || {})
                : null;
          if (payload === null) throw new Error(`unknown tool: ${name}`);
          send({
            jsonrpc: '2.0',
            id: msg.id,
            result: { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] },
          });
        } catch (err) {
          send({
            jsonrpc: '2.0',
            id: msg.id,
            result: { content: [{ type: 'text', text: `error: ${err.message}` }], isError: true },
          });
        }
      } else if (msg.method === 'ping') {
        send({ jsonrpc: '2.0', id: msg.id, result: {} });
      } else {
        send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `method not found: ${msg.method}` } });
      }
    } catch (err) {
      send({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: String(err.message || err) } });
    }
  });
}

module.exports = { serve };
