'use strict';
// Pure logic for the VS Code extension — no `vscode` import, so it unit-tests
// under plain node. Turns `npm-script-lens audit --json` output into editor
// diagnostics anchored to dependency lines in package.json (where every
// manager declares its deps), and locates allowlist entries for pnpm's
// workspace file. extension.js maps these to real vscode objects.

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Risk → editor severity string (extension.js maps to vscode.DiagnosticSeverity).
const RISK_SEVERITY = {
  MALICIOUS: 'error',
  HIGH: 'warning',
  MEDIUM: 'warning',
  LOW: 'information',
  SAFE: 'hint',
  ERROR: 'information',
};
const RISK_ICON = { MALICIOUS: '⛔', HIGH: '🔴', MEDIUM: '🟠', LOW: '🟡', SAFE: '🟢', ERROR: '⚪' };

// 0-based line index where a dependency name is declared in package.json text
// (`"name": "range"`), or -1. Matches the first occurrence across any
// dependency section.
function findDepLine(text, name) {
  const lines = text.split(/\r?\n/);
  const re = new RegExp(`^\\s*"${escapeRe(name)}"\\s*:`);
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return i;
  return -1;
}

// 0-based line of a bare key inside a YAML block (e.g. an allowBuilds entry),
// or -1. Handles quoted and unquoted keys.
function findYamlKeyLine(text, name) {
  const lines = text.split(/\r?\n/);
  const re = new RegExp(`^\\s+(?:"${escapeRe(name)}"|${escapeRe(name)})\\s*:`);
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return i;
  return -1;
}

const riskOf = (r) => (r.malicious ? 'MALICIOUS' : (r.risk || 'SAFE'));

function messageFor(r) {
  const risk = riskOf(r);
  const signals = (r.rows || []).flatMap((row) => row.signals || []);
  const detail = r.malicious ? `flagged malicious by OSV (${(r.advisories || []).join(', ')})`
    : r.error ? `could not be analyzed: ${r.error}`
      : signals.length ? signals.slice(0, 6).join(' · ') + (signals.length > 6 ? ' · …' : '')
        : 'has an install script';
  return `${RISK_ICON[risk] || ''} ${risk} — ${r.name}@${r.version}: ${detail}`;
}

// Build diagnostics from audit results for one package.json document text.
// Only packages that actually run install scripts (or are malicious/errored)
// produce a diagnostic; each is anchored to that dependency's line.
function diagnosticsForPackageJson(text, results) {
  const out = [];
  for (const r of results) {
    const scripted = (r.rows && r.rows.length > 0) || r.malicious || r.error;
    if (!scripted) continue;
    const line = findDepLine(text, r.name);
    if (line < 0) continue;
    const risk = riskOf(r);
    out.push({
      line,
      severity: RISK_SEVERITY[risk] || 'information',
      risk,
      name: r.name,
      version: r.version,
      signals: (r.rows || []).flatMap((row) => row.signals || []),
      message: `${messageFor(r)} (npm-script-lens)`,
    });
  }
  return out;
}

// One-line workspace summary for the status bar / notifications.
function summarize(results) {
  const counts = { MALICIOUS: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const r of results) {
    const risk = riskOf(r);
    const scripted = (r.rows && r.rows.length > 0) || r.malicious || r.error;
    if (scripted && counts[risk] !== undefined) counts[risk]++;
  }
  const bad = counts.MALICIOUS + counts.HIGH;
  const text = counts.MALICIOUS ? `⛔ ${counts.MALICIOUS} malicious`
    : bad ? `🔴 ${counts.HIGH} high-risk install script${counts.HIGH === 1 ? '' : 's'}`
      : (counts.MEDIUM + counts.LOW) ? `🟡 ${counts.MEDIUM + counts.LOW} scripted dep${counts.MEDIUM + counts.LOW === 1 ? '' : 's'}`
        : '🟢 install scripts clean';
  return { counts, text, bad };
}

// Parse `audit --json` stdout into the results array (tolerant of leading
// human log lines that landed on stdout).
function parseAuditJson(stdout) {
  const i = stdout.indexOf('{');
  if (i < 0) return null;
  try {
    const j = JSON.parse(stdout.slice(i));
    return Array.isArray(j.results) ? j.results : null;
  } catch { return null; }
}

module.exports = {
  findDepLine, findYamlKeyLine, diagnosticsForPackageJson, summarize, parseAuditJson,
  riskOf, messageFor, RISK_SEVERITY, RISK_ICON,
};
