'use strict';
// Pure logic for the VS Code extension, with no `vscode` import, so it unit-tests
// under plain node. Turns `npm-script-lens audit --json` output into editor
// diagnostics anchored to dependency lines in package.json (where every manager
// declares its deps) and to allowlist entries in pnpm's workspace file.
// extension.js maps these to real vscode objects.
//
// The organising idea: an install script is only a *problem* while it is
// undecided. Once a decision is recorded in the package manager's allowlist the
// finding is settled and must stop nagging. Otherwise the squiggle outlives the
// exact action the tool asked for, and the Problems panel becomes something you
// learn to scroll past. So a diagnostic here is a function of behavioral risk
// AND the recorded decision, never risk alone.

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
const RISK_ICON = { MALICIOUS: '⛔', HIGH: '🔴', MEDIUM: '🟠', LOW: '🟡', SAFE: '🟢', ERROR: '⚪', INFO: 'ℹ️' };

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

// --- recorded decisions ----------------------------------------------------
// Each manager stores the same decision in a different file and shape. These
// readers mirror src/pm-contract.js (the writer), so what the CLI writes is
// exactly what the editor reads back.

const unquoteYaml = (s) => (s.startsWith('"') ? JSON.parse(s) : s);

// pnpm's `allowBuilds:` block in pnpm-workspace.yaml → { name: boolean }.
// Line-scanned rather than YAML-parsed, matching pm-contract.readAllowBuilds and
// keeping this module dependency-free.
function parseAllowBuilds(yamlText) {
  const out = {};
  if (!yamlText) return out;
  const lines = yamlText.split(/\r?\n/);
  const start = lines.findIndex((l) => /^allowBuilds:\s*$/.test(l));
  if (start === -1) return out;
  for (let i = start + 1; i < lines.length; i++) {
    if (!/^\s+\S/.test(lines[i])) break; // dedent → block ended
    const m = lines[i].match(/^\s+("(?:[^"\\]|\\.)*"|[^:]+?):\s*(true|false)\s*$/);
    if (m) out[unquoteYaml(m[1].trim())] = m[2] === 'true';
  }
  return out;
}

// Collapse all four managers' allowlists into one lookup. Keys are whatever
// that manager keys by (`name@version` for npm, bare `name` for the rest), and
// decisionFor() tries both. A package.json that does not parse (mid-edit, or
// genuinely broken) yields no decisions, which degrades to "nothing is decided
// yet" rather than to "everything is approved".
function readDecisions(pkgText, yamlText = '') {
  const out = new Map();
  // A repo that has used more than one package manager keeps more than one
  // allowlist, and they can disagree. Resolve that the safe way: a denial from
  // any manager sticks, and no later `true` can lift it. Last-writer-wins would
  // let a stale bun `trustedDependencies` entry quietly re-enable a script an
  // npm `allowScripts: false` had deliberately blocked.
  const record = (key, allow) => { if (out.get(key) !== false) out.set(key, allow); };
  let pkg = null;
  try { pkg = JSON.parse(pkgText); } catch { /* no decisions readable */ }
  if (pkg && typeof pkg === 'object') {
    // npm: allowScripts { "pkg@1.2.3": true }, may also be keyed by bare name
    for (const [key, v] of Object.entries(pkg.allowScripts || {})) record(key, Boolean(v));
    // yarn Berry: dependenciesMeta.<pkg>.built
    for (const [name, meta] of Object.entries(pkg.dependenciesMeta || {})) {
      if (meta && typeof meta === 'object' && 'built' in meta) record(name, Boolean(meta.built));
    }
    // bun: trustedDependencies is presence-only. It can record a trust but has
    // no way to spell a denial, so an absent name stays undecided, never denied.
    if (Array.isArray(pkg.trustedDependencies)) {
      for (const n of pkg.trustedDependencies) if (typeof n === 'string') record(n, true);
    }
  }
  // pnpm: allowBuilds in pnpm-workspace.yaml
  for (const [name, v] of Object.entries(parseAllowBuilds(yamlText))) record(name, v);
  return out;
}

// true = allowed to run · false = explicitly denied · undefined = never decided.
function decisionFor(decisions, name, version) {
  if (!decisions) return undefined;
  const exact = `${name}@${version}`;
  if (decisions.has(exact)) return decisions.get(exact);
  if (decisions.has(name)) return decisions.get(name);
  return undefined;
}

// --- what the editor should say -------------------------------------------
// One state per package, from behavioral risk crossed with the recorded
// decision:
//   alarm:    known-malicious. An allowlist entry predates the advisory, so a
//             recorded `true` must never suppress this one.
//   decide:   has install-time behavior, nobody has ruled on it. The single
//             actionable state, and the only one that warrants a warning.
//   override: allowed, but the analysis would have held it back. A standing
//             risk acceptance: worth a marker, not a nag.
//   settled:  decided, and the decision agrees with the analysis.
//   blocked:  denied. The script does not run; nothing to warn about.
//   quiet:    no install-time behavior, or nothing worth saying.
function stateFor(r, decisions, recommended) {
  const scripted = (r.rows && r.rows.length > 0) || r.malicious || r.error;
  if (!scripted) return 'quiet';
  if (r.malicious) return 'alarm';
  const allowed = decisionFor(decisions, r.name, r.version);
  if (allowed === false) return 'blocked';
  if (allowed === true) {
    const advised = recommended ? recommended[`${r.name}@${r.version}`] : undefined;
    const heldBack = advised === false || Boolean(r.error) || ['HIGH', 'MEDIUM'].includes(riskOf(r));
    return heldBack ? 'override' : 'settled';
  }
  return riskOf(r) === 'SAFE' && !r.error ? 'quiet' : 'decide';
}

const DIAGNOSTIC_STATES = new Set(['alarm', 'decide', 'override']);
const STATE_SEVERITY = { alarm: 'error', override: 'information' };

function severityFor(r, state) {
  if (STATE_SEVERITY[state]) return STATE_SEVERITY[state];
  // A package that could not be fetched or parsed carries no meaningful risk
  // label. The CLI reports whatever it had, often SAFE. Running that through
  // the risk table would render "we do not know what this does" as a Hint, i.e.
  // a dotted underline nobody sees. It is an open question, so: information.
  if (r.error) return 'information';
  return RISK_SEVERITY[riskOf(r)] || 'information';
}

// gyp command strings carry gyp's own macro syntax: `<(VAR)`, `>(VAR)`,
// `<!(cmd)`. Verbatim in a one-line diagnostic that reads as line noise, so
// render it as the shell-ish `$VAR` a human already parses at a glance.
const GYP_MACRO = /[<>]!?@?\(([^()]*)\)/g;
const readableSignal = (s) => s.replace(GYP_MACRO, '$$$1');

// Flatten a result's signals into the shortest readable set. A package's rows
// routinely repeat the same finding, and gyp in particular emits one signal per
// action invocation, so the same command shows up several times with extra
// trailing args. Keep the shortest spelling of each and drop the rest.
function condenseSignals(rows) {
  const out = [];
  for (const raw of (rows || []).flatMap((row) => row.signals || [])) {
    const s = readableSignal(raw);
    if (out.some((kept) => kept === s || s.startsWith(`${kept} `))) continue;
    for (let i = out.length - 1; i >= 0; i--) if (out[i].startsWith(`${s} `)) out.splice(i, 1);
    out.push(s);
  }
  return out;
}

const SIGNAL_CAP = 6;

function detailFor(r) {
  if (r.malicious) return `flagged malicious by OSV (${(r.advisories || []).join(', ')})`;
  if (r.error) return `could not be analyzed: ${r.error}`;
  const signals = condenseSignals(r.rows);
  if (signals.length === 0) return 'has an install script';
  return signals.slice(0, SIGNAL_CAP).join(' · ')
    + (signals.length > SIGNAL_CAP ? ` · +${signals.length - SIGNAL_CAP} more` : '');
}

// The trailing clause is the part that answers "…and what do I do about it?".
const STATE_NOTE = {
  alarm: 'remove it: an allowlist entry cannot make this safe',
  decide: 'undecided, run “npm-script-lens: Generate allowlist”',
  override: 'allowed in your allowlist, overriding the recommendation',
};

function messageFor(r, state = 'decide', via = null) {
  const risk = riskOf(r);
  const note = STATE_NOTE[state];
  const chain = via && via.length ? ` (via ${via.join(' → ')})` : '';
  return `${RISK_ICON[risk] || ''} ${risk} ${r.name}@${r.version}${chain}: ${detailFor(r)}${note ? ` · ${note}` : ''}`;
}

const toDiagnostic = (r, state, line, via = null) => ({
  line,
  severity: severityFor(r, state),
  risk: riskOf(r),
  state,
  name: r.name,
  version: r.version,
  via: via || null,
  signals: condenseSignals(r.rows),
  message: messageFor(r, state, via),
});

// Where does this package's diagnostic go? Most install-time risk is NOT a line
// in your package.json. It arrives transitively, and the audit reports it under
// a name you never typed. Anchoring only on the package's own line would drop
// those silently, leaving the status bar counting packages with no squiggle
// anywhere to find. So fall back to the direct dependency that pulled it in;
// that is the line you can actually act on.
function anchorFor(text, r) {
  const own = findDepLine(text, r.name);
  if (own >= 0) return { line: own, via: null };
  for (const parent of r.via || []) {
    const line = findDepLine(text, parent);
    if (line >= 0) return { line, via: r.via };
  }
  return null;
}

// Build diagnostics for one package.json document. Only alarm/decide/override
// surface; settled, blocked and clean packages produce nothing. Messages carry
// no `(npm-script-lens)` suffix, because extension.js sets `diagnostic.source`, which
// VS Code already renders in the Problems panel and on hover.
//
// `decisions` defaults to whatever this very document records, so npm, yarn and
// bun work with no wiring at all; pnpm keeps its allowlist in a second file, so
// extension.js passes a merged map built from both.
function diagnosticsForPackageJson(text, results, { recommended, decisions } = {}) {
  const known = decisions || readDecisions(text);
  const out = [];
  for (const r of results) {
    const state = stateFor(r, known, recommended);
    if (!DIAGNOSTIC_STATES.has(state)) continue;
    const at = anchorFor(text, r);
    if (!at) continue;
    out.push(toDiagnostic(r, state, at.line, at.via));
  }
  return out;
}

// pnpm keeps its allowlist outside package.json, so the entries worth a second
// look (a standing override, or something OSV has flagged since it was
// approved) are anchored on their own line in pnpm-workspace.yaml. Undecided
// packages are not here by definition: they have no allowBuilds line to point at.
function diagnosticsForWorkspaceYaml(yamlText, results, { recommended, decisions } = {}) {
  const known = decisions || readDecisions('{}', yamlText);
  const out = [];
  for (const r of results) {
    const state = stateFor(r, known, recommended);
    if (state !== 'override' && state !== 'alarm') continue;
    const line = findYamlKeyLine(yamlText, r.name);
    if (line < 0) continue;
    out.push(toDiagnostic(r, state, line));
  }
  return out;
}

// One-line workspace summary for the status bar / notifications. The headline
// number is how many packages still need a ruling, the only figure the
// reader can act on. Settled scripted deps stay visible as a reassuring count
// rather than disappearing entirely.
function summarize(results, { recommended, decisions } = {}) {
  const counts = { MALICIOUS: 0, HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 };
  let scripted = 0; let undecided = 0; let overrides = 0;
  for (const r of results) {
    const state = stateFor(r, decisions, recommended);
    if (state === 'quiet' && !((r.rows && r.rows.length > 0) || r.malicious || r.error)) continue;
    scripted++;
    const risk = riskOf(r);
    if (counts[risk] !== undefined) counts[risk]++;
    if (state === 'decide') undecided++;
    if (state === 'override') overrides++;
  }
  const bad = counts.MALICIOUS + counts.HIGH;
  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
  const text = counts.MALICIOUS ? `⛔ ${plural(counts.MALICIOUS, 'malicious package')}`
    : undecided ? `🔴 ${plural(undecided, 'install script')} to review`
      : scripted ? `🟢 ${plural(scripted, 'scripted dep')}, none to review${overrides ? ` (${plural(overrides, 'override')})` : ''}`
        : '🟢 install scripts clean';
  return { counts, text, bad, scripted, undecided, overrides };
}

// --- open-time hooks (CLI `hooks --json`, since CLI 1.8.0) ------------------
// The fourth surface: code that runs when the folder is OPENED, not installed.
// The CLI anchors every finding to a real file:line in .vscode/tasks.json or
// .claude/settings.json, exactly the files you'd have open when you
// want to know, so the diagnostic lands on the offending task/hook itself.

const HOOK_FILES = ['.vscode/tasks.json', '.claude/settings.json'];
const isHookFile = (fsPath) => {
  const p = String(fsPath).replace(/\\/g, '/');
  return HOOK_FILES.some((f) => p === f || p.endsWith(`/${f}`));
};

// Parse `hooks --json` stdout, tolerant of leading log lines like parseAudit.
function parseHooks(stdout) {
  const i = stdout.indexOf('{');
  if (i < 0) return null;
  try {
    const j = JSON.parse(stdout.slice(i));
    if (!Array.isArray(j.findings)) return null;
    return { findings: j.findings, partial: Array.isArray(j.partial) ? j.partial : [] };
  } catch { return null; }
}

function hookMessage(f) {
  const what = f.surface === 'vscode-task'
    ? `folderOpen task ${f.label ? `"${f.label}"` : '(unnamed)'} runs when this folder is opened${f.silent ? ', silently (presentation.reveal: silent)' : ''}`
    : f.kind === 'command'
      ? f.auto
        ? `${f.event} hook runs on your next Claude Code session in this folder`
        : `${f.event} hook runs when the agent fires ${f.event} (agent-triggered, not open-time)`
      : `${f.event} ${f.kind} hook (not shell command execution)`;
  const target = f.command || f.target || '';
  const signals = (f.signals || []).map(readableSignal).slice(0, 4).join(' · ');
  return `${RISK_ICON[f.risk] || ''} ${f.risk} ${what}: ${target}`
    + `${signals ? ` · ${signals}` : ''}${f.fromDep ? ` · shipped in ${f.fromDep}` : ''}`;
}

// Diagnostics for one open hooks-surface document. HIGH is the actionable
// state (warning, same bar as an undecided risky install script); everything
// tiered lower (agent-triggered hooks, non-command hook types) is
// information. A file the CLI reported `partial` gets one line-1 note: a
// surface file that will not parse is itself worth a look (warning when the
// raw bytes still mention folderOpen or an auto event).
function diagnosticsForHooksFile(relFile, findings, partials = []) {
  const rel = String(relFile).replace(/\\/g, '/');
  const out = [];
  for (const f of findings) {
    if (f.file !== rel) continue;
    out.push({
      line: Math.max(0, (f.line || 1) - 1),
      severity: f.risk === 'HIGH' ? 'warning' : 'information',
      risk: f.risk,
      message: hookMessage(f),
    });
  }
  for (const p of partials) {
    if (p.file !== rel) continue;
    out.push({
      line: 0,
      severity: p.rawHit ? 'warning' : 'information',
      risk: 'PARTIAL',
      message: `⚠️ npm-script-lens could not fully read this file: ${p.note}`,
    });
  }
  return out;
}

// Parse `audit --json` stdout into { results, recommended } (tolerant of leading
// human log lines that landed on stdout). `recommended` is the CLI's own
// name@version → boolean verdict, which is what makes an override detectable:
// the allowlist says true where the recommendation says false.
function parseAudit(stdout) {
  const i = stdout.indexOf('{');
  if (i < 0) return null;
  try {
    const j = JSON.parse(stdout.slice(i));
    if (!Array.isArray(j.results)) return null;
    return { results: j.results, recommended: j.allowScripts || {} };
  } catch { return null; }
}

module.exports = {
  findDepLine, findYamlKeyLine, diagnosticsForPackageJson, diagnosticsForWorkspaceYaml,
  summarize, parseAudit, readDecisions, decisionFor, parseAllowBuilds, stateFor,
  riskOf, messageFor, condenseSignals, readableSignal, RISK_SEVERITY, RISK_ICON,
  isHookFile, parseHooks, hookMessage, diagnosticsForHooksFile, HOOK_FILES,
};
