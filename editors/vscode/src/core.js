'use strict';
const nodePath = require('node:path');
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

// --- recording ONE decision, from the editor -------------------------------
// Reading a warning you cannot act on is the whole complaint about tools like
// this. `allow --write` decides the entire project by policy, which is the
// wrong granularity when you are looking at one squiggle and know the answer
// for that one package. These build the exact new file text, so the editor can
// apply it as a normal undoable edit rather than shelling out and reloading.
//
// The four formats mirror src/pm-contract.js, the CLI's writer. Same bytes,
// whichever end you drive it from.

// Lockfile precedence, matching lockfiles.js LOCKFILE_NAMES order: first one
// present in the project directory wins.
const LOCKFILES = [
  ['package-lock.json', 'npm'], ['npm-shrinkwrap.json', 'npm'], ['yarn.lock', 'yarn'],
  ['pnpm-lock.yaml', 'pnpm'], ['bun.lock', 'bun'], ['bun.lockb', 'bun'],
];
// present: array of file basenames in the project dir. npm is the fallback,
// same as the CLI's, because allowScripts is the format npm 12 itself reads.
const managerFrom = (present = []) => {
  const hit = LOCKFILES.find(([file]) => present.includes(file));
  return hit ? hit[1] : 'npm';
};

const MANAGER_LABEL = { npm: 'npm', pnpm: 'pnpm', yarn: 'yarn (Berry)', bun: 'bun' };
// Which file each manager keeps its allowlist in. pnpm is the only one that
// answers something other than package.json.
const allowlistFileFor = (manager) => (manager === 'pnpm' ? 'pnpm-workspace.yaml' : 'package.json');

const sortedMap = (obj) => Object.fromEntries(Object.entries(obj).sort(([a], [b]) => a.localeCompare(b)));
const indentOf = (raw) => { const m = raw.match(/^([ \t]+)"/m); return m ? m[1] : 2; };
const stringifyPkg = (pkg, raw) => JSON.stringify(pkg, null, indentOf(raw)) + (raw.endsWith('\n') ? '\n' : '');

// pnpm: splice the allowBuilds block, leaving every other byte of the file
// alone. Ported from pm-contract.writeAllowBuilds so a decision recorded here
// is byte-identical to one recorded by the CLI.
const yamlKeyOf = (k) => (/^[A-Za-z0-9._-]+$/.test(k) ? k : JSON.stringify(k));
function writeAllowBuilds(yamlText, entries) {
  const merged = sortedMap({ ...parseAllowBuilds(yamlText), ...entries });
  const block = ['allowBuilds:', ...Object.keys(merged).map((k) => `  ${yamlKeyOf(k)}: ${merged[k]}`)];
  if (!yamlText) return `${block.join('\n')}\n`;
  const lines = yamlText.split(/\r?\n/);
  const start = lines.findIndex((l) => /^allowBuilds:\s*$/.test(l));
  if (start === -1) {
    const sep = lines[lines.length - 1] === '' ? '' : '\n';
    return `${yamlText}${sep}${block.join('\n')}\n`;
  }
  let end = start + 1;
  while (end < lines.length && /^\s+\S/.test(lines[end])) end++;
  lines.splice(start, end - start, ...block);
  return lines.join('\n');
}

// bun's trustedDependencies is presence-only: it can spell a trust but not a
// denial, and merely DEFINING the field replaces bun's built-in trusted list.
// Both facts have to reach the user, so they come back as a note rather than
// being silently absorbed.
const BUN_DENY_NOTE = 'bun has no way to record a denial, so this only removes the trust entry. '
  + 'Nothing runs the script now, but nothing states the decision either.';
const BUN_REPLACE_NOTE = 'Defining trustedDependencies replaces bun\'s built-in trusted list, '
  + 'so packages bun trusted by default (esbuild, sharp, …) stop running scripts unless they are listed here too.';

// Compute the file change that records one decision.
// → { file, text, note } · file is relative to the project dir, text is its
// complete new contents. Throws only if package.json cannot be parsed, which
// the caller is better placed to explain than a half-written allowlist is.
function decisionEdit({ manager, name, version, allow, pkgText = '{}', yamlText = '' }) {
  if (manager === 'pnpm') {
    return { file: 'pnpm-workspace.yaml', text: writeAllowBuilds(yamlText, { [name]: allow }), note: null };
  }
  const pkg = JSON.parse(pkgText);
  let note = null;
  if (manager === 'yarn') {
    const meta = { ...(pkg.dependenciesMeta || {}) };
    meta[name] = { ...(meta[name] || {}), built: allow };
    pkg.dependenciesMeta = sortedMap(meta);
    note = 'yarn only treats dependenciesMeta as an allowlist when .yarnrc.yml sets enableScripts: false.';
  } else if (manager === 'bun') {
    const had = Array.isArray(pkg.trustedDependencies) ? pkg.trustedDependencies : [];
    const set = new Set(had);
    if (allow) set.add(name); else set.delete(name);
    pkg.trustedDependencies = [...set].sort();
    note = allow ? (had.length ? null : BUN_REPLACE_NOTE) : BUN_DENY_NOTE;
  } else {
    pkg.allowScripts = sortedMap({ ...(pkg.allowScripts || {}), [`${name}@${version}`]: allow });
  }
  return { file: 'package.json', text: stringifyPkg(pkg, pkgText), note };
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

// --- saying it in English --------------------------------------------------
// The analyzer emits signals as `kind: detail`, and a bare list of them reads as
// line noise to anyone who is not already the author: "env: process.env · exec:
// child_process.execFileSync() · fs: fs2.chmodSync" tells a reader nothing about
// whether to worry. Risk is scored from the KINDS (analyzer.js score()), so the
// kinds are also the honest summary. Say what each kind lets the script do, keep
// a couple of raw signals as the evidence, and drop the rest.
//
// Listed in the order score() checks them, so the first capability present is
// literally the one that set the risk level. That is what `why` explains.
const CAPABILITY_ORDER = ['exec', 'obf', 'gyp', 'net', 'fs', 'env', 'ref'];
const CAPABILITY = {
  exec: { does: 'runs other programs', why: 'anything your own shell could do, it can do' },
  obf: { does: 'assembles code while it runs', why: 'a script that decodes or builds itself is hiding what it does' },
  gyp: { does: 'compiles native code', why: 'its build file runs shell commands before a line of C is compiled' },
  net: { does: 'uses the network', why: 'it can fetch what it runs, or send out what it reads' },
  fs: { does: 'reads and writes files', why: 'it reaches your disk beyond its own folder' },
  env: { does: 'reads your environment variables', why: 'tokens, keys and CI secrets live there' },
  ref: { does: 'loads other packages', why: 'what it does is really what they do' },
};

// Group a result's signals by capability, keeping the raw signals as evidence.
// → [{ kind, does, why, examples: [...] }], strongest capability first.
function capabilitiesOf(rows) {
  const byKind = new Map();
  for (const signal of condenseSignals(rows)) {
    const i = signal.indexOf(':');
    const kind = i < 0 ? '' : signal.slice(0, i);
    if (!CAPABILITY[kind]) continue;
    if (!byKind.has(kind)) byKind.set(kind, []);
    const detail = signal.slice(i + 1).trim();
    if (detail && !byKind.get(kind).includes(detail)) byKind.get(kind).push(detail);
  }
  return CAPABILITY_ORDER.filter((k) => byKind.has(k))
    .map((kind) => ({ kind, ...CAPABILITY[kind], examples: byKind.get(kind) }));
}

// "runs other programs, uses the network and reads your environment variables"
function joinList(parts) {
  if (parts.length <= 1) return parts.join('');
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

const CAP_CAP = 3;
const capabilitySentence = (caps) => (caps.length === 0 ? '' : joinList(caps.slice(0, CAP_CAP).map((c) => c.does)));

const originOf = (via) => (via && via.length ? ` (pulled in by ${via.join(' → ')})` : '');

// The one-line version, for the squiggle and the Problems panel: who, what it
// does in plain words, and what is outstanding. No emoji and no risk word —
// VS Code already draws the severity, and "HIGH" on its own says nothing the
// capability sentence does not say better.
const STATE_TAIL = {
  decide: 'You have not approved or blocked it yet.',
  override: 'Your allowlist approves it; the analysis would have held it back.',
};

function messageFor(r, state = 'decide', via = null) {
  const id = `${r.name}@${r.version}${originOf(via)}`;
  if (r.malicious) {
    const ids = (r.advisories || []).join(', ');
    return `${id} is reported malicious${ids ? ` (${ids})` : ''}. Remove it. Allowlisting cannot make it safe.`;
  }
  const tail = STATE_TAIL[state] ? ` ${STATE_TAIL[state]}` : '';
  if (r.error) return `${id} runs code when you install it, and it could not be analyzed (${r.error}), so what that code does is unknown.${tail}`;
  const caps = capabilitySentence(capabilitiesOf(r.rows));
  return `${id} runs code when you install it${caps ? `: ${caps}` : ''}.${tail}`;
}

// The long version, for the hover. Markdown, but no `vscode` types and no
// command links, so it stays unit-testable; extension.js appends the buttons.
const STATE_HEADLINE = {
  alarm: 'reported malicious',
  decide: 'waiting on your decision',
  override: 'approved against the recommendation',
};

const STATE_ADVICE = {
  alarm: 'Remove it, and treat anything this machine had access to as exposed. An allowlist entry cannot undo an install that already ran.',
  decide: 'Approve and it installs as normal, block and the script never runs. Either way the decision goes into your package manager\'s own allowlist, so CI and your team get the same answer.',
  override: 'A deliberate exception is fine. Worth re-reading when this package changes version, because the approval carries over and the code doesn\'t.',
};

// Where the editor injects its Approve / Block links. Position here is not
// cosmetic. A hover caps its height and the diagnostic messages stack above
// this block, which in a real editor left about six lines to work with;
// screenshots of the finished hover showed the buttons cut off both when they
// sat at the very bottom and when they sat below the capability list. So they
// go directly under the opening sentence: by then the squiggle has already
// said what the script does in words, and the bullets below are the evidence
// for a reader who wants it. Summary, decide, then detail.
// extension.js always substitutes this, so it never reaches a renderer.
const ACTIONS_SLOT = '<!--npm-script-lens:actions-->';

// Install commands run long (`npm install --loglevel=error --prefer-offline …`).
// Cut on the last word boundary before the limit, so the tail reads as a
// truncated command rather than as a corrupted one.
const CODE_CAP = 64;
function code(s) {
  if (s.length <= CODE_CAP) return `\`${s}\``;
  const cut = s.lastIndexOf(' ', CODE_CAP);
  return `\`${s.slice(0, cut > CODE_CAP / 2 ? cut : CODE_CAP)} …\``;
}
const EVIDENCE_CAP = 2;

// The line every reader looks for first and the extension used to drop on the
// floor: which lifecycle script, and the command it runs. `rows` has carried
// both since the first CLI release.
function scriptLines(rows) {
  const seen = new Set();
  const out = [];
  for (const row of rows || []) {
    if (!row || !row.script) continue;
    const key = `${row.script} ${row.command || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(`- \`${row.script}\` → ${row.command ? code(readableSignal(row.command)) : '_(no command recorded)_'}`);
  }
  return out;
}

// What `--trust` fetched about the publisher. Absent unless the audit ran with
// it, so every field is optional and an empty answer means "not checked",
// never "checked and clean".
const FRESH_DAYS = 7;
function trustLines(t) {
  if (!t) return [];
  const facts = [];
  if (typeof t.weeklyDownloads === 'number') facts.push(`${t.weeklyDownloads.toLocaleString('en-US')} downloads a week`);
  if (typeof t.ageDays === 'number') {
    facts.push(t.ageDays === 0 ? 'published **today**'
      : t.ageDays <= FRESH_DAYS ? `published **${t.ageDays} day${t.ageDays === 1 ? '' : 's'} ago**`
        : `published ${t.ageDays} days ago`);
  }
  if (typeof t.maintainers === 'number') facts.push(`${t.maintainers} maintainer${t.maintainers === 1 ? '' : 's'}`);
  const p = t.provenance;
  const present = t.provenanceOk !== undefined ? Boolean(t.provenanceOk) : Boolean(p && (p === true || p.present));
  facts.push(present
    ? (p && p.repository ? `built from \`${p.repository}\`${p.workflow ? ` by \`${p.workflow}\`` : ''}` : 'has a provenance attestation')
    : 'no provenance attestation, so nothing ties this tarball to any source repo');
  const out = ['', `**Who published it** — ${facts.join(' · ')}.`];
  // The one combination worth spelling out: brand-new code that runs on install
  // is the exact shape of a hijacked release, and the fix is just to wait.
  if (typeof t.ageDays === 'number' && t.ageDays <= FRESH_DAYS) {
    out.push('', `This version is ${t.ageDays === 0 ? 'less than a day' : `${t.ageDays} day${t.ageDays === 1 ? '' : 's'}`} old. Compromised releases get caught in hours to days, so waiting out a cooldown before approving a fresh version costs you nothing and skips most of the risk.`);
  }
  return out;
}

// Budget matters here. A VS Code hover caps its height and scrolls, and the
// diagnostic messages stack ABOVE this block, so a leisurely explanation gets
// its tail cut off in practice. A screenshot of a real hover showed everything
// past the first section clipped, buttons included. So: one intro line that
// folds in the origin and the command, the evidence, then the actions, and
// only then the reasoning nobody has to read to decide.
function explainFor(r, state = 'decide', via = null) {
  const origin = via && via.length ? `\`${via.join('` → `')}\` pulls it in. ` : '';
  const out = [`**${r.name}@${r.version}** — ${STATE_HEADLINE[state] || 'install script'}`];

  if (r.malicious) {
    const ids = (r.advisories || []).join(', ');
    out.push('', `${origin}A malware advisory covers this exact version${ids ? ` (${ids})` : ''}.`);
  } else if (r.error) {
    out.push('', `${origin}**Could not be analyzed** — ${r.error}. That is not a clean bill of health, it means the tool has nothing to show you.`);
  } else {
    const scripts = scriptLines(r.rows);
    // One script is a sentence; several earn a list.
    out.push('', scripts.length === 1
      ? `${origin}Installing it runs ${scripts[0].replace(/^- /, '')} on this machine.`
      : `${origin}Installing it runs code on this machine.`);
    if (scripts.length > 1) out.push('', ...scripts);

    out.push('', ACTIONS_SLOT);

    const caps = capabilitiesOf(r.rows);
    if (caps.length === 0) out.push('', 'The analyzer read that script and found no behavior worth reporting in it.');
    else {
      out.push('');
      for (const c of caps) {
        const evidence = c.examples.slice(0, EVIDENCE_CAP).map(code).join(', ');
        const more = c.examples.length - EVIDENCE_CAP;
        out.push(`- ${c.does}${evidence ? ` — ${evidence}${more > 0 ? `, +${more} more` : ''}` : ''}`);
      }
      out.push('', `Rated **${riskOf(r)}**: it ${caps[0].does}, and ${caps[0].why}.`);
    }
  }

  if (r.malicious || r.error) out.push('', ACTIONS_SLOT);
  out.push(...trustLines(r.trust));
  if (STATE_ADVICE[state]) out.push('', `**What to do** — ${STATE_ADVICE[state]}`);
  return out.join('\n');
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
  explain: explainFor(r, state, via),
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
  const text = counts.MALICIOUS ? `${plural(counts.MALICIOUS, 'malicious package')}`
    : undecided ? `${plural(undecided, 'install script')} to review`
      : scripted ? `${plural(scripted, 'install script')}, all decided${overrides ? ` (${plural(overrides, 'override')})` : ''}`
        : 'no install scripts';
  return { counts, text, bad, scripted, undecided, overrides };
}

// --- the panel -------------------------------------------------------------
// Squiggles only cover packages with a line to anchor to, and only ever the
// files you happen to have open. The panel is the other half: every dependency
// in the project that runs code at install time, whether or not it is written
// down anywhere you can see, grouped by what is left to do about it.

const TREE_ORDER = ['alarm', 'decide', 'override', 'clean', 'settled', 'blocked'];
const TREE_LABEL = {
  alarm: 'Malicious',
  decide: 'Needs a decision',
  override: 'Approved against advice',
  clean: 'Analyzed clean, still undecided',
  settled: 'Approved',
  blocked: 'Blocked',
};
// Worst first inside a group, then alphabetically, so the list is stable across
// re-audits and the thing you should look at first is at the top.
const RISK_ORDER = { MALICIOUS: 0, HIGH: 1, MEDIUM: 2, ERROR: 3, LOW: 4, SAFE: 5 };

const isScripted = (r) => (r.rows && r.rows.length > 0) || Boolean(r.malicious) || Boolean(r.error);

// → [{ id, label, items: [{ name, version, key, state, risk, via, detail, explain }] }]
// Only groups with something in them, in TREE_ORDER.
function treeFor(results, { recommended, decisions } = {}) {
  const groups = new Map();
  for (const r of results) {
    if (!isScripted(r)) continue;
    const settled = stateFor(r, decisions, recommended);
    const state = settled === 'quiet' ? 'clean' : settled;
    if (!groups.has(state)) groups.set(state, []);
    groups.get(state).push({
      name: r.name,
      version: r.version,
      key: `${r.name}@${r.version}`,
      state,
      risk: riskOf(r),
      via: r.via || null,
      detail: r.error ? `could not be analyzed: ${r.error}`
        : capabilitySentence(capabilitiesOf(r.rows)) || 'runs an install script',
      explain: explainFor(r, state === 'clean' ? 'decide' : state, (r.via && r.via.length ? r.via : null)),
    });
  }
  return TREE_ORDER.filter((id) => groups.has(id)).map((id) => ({
    id,
    label: TREE_LABEL[id],
    items: groups.get(id).sort((a, b) => (RISK_ORDER[a.risk] - RISK_ORDER[b.risk]) || a.key.localeCompare(b.key)),
  }));
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

// When does this thing run, in the reader's terms? The distinction that matters
// is open-time (it already ran, or runs next time) versus agent-triggered.
function hookTrigger(f) {
  if (f.surface === 'vscode-task') {
    return `Opening this folder runs the task ${f.label ? `“${f.label}”` : '(unnamed)'}${f.silent ? ', with no terminal shown' : ''}`;
  }
  if (f.kind !== 'command') return `A ${f.event} ${f.kind} hook is configured here (it does not run a shell command)`;
  return f.auto
    ? `Your next Claude Code session in this folder runs a ${f.event} hook`
    : `A ${f.event} hook runs whenever the agent fires ${f.event} (agent-triggered, not on open)`;
}

function hookMessage(f) {
  const target = f.command || f.target || '';
  const caps = capabilitySentence(capabilitiesOf([{ signals: f.signals || [] }]));
  const parts = [`${hookTrigger(f)}${target ? `: ${readableSignal(target)}` : ''}.`];
  if (caps) parts.push(`It ${caps}.`);
  if (f.fromDep) parts.push(`You did not write it: it shipped inside ${f.fromDep}.`);
  return parts.join(' ');
}

function hookExplain(f) {
  const caps = capabilitiesOf([{ signals: f.signals || [] }]);
  const out = [`**${hookTrigger(f)}**`, ''];
  if (f.command || f.target) out.push('```sh', readableSignal(f.command || f.target), '```');
  if (f.fromDep) out.push('', `This is not something you wrote. It arrived inside **${f.fromDep}**, so installing that dependency is what put code on your open-folder path.`);
  if (caps.length) {
    out.push('', '**What it does**');
    for (const c of caps) {
      const evidence = c.examples.slice(0, EVIDENCE_CAP).map(code).join(', ');
      out.push(`- ${c.does}${evidence ? ` — ${evidence}` : ''}`);
    }
  }
  out.push('', f.risk === 'HIGH'
    ? '**What to do** — read the command above and decide if you meant it. Cloning a repo is enough to trigger this one, so it runs before you have reviewed a single line of the project.'
    : '**What to do** — nothing urgent. It is listed so you know it exists; it only runs when something explicitly triggers it.');
  return out.join('\n');
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
      explain: hookExplain(f),
    });
  }
  for (const p of partials) {
    if (p.file !== rel) continue;
    out.push({
      line: 0,
      severity: p.rawHit ? 'warning' : 'information',
      risk: 'PARTIAL',
      message: `npm-script-lens could not fully read this file (${p.note}), so anything below may be unreported.`,
      explain: `**This file did not fully parse** — ${p.note}.\n\nThat is worth a look on its own: a config the editor still acts on but a scanner cannot read is exactly where something hides. Nothing here is a finding yet, it just means the scan is incomplete.`,
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
    // A CLI given a directory holding no lockfile answers { projects: [...] }.
    // One of them is still unambiguous; several cannot paint one file.
    const one = Array.isArray(j.projects) ? (j.projects.length === 1 ? j.projects[0] : null) : j;
    if (!one || !Array.isArray(one.results)) return null;
    return { results: one.results, recommended: one.allowScripts || {} };
  } catch { return null; }
}

const TRACKED_FILES = new Set(['package.json', 'pnpm-workspace.yaml']);

// The project an allowlist file belongs to is its own directory, never the
// workspace root. In a monorepo those differ, and auditing the root reports a
// different project's lockfile and reads a different project's allowlist.
// Returns null for anything that is not an allowlist file, so callers can fall
// back to the workspace.
const projectDirOf = (fsPath) => (TRACKED_FILES.has(nodePath.basename(String(fsPath))) ? nodePath.dirname(String(fsPath)) : null);

module.exports = {
  findDepLine, findYamlKeyLine, diagnosticsForPackageJson, diagnosticsForWorkspaceYaml,
  summarize, parseAudit, readDecisions, decisionFor, parseAllowBuilds, stateFor,
  riskOf, messageFor, explainFor, capabilitiesOf, scriptLines, trustLines,
  condenseSignals, readableSignal, RISK_SEVERITY, RISK_ICON, CAPABILITY,
  managerFrom, MANAGER_LABEL, allowlistFileFor, ACTIONS_SLOT,
  decisionEdit, writeAllowBuilds, LOCKFILES,
  treeFor, TREE_LABEL, TREE_ORDER, isScripted,
  isHookFile, parseHooks, hookMessage, hookExplain, diagnosticsForHooksFile, HOOK_FILES,
  projectDirOf, TRACKED_FILES,
};
