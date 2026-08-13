'use strict';
// Open-time execution surfaces: the code that runs when a folder is OPENED,
// not installed. The 2026-08-04 keyv/ChainDrop worm made this a first-class
// supply-chain stage, Wiz: "Persistence is attempted via Claude Code hooks
// and VS Code `tasks.json`" (two separately-hashed setup.mjs payloads, one
// under .claude, one under .vscode). The tarball half predates it: the
// hijacked html-to-gutenberg / fetch-page-assets releases (2026-05-25) hid a
// task named "eslint-check" with `runOn: "folderOpen"` inside the published
// package, firing when the package directory itself is opened as a workspace.
//
// Two surfaces, deliberately NOT symmetric in what a finding means:
//  - .vscode/tasks.json `runOptions.runOn: "folderOpen"`, VS Code 1.117
//    defaults `task.allowAutomaticTasks` to 'off' with a one-time
//    Allow/Disallow prompt (which does not display the command
//    microsoft/vscode#309406), and automatic tasks never run in an untrusted
//    workspace. A finding means "this runs once you trust this folder and
//    allow automatic tasks", not "this has run".
//  - .claude/settings.json hooks, a documented project-level, committable
//    location. There is NO hook review gate before a project command hook
//    fires ("Claude Code doesn't use the same hook review gate as Codex"
//    Datadog Security Labs, 2026-08). A SessionStart/Setup/InstructionsLoaded
//    finding means "this runs on your next session in this trusted folder".
//
// Both files permit comments and trailing commas, so the reader is a tolerant
// JSONC parser in the same spirit as src/gyp.js: never throw past the API, a
// file that will not parse is reported `partial` (with a raw-text hint when
// the tell-tale keys appear), never passed silently. Command strings feed the
// same shell-signal extraction and score() that audit applies to lifecycle
// scripts: the risk ladder is not forked.

const fs = require('node:fs');
const path = require('node:path');
const { analyzeCommand, score } = require('./analyzer');
const { loadDeps } = require('./lockfiles');
const { fetchPackage } = require('./registry');
const { cacheGet, cacheSet } = require('./cache');

const MAX_FILE_BYTES = 2 * 1024 * 1024; // matches registry.js indexing cap
const MAX_TREE_DIRS = 4000;
const MAX_TREE_DEPTH = 8;

// Claude Code hook events that fire without the agent doing anything: opening
// a session in the folder is enough. Everything else (PreToolUse, PostToolUse,
// Stop, …) is agent- or user-triggered mid-session, collected, tiered one
// level lower, and labelled as such.
const AUTO_EVENTS = new Set(['SessionStart', 'Setup', 'InstructionsLoaded']);
// The complete documented hook handler type set (code.claude.com/docs/hooks).
// Only 'command' is shell execution; the other four are reported but never as
// command execution.
const HOOK_TYPES = new Set(['command', 'http', 'mcp_tool', 'prompt', 'agent']);

// --- tolerant JSONC reader --------------------------------------------------
// JSON plus // and /* */ comments and trailing commas (what VS Code and
// Claude Code both accept). String values come back as String OBJECTS with a
// .line property; dicts carry a hidden __keyLines__ map, same anchoring
// trick as src/gyp.js, so every finding lands on a real file:line.

function tokenizeJsonc(text) {
  const tokens = [];
  let line = 1;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\n') { line++; continue; }
    if (ch === ' ' || ch === '\t' || ch === '\r') continue;
    if (ch === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      i--; continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) { if (text[i] === '\n') line++; i++; }
      i++; continue;
    }
    if (ch === '"' || ch === "'") { // single quotes tolerated, JSONC-adjacent
      const startLine = line;
      let value = '';
      i++;
      for (; i < text.length; i++) {
        const c = text[i];
        if (c === '\\') {
          const n = text[i + 1];
          if (n === ch || n === '\\' || n === '/') { value += n; i++; }
          else if (n === 'n') { value += '\n'; i++; }
          else if (n === 't') { value += '\t'; i++; }
          else if (n === 'r') { value += '\r'; i++; }
          else if (n === 'b') { value += '\b'; i++; }
          else if (n === 'f') { value += '\f'; i++; }
          else if (n === 'u' && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) {
            value += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16)); i += 5;
          } else value += c;
        } else if (c === ch) break;
        else {
          if (c === '\n') line++;
          value += c;
        }
      }
      if (i >= text.length) throw new Error(`unterminated string at line ${startLine}`);
      tokens.push({ type: 'string', value, line: startLine });
      continue;
    }
    if ('{}[],:'.includes(ch)) { tokens.push({ type: ch, line }); continue; }
    if (/[-0-9]/.test(ch)) {
      let j = i;
      while (j < text.length && /[-0-9.eE+]/.test(text[j])) j++;
      tokens.push({ type: 'literal', value: Number(text.slice(i, j)), line });
      i = j - 1; continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < text.length && /[A-Za-z_]/.test(text[j])) j++;
      const word = text.slice(i, j);
      if (word === 'true') tokens.push({ type: 'literal', value: true, line });
      else if (word === 'false') tokens.push({ type: 'literal', value: false, line });
      else if (word === 'null') tokens.push({ type: 'literal', value: null, line });
      else throw new Error(`unexpected token "${word}" at line ${line}`);
      i = j - 1; continue;
    }
    throw new Error(`unexpected character "${ch}" at line ${line}`);
  }
  return tokens;
}

function parseJsonc(text) {
  const tokens = tokenizeJsonc(text);
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];
  const expect = (type) => {
    const t = next();
    if (!t || t.type !== type) throw new Error(`expected "${type}" at line ${t ? t.line : '<eof>'}`);
    return t;
  };
  function parseValue() {
    const t = peek();
    if (!t) throw new Error('unexpected end of input');
    if (t.type === 'string') { next(); return Object.assign(new String(t.value), { line: t.line }); }
    if (t.type === 'literal') { next(); return t.value; }
    if (t.type === '{') {
      next();
      const dict = {};
      const keyLines = {};
      Object.defineProperty(dict, '__keyLines__', { value: keyLines, enumerable: false });
      while (peek() && peek().type !== '}') {
        const key = expect('string');
        expect(':');
        dict[key.value] = parseValue();
        keyLines[key.value] = key.line;
        if (peek() && peek().type === ',') next(); // trailing commas tolerated
        else break;
      }
      expect('}');
      return dict;
    }
    if (t.type === '[') {
      next();
      const arr = [];
      while (peek() && peek().type !== ']') {
        arr.push(parseValue());
        if (peek() && peek().type === ',') next();
        else break;
      }
      expect(']');
      return arr;
    }
    throw new Error(`unexpected "${t.type}" at line ${t.line}`);
  }
  const value = parseValue();
  if (pos < tokens.length) throw new Error(`trailing content at line ${tokens[pos].line}`);
  return value;
}

const strVal = (v) => (v instanceof String || typeof v === 'string' ? String(v) : null);
const lineOfVal = (v) => (v instanceof String && v.line ? v.line : null);
const isDict = (v) => v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof String);

// --- surface extractors -----------------------------------------------------
// Raw entries: { surface, trigger, auto, kind, label, command, line, silent?,
// event?, matcher?, note? }. Interpolations (${workspaceFolder},
// ${CLAUDE_PROJECT_DIR}) are kept literal, resolving them would be guessing.

function extractVscodeTasks(parsed) {
  const entries = [];
  const tasks = isDict(parsed) && Array.isArray(parsed.tasks) ? parsed.tasks : [];
  for (const task of tasks) {
    if (!isDict(task)) continue;
    const runOn = isDict(task.runOptions) ? strVal(task.runOptions.runOn) : null;
    if (runOn !== 'folderOpen') continue; // "default" (and absent) = on-demand only
    const label = strVal(task.label) || strVal(task.taskName) || null;
    const type = strVal(task.type) || null;
    let command = strVal(task.command);
    const args = Array.isArray(task.args) ? task.args.map((a) => strVal(a)).filter((a) => a !== null) : [];
    if (command && args.length > 0) command = `${command} ${args.join(' ')}`;
    // contributed task types ("npm", "gulp", …) carry the payload in `script`
    if (!command && strVal(task.script)) command = `${type || 'npm'} run ${strVal(task.script)}`;
    const entry = {
      surface: 'vscode-task', trigger: 'folderOpen', auto: true, kind: 'command',
      label, type, command,
      silent: isDict(task.presentation) && strVal(task.presentation.reveal) === 'silent',
      line: lineOfVal(task.label) || lineOfVal(task.command)
        || (isDict(task.runOptions) && lineOfVal(task.runOptions.runOn)) || null,
    };
    if (!command) entry.note = 'task defines no command string this scanner can read';
    entries.push(entry);
  }
  return entries;
}

function extractClaudeHooks(parsed) {
  const entries = [];
  const hooks = isDict(parsed) && isDict(parsed.hooks) ? parsed.hooks : {};
  const keyLines = hooks.__keyLines__ || {};
  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const group of groups) {
      if (!isDict(group)) continue;
      // documented shape: { matcher?, hooks: [handler, …] }, but tolerate a
      // handler written directly in the group position
      const handlers = Array.isArray(group.hooks) ? group.hooks
        : (strVal(group.type) || strVal(group.command)) ? [group] : [];
      for (const h of handlers) {
        if (!isDict(h)) continue;
        const declared = strVal(h.type);
        const command = strVal(h.command);
        // a payload in `command` is command execution whatever the label says
        const kind = command ? 'command' : (declared || 'unknown');
        const args = Array.isArray(h.args) ? h.args.map((a) => strVal(a)).filter((a) => a !== null) : [];
        const target = command ? (args.length > 0 ? `${command} ${args.join(' ')}` : command)
          : strVal(h.url) || (strVal(h.server) && `${strVal(h.server)} → ${strVal(h.tool) || '?'}`)
            || strVal(h.prompt) || null;
        const entry = {
          surface: 'claude-hook', trigger: event, event, auto: AUTO_EVENTS.has(event),
          kind, label: event, command: kind === 'command' ? target : null,
          matcher: strVal(group.matcher), silent: false,
          line: lineOfVal(h.command) || lineOfVal(h.type) || lineOfVal(h.url)
            || keyLines[event] || null,
        };
        if (kind !== 'command') {
          entry.target = target;
          entry.note = HOOK_TYPES.has(kind)
            ? `a "${kind}" hook — not shell command execution (the documented type set is command/http/mcp_tool/prompt/agent)`
            : `undocumented hook type "${kind}" — not classified as command execution`;
        }
        entries.push(entry);
      }
    }
  }
  return entries;
}

// One entry per auto-run location, adding an editor (Cursor rules, JetBrains
// startup tasks, …) is a new row here, nothing else.
const SURFACES = [
  {
    id: 'vscode-tasks',
    file: '.vscode/tasks.json',
    label: 'VS Code folderOpen task',
    rawHints: ['folderOpen'],
    extract: extractVscodeTasks,
    caveat: 'note (.vscode/tasks.json): a folderOpen finding means "this runs once you trust this folder and allow automatic tasks" — '
      + "VS Code 1.117 defaults task.allowAutomaticTasks to 'off' with a one-time Allow/Disallow prompt "
      + '(which does not display the command — microsoft/vscode#309406), workspace settings can no longer define that key, '
      + 'and automatic tasks never run in an untrusted workspace.',
  },
  {
    id: 'claude-hooks',
    file: '.claude/settings.json',
    label: 'Claude Code hook',
    rawHints: ['SessionStart', 'InstructionsLoaded', '"Setup"'],
    extract: extractClaudeHooks,
    caveat: 'note (.claude/settings.json): a SessionStart/Setup/InstructionsLoaded finding means "this runs on your next session in this trusted folder" — '
      + 'Claude Code has no hook review gate before a project command hook fires '
      + '("Claude Code doesn\'t use the same hook review gate as Codex" — Datadog Security Labs, 2026-08).',
  },
];

// --- classification ---------------------------------------------------------
// The same ladder audit applies to a lifecycle script: analyzeCommand extracts
// exec/net/fs/obf signals from the shell line (curl|sh, base64 payloads,
// node -e bodies, EXEC_BINS/NET_BINS), score() maps signals to a tier. Two
// adjustments, both labelled in the row: agent-triggered hooks tier one level
// lower, and anything shipped inside a dependency tarball is HIGH regardless
// of command: a folderOpen task in a published package is a payload, not a
// team convention (html-to-gutenberg / fetch-page-assets, 2026-05-25).

const DOWNGRADE = { HIGH: 'MEDIUM', MEDIUM: 'LOW', LOW: 'LOW', SAFE: 'SAFE' };

function classifyEntry(entry, files = new Map()) {
  if (entry.kind !== 'command' || !entry.command) {
    entry.signals = [];
    entry.risk = entry.kind === 'command' ? 'LOW' : 'INFO';
    return entry;
  }
  const signals = new Set();
  analyzeCommand(entry.command, files, signals, {}, new Set());
  entry.signals = [...signals].sort().map((s) => s.replace(' (source not in tarball)', ' (file not present)'));
  entry.risk = score(signals);
  if (entry.fromDep && entry.auto) {
    entry.risk = 'HIGH';
    entry.depForced = true;
  } else if (!entry.auto) {
    entry.risk = DOWNGRADE[entry.risk] || entry.risk;
  }
  return entry;
}

// Resolve `node setup.mjs`-style references against the directory being
// scanned so the payload file itself gets walked, the report then shows what
// the hook actually does, not just that it runs something.
function localFilesMap(rootDir, command) {
  const files = new Map();
  if (!command) return files;
  for (const tok of command.split(/\s+/)) {
    if (!/\.(c|m)?js$/i.test(tok) || tok.startsWith('-') || tok.includes('$')) continue;
    const rel = tok.replace(/^\.\//, '').replace(/\\/g, '/');
    if (rel.includes('..') || path.isAbsolute(tok)) continue;
    const full = path.join(rootDir, rel);
    try {
      if (fs.existsSync(full) && fs.statSync(full).size <= MAX_FILE_BYTES) {
        files.set(rel, fs.readFileSync(full, 'utf8'));
      }
    } catch { /* unreadable: the unresolved-file signal stands */ }
  }
  return files;
}

// --- workspace scan ---------------------------------------------------------

// Parse one surface file's text into classified findings. Never throws: a
// file that will not parse yields a single `partial` row, with a raw-text
// hint when the tell-tale keys appear (a hidden folderOpen task behind broken
// syntax is a hit worth surfacing over a silent pass).
function scanSurfaceText(surface, text, relFile, { rootDir = null, files = null } = {}) {
  let parsed;
  try {
    parsed = parseJsonc(text);
  } catch (err) {
    const hints = surface.rawHints.filter((h) => text.includes(h.replace(/"/g, '')));
    return {
      findings: [],
      partial: {
        file: relFile, surface: surface.id, line: 1,
        note: `did not parse as JSON/JSONC (${err.message})${hints.length > 0 ? ` — raw text mentions ${hints.map((h) => `"${h.replace(/"/g, '')}"`).join(', ')}` : ''}`,
        rawHit: hints.length > 0,
      },
    };
  }
  const findings = surface.extract(parsed).map((e) => {
    e.file = relFile;
    const map = files || (rootDir ? localFilesMap(rootDir, e.command) : new Map());
    return classifyEntry(e, map);
  });
  return { findings, partial: null };
}

// Directories that never hold a project-level surface file: dependency trees
// (the --deps scan covers those via tarballs) and VCS/internal dirs. .vscode
// and .claude themselves are dot-dirs, so the walk looks inside candidates
// explicitly rather than recursing into dot-dirs generally.
function scanProject(target = '.') {
  const rootDir = path.resolve(target);
  if (!fs.existsSync(rootDir) || !fs.statSync(rootDir).isDirectory()) {
    throw new Error(`not a directory: ${target}`);
  }
  const findings = [];
  const partials = [];
  const scanned = [];
  let dirCount = 0;
  const visit = (dir, rel, depth) => {
    if (dirCount++ > MAX_TREE_DIRS) return;
    for (const surface of SURFACES) {
      const file = path.join(dir, surface.file);
      const relFile = (rel ? `${rel}/` : '') + surface.file;
      let stat = null;
      try { stat = fs.statSync(file); } catch { continue; } // absent: nothing to report
      if (!stat.isFile()) continue;
      scanned.push(relFile);
      if (stat.size > MAX_FILE_BYTES) {
        partials.push({ file: relFile, surface: surface.id, line: 1, note: `over the ${MAX_FILE_BYTES / 1024 / 1024} MB cap — not scanned`, rawHit: false });
        continue;
      }
      const text = fs.readFileSync(file, 'utf8');
      const { findings: f, partial } = scanSurfaceText(surface, text, relFile, { rootDir: dir });
      findings.push(...f);
      if (partial) partials.push(partial);
    }
    if (depth >= MAX_TREE_DEPTH) return;
    let names = [];
    try { names = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of names) {
      if (!e.isDirectory() || e.name === 'node_modules' || e.name.startsWith('.')) continue;
      visit(path.join(dir, e.name), (rel ? `${rel}/` : '') + e.name, depth + 1);
    }
  };
  visit(rootDir, '', 0);
  return { projectDir: rootDir, findings, partials, scanned };
}

// --- dependency scan (--deps) -----------------------------------------------
// Every locked dependency's tarball, via the same registry/cache path audit
// uses. Needs the tarball for every package (a shipped .vscode is invisible in
// registry metadata), so it is heavier than a plain audit, results are
// cached per name@version like analysis rows are.

const DEP_SURFACE_RE = {
  'vscode-tasks': /(^|\/)\.vscode\/tasks\.json$/,
  'claude-hooks': /(^|\/)\.claude\/settings\.json$/,
};

function scanDepPackage(pkg) {
  const findings = [];
  for (const surface of SURFACES) {
    const re = DEP_SURFACE_RE[surface.id];
    for (const key of pkg.files.keys()) {
      if (!re.test(key)) continue;
      const relFile = `node_modules/${pkg.name}/${key}`;
      const { findings: f, partial } = scanSurfaceText(surface, pkg.files.get(key), relFile, { files: pkg.files });
      for (const e of f) {
        e.fromDep = `${pkg.name}@${pkg.version}`;
        // re-classify with the dep rule: auto entries are HIGH regardless
        classifyEntry(e, pkg.files);
      }
      findings.push(...f);
      if (partial) {
        partial.fromDep = `${pkg.name}@${pkg.version}`;
        partial.rawHit = true; // unparseable surface file inside a tarball is itself suspicious
        findings.push({
          surface: surface.id, file: relFile, line: 1, kind: 'partial', auto: true,
          fromDep: partial.fromDep, label: null, command: null, signals: [],
          risk: 'HIGH', depForced: true, note: partial.note,
        });
      }
    }
  }
  return findings;
}

async function scanDeps(target, { cache = true, concurrency = 8, log = () => {} } = {}) {
  const { deps } = loadDeps(target);
  log(`hooks --deps: scanning ${deps.length} locked package tarball(s) for shipped open-time surfaces`);
  const findings = [];
  const errors = [];
  let i = 0, done = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, deps.length) }, async () => {
    while (i < deps.length) {
      const dep = deps[i++];
      const cKey = [`hooks~${dep.name.replace('/', '+')}`, dep.version];
      const hit = cache ? cacheGet(cKey[0], cKey[1]) : null;
      if (hit) { findings.push(...hit); done++; continue; }
      try {
        const pkg = await fetchPackage(dep.name, dep.version, { forceTarball: true });
        const rows = scanDepPackage(pkg);
        if (cache) cacheSet(cKey[0], cKey[1], rows);
        findings.push(...rows);
      } catch (err) {
        errors.push(`${dep.name}@${dep.version}: ${String(err.message || err)}`);
      }
      if (++done % 25 === 0) log(`  ${done}/${deps.length}`);
    }
  }));
  return { findings, errors, total: deps.length };
}

// --- verdict + rendering ----------------------------------------------------

const RANK = { HIGH: 3, MEDIUM: 2, LOW: 1, SAFE: 0, INFO: 0 };
const FLOORS = { none: Infinity, medium: 2, high: 3 };

// --check verdict: entries at or above the floor (partial files never fail on
// their own, except dep-shipped ones, which surface as HIGH findings above).
function checkHooks(findings, failOn = 'high') {
  const floor = FLOORS[failOn];
  if (floor === undefined) throw new Error(`--fail-on expects none | medium | high, got: ${failOn}`);
  const over = findings.filter((f) => (RANK[f.risk] || 0) >= floor);
  return { ok: over.length === 0, over };
}

function describeFinding(f) {
  if (f.kind === 'partial') return `unparseable ${f.surface === 'vscode-tasks' ? 'tasks.json' : 'settings.json'} — ${f.note}`;
  if (f.surface === 'vscode-task') {
    return `folderOpen task ${f.label ? `"${f.label}"` : '(unnamed)'} → ${f.command || '(no command)'}${f.silent ? ' (silent)' : ''}`;
  }
  if (f.kind === 'command') {
    return `${f.event} hook${f.auto ? '' : ' (agent-triggered, not open-time)'} → ${f.command}`;
  }
  return `${f.event} ${f.kind} hook${f.auto ? '' : ' (agent-triggered, not open-time)'} → ${f.target || '(no target)'}`;
}

function renderHooks(findings, partials = []) {
  const lines = [];
  for (const f of findings) {
    const dep = f.fromDep ? `  [shipped in ${f.fromDep}]` : '';
    lines.push(`${f.file}:${f.line == null ? '?' : f.line}  ${f.risk}  ${describeFinding(f)}${dep}`);
  }
  for (const p of partials) {
    lines.push(`${p.file}:${p.line}  PARTIAL  ${p.note}`);
  }
  if (findings.length === 0) {
    lines.push(partials.length > 0
      ? `no open-time execution entries found (${partials.length} file(s) partial — see above)`
      : 'no open-time execution entries found');
  } else {
    const counts = {};
    for (const f of findings) counts[f.risk] = (counts[f.risk] || 0) + 1;
    const mix = ['HIGH', 'MEDIUM', 'LOW', 'SAFE', 'INFO'].filter((k) => counts[k]).map((k) => `${counts[k]} ${k}`).join(', ');
    lines.push(`${findings.length} open-time execution entr${findings.length === 1 ? 'y' : 'ies'} found (${mix}).`);
  }
  return lines.join('\n');
}

// The honesty notes, per surface with findings, the two surfaces gate very
// differently, so one shared caveat would overstate one or soften the other.
function surfaceCaveats(findings) {
  const present = new Set(findings.map((f) => (f.surface === 'vscode-task' || f.surface === 'vscode-tasks' ? 'vscode-tasks' : 'claude-hooks')));
  return SURFACES.filter((s) => present.has(s.id)).map((s) => s.caveat);
}

function hooksJson(findings, partials, { errors = [], depsScanned = null } = {}) {
  return {
    findings: findings.map((f) => ({
      file: f.file, line: f.line == null ? null : f.line, surface: f.surface,
      trigger: f.trigger || null, event: f.event || null, kind: f.kind,
      auto: Boolean(f.auto), label: f.label || null,
      command: f.command || null, target: f.target || null,
      silent: Boolean(f.silent), matcher: f.matcher || null,
      signals: f.signals || [], risk: f.risk,
      fromDep: f.fromDep || null, depForced: Boolean(f.depForced),
      note: f.note || null,
    })),
    partial: partials.map((p) => ({ file: p.file, surface: p.surface, note: p.note, rawHit: Boolean(p.rawHit) })),
    caveats: surfaceCaveats(findings),
    deps: depsScanned === null ? null : { scanned: depsScanned, errors },
  };
}

// SARIF-ready findings (rule hook-auto-run), same generic shape
// reporter.buildSarif consumes for the gap/publish rules: warning by default,
// error at HIGH, anchored to the real file:line.
function hooksFindings(findings) {
  return findings.filter((f) => f.risk !== 'INFO').map((f, i) => ({
    id: 'hook-auto-run',
    level: f.risk === 'HIGH' ? 'error' : 'warning',
    package: f.fromDep || f.label || f.event || f.surface,
    file: f.file,
    line: f.line || 1,
    fix: `${describeFinding(f)}${f.fromDep ? ` — shipped inside ${f.fromDep}: a published package has no business auto-running code when its folder is opened` : ''}`,
    fingerprint: `hook-auto-run:${f.file}:${f.line || 1}:${i}`,
  }));
}

module.exports = {
  SURFACES, AUTO_EVENTS, HOOK_TYPES,
  parseJsonc, scanSurfaceText, scanProject, scanDeps, scanDepPackage,
  classifyEntry, checkHooks, renderHooks, surfaceCaveats, hooksJson, hooksFindings,
};
