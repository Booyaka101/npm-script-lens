'use strict';
// VS Code host for npm-script-lens. Thin UI over the CLI: it shells out to
// `npm-script-lens audit --json` and renders the results as inline diagnostics
// on package.json, hovers that explain them, a panel listing every scripted
// dependency, per-package approve/block edits, and a status-bar summary. All
// analysis lives in the CLI; the pure mapping lives in core.js (unit-tested).
const vscode = require('vscode');
const cp = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const core = require('./core');

// The two files a decision can live in: package.json (npm allowScripts, yarn
// dependenciesMeta, bun trustedDependencies) and pnpm-workspace.yaml
// (allowBuilds). Editing either one changes what should be flagged, so both are
// watched and both can carry diagnostics.
const PKG = 'package.json';
const PNPM_WORKSPACE = 'pnpm-workspace.yaml';
const TRACKED = new Set([PKG, PNPM_WORKSPACE]);

const SEVERITY = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};

let channel;
let diagnostics;
let status;
let tree;
let view;

// projectDir → the last audit of it: { results, opts, sum, manager, at }. Kept
// so the panel, the status bar and a per-package decision all read the same
// answer instead of each shelling out for their own.
const audits = new Map();
// uri string → [{ line, markdown, name, version }] for hovers and quick fixes.
// A diagnostic message has to stay one scannable line, but "esbuild runs other
// programs" only helps if the reader can find out WHICH programs, and decide,
// without leaving the file.
const explanations = new Map();

function config() {
  const c = vscode.workspace.getConfiguration('npmScriptLens');
  return {
    command: c.get('command', 'npx npm-script-lens'),
    trust: c.get('trust', true),
    auditOnOpen: c.get('auditOnOpen', true),
  };
}

// --- shelling out ----------------------------------------------------------

function runCli(args, cwd) {
  const { command } = config();
  return new Promise((resolve) => {
    cp.exec(`${command} ${args.join(' ')}`, { cwd, maxBuffer: 32 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      resolve({ code: err ? (err.code || 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

function workspaceDir(doc) {
  const folder = doc && vscode.workspace.getWorkspaceFolder(doc.uri);
  if (folder) return folder.uri.fsPath;
  const first = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  return first ? first.uri.fsPath : undefined;
}

// A tracked file's own directory, falling back to the workspace. When that
// directory holds no lockfile of its own (an npm workspaces member), the CLI
// searches upward from it and lands on the root that really governs it.
function projectDir(doc) {
  return (doc && core.projectDirOf(doc.uri.fsPath)) || workspaceDir(doc);
}

// Reading a dependency's own package.json is completely normal, and every one
// of them is a `package.json` that matches every pattern this extension
// registers. Auditing them is not: the answer would be about a package the
// reader does not own, and opening a handful of them would queue a CLI run
// each. The file still gets hovers if we already have findings for it; it just
// never triggers an audit of its own.
const isVendored = (fsPath) => /[\\/]node_modules[\\/]/.test(String(fsPath));

const readIfPresent = (dir, file) => {
  try { return fs.readFileSync(path.join(dir, file), 'utf8'); } catch { return ''; }
};

// The open buffer beats the file on disk. A decision recorded from stale disk
// content would be applied over the whole document, throwing away whatever the
// user had typed and not yet saved.
function liveText(dir, file) {
  const want = path.join(dir, file);
  for (const d of vscode.workspace.textDocuments) {
    if (d.uri.scheme === 'file' && path.normalize(d.uri.fsPath) === path.normalize(want)) return d.getText();
  }
  return readIfPresent(dir, file);
}

// Which package manager's allowlist does a decision here belong in? Answered
// from the nearest lockfile at or above `dir`, the way the CLI resolves it, so
// the editor writes the same file the CLI would.
function managerFor(dir) {
  for (let at = dir, prev = null; at && at !== prev; prev = at, at = path.dirname(at)) {
    let present = [];
    try { present = fs.readdirSync(at); } catch { /* unreadable, keep walking */ }
    if (core.LOCKFILES.some(([f]) => present.includes(f))) return core.managerFrom(present);
  }
  return 'npm';
}

// --- painting --------------------------------------------------------------

// Doc links for the hover footer. Command URIs only resolve in a trusted
// MarkdownString, so this is built here rather than in core.js.
const ACTIONS = [
  ['Approve the safe ones', 'npmScriptLens.allowWrite'],
  ['Show every finding', 'npmScriptLens.review'],
  ['Re-check', 'npmScriptLens.audit'],
];

// What VS Code renders after the source, as `npm-script-lens(undecided)`. The
// internal state names are not the reader's words.
const CODE = { alarm: 'malicious', decide: 'undecided', override: 'override' };

const cmdLink = (label, command, args) => `[${label}](command:${command}${args ? `?${encodeURIComponent(JSON.stringify(args))}` : ''})`;

// The two decisions the finding is asking for, per package, so the answer sits
// next to the question. Findings that are not about a single package (open-time
// hooks) fall back to the project-wide commands.
function actionLinks(entry, cwd) {
  if (!entry.name || !cwd) return ACTIONS.map(([label, command]) => cmdLink(label, command)).join(' · ');
  const arg = (allow) => ({ cwd, name: entry.name, version: entry.version, allow });
  return [
    cmdLink('$(check) Approve', 'npmScriptLens.decide', arg(true)),
    cmdLink('$(circle-slash) Block', 'npmScriptLens.decide', arg(false)),
    cmdLink('$(list-unordered) Show every finding', 'npmScriptLens.review'),
  ].join(' · ');
}

function markdownFor(entry, cwd) {
  const md = new vscode.MarkdownString(entry.markdown.replace(core.ACTIONS_SLOT, actionLinks(entry, cwd)));
  md.isTrusted = true;
  md.supportThemeIcons = true;
  return md;
}

// Set both the squiggles and their hover text for one document, from core.js
// diagnostic objects. Kept together so the two can never drift out of sync.
function paint(doc, found) {
  diagnostics.set(doc.uri, found.map((f) => {
    const line = Math.min(f.line, doc.lineCount - 1);
    const diag = new vscode.Diagnostic(doc.lineAt(line).range, f.message,
      SEVERITY[f.severity] || vscode.DiagnosticSeverity.Information);
    diag.source = 'npm-script-lens';
    const code = CODE[f.state] || (f.risk ? String(f.risk).toLowerCase() : '');
    if (code) diag.code = code;
    return diag;
  }));
  explanations.set(doc.uri.toString(), found
    .filter((f) => f.explain)
    .map((f) => ({
      line: Math.min(f.line, doc.lineCount - 1),
      markdown: f.explain,
      name: f.name || null,
      version: f.version || null,
    })));
}

// --- auditing --------------------------------------------------------------

// One audit in flight per project, and the newest request wins. Saving
// package.json three times in five seconds used to mean three concurrent CLI
// runs racing to paint the same file.
const inFlight = new Map();
const pending = new Map();
const DEBOUNCE_MS = 400;

function busy() {
  status.text = '$(sync~spin) checking install scripts…';
  status.show();
}

async function audit(cwd) {
  const { trust } = config();
  // --path pins the audit to this project. Without it the CLI defaults to the
  // cwd, and a cwd holding no lockfile now audits every project underneath.
  const args = ['audit', '--json', '--path', JSON.stringify(cwd)];
  if (!trust) args.push('--no-trust');
  const { stdout, stderr, code } = await runCli(args, cwd);
  const parsed = core.parseAudit(stdout);
  if (!parsed) {
    const detail = stderr.trim() || stdout.trim() || 'no output';
    channel.appendLine(`audit failed (exit ${code}): ${detail}`);
    status.text = '$(shield) install scripts: audit failed';
    status.tooltip = `npm-script-lens could not run. Click to open the log.\n\n${detail.slice(0, 400)}`;
    status.command = 'npmScriptLens.showLog';
    status.show();
    return null;
  }
  status.command = 'npmScriptLens.focusPanel';
  return parsed;
}

// Re-audit the project that `doc` belongs to and repaint EVERY open allowlist
// file in it, not just the one that was touched. The two files are one
// decision surface: denying a package in pnpm-workspace.yaml clears its warning
// over in package.json, so refreshing only the saved document would leave the
// other one asserting something that is no longer true. One audit, all views.
async function refreshProject(cwd) {
  if (!cwd) return;
  busy();
  const parsed = await audit(cwd);
  if (!parsed) { tree.refresh(); return; }
  const { results, recommended } = parsed;

  // Only the files of this project. Grouping by workspace root would repaint a
  // sibling package's package.json from these results.
  const open = new Map();
  for (const d of vscode.workspace.textDocuments) {
    if (TRACKED.has(path.basename(d.uri.fsPath)) && projectDir(d) === cwd) open.set(d.uri.toString(), d);
  }

  // liveText prefers the open buffer, so an unsaved allowlist edit is reflected
  // as soon as anything triggers a refresh.
  const opts = {
    recommended,
    decisions: core.readDecisions(liveText(cwd, PKG) || '{}', liveText(cwd, PNPM_WORKSPACE)),
  };

  for (const d of open.values()) {
    const text = d.getText();
    paint(d, path.basename(d.uri.fsPath) === PKG
      ? core.diagnosticsForPackageJson(text, results, opts)
      : core.diagnosticsForWorkspaceYaml(text, results, opts));
  }

  // Delete before set: re-setting an existing key leaves it where it was in
  // insertion order, and the panel's fallback reads that order as recency.
  audits.delete(cwd);
  audits.set(cwd, { results, opts, sum: core.summarize(results, opts) });
  tree.refresh();
  lensChanged.fire();
  syncViews();
}

// The status bar and the activity-bar badge describe ONE project, so they
// follow the project you are looking at rather than whichever one finished
// auditing last. In a monorepo those are routinely different.
function syncViews() {
  const state = tree.current();
  if (!state) return;
  const { sum } = state;
  status.text = `$(shield) ${sum.text}`;
  status.tooltip = sum.undecided
    ? `${sum.undecided} package(s) run code when you install them, and you have not approved or blocked them yet. Click to open the panel.`
    : 'npm-script-lens: nothing left to decide. Click to open the panel.';
  status.show();
  // A count you cannot miss, and no badge at all once there is nothing to do.
  view.badge = sum.undecided
    ? { value: sum.undecided, tooltip: `${sum.undecided} install script(s) awaiting a decision` }
    : undefined;
}

// Coalesce bursts (save-all, a lockfile rewrite, an applied decision) into one
// run per project, and never overlap two runs of the same project.
function schedule(cwd) {
  if (!cwd) return;
  clearTimeout(pending.get(cwd));
  pending.set(cwd, setTimeout(() => {
    pending.delete(cwd);
    if (inFlight.has(cwd)) { inFlight.get(cwd).then(() => schedule(cwd)); return; }
    const run = refreshProject(cwd)
      .catch((e) => channel.appendLine(`error: ${e.message}`))
      .finally(() => inFlight.delete(cwd));
    inFlight.set(cwd, run);
  }, DEBOUNCE_MS));
}

// Diagnostics on the open-time surfaces themselves. When a .vscode/tasks.json
// or .claude/settings.json is opened or saved, run `hooks --json` (CLI 1.8.0)
// and paint the findings on their real lines. Every open hooks file in the
// workspace repaints from the one scan, same discipline as refreshProject().
// On a CLI too old to know `hooks`, parseHooks returns null and nothing is
// painted.
async function refreshHooks(doc) {
  if (!doc || !core.isHookFile(doc.uri.fsPath)) return;
  const cwd = workspaceDir(doc);
  if (!cwd) return;
  const { stdout, stderr, code } = await runCli(['hooks', '--json'], cwd);
  const parsed = core.parseHooks(stdout);
  if (!parsed) {
    channel.appendLine(`hooks scan failed (exit ${code}): ${stderr.trim() || stdout.trim() || 'no output'}. CLI >= 1.8.0 required`);
    return;
  }
  const open = new Map([[doc.uri.toString(), doc]]);
  for (const d of vscode.workspace.textDocuments) {
    if (core.isHookFile(d.uri.fsPath) && workspaceDir(d) === cwd) open.set(d.uri.toString(), d);
  }
  for (const d of open.values()) {
    const rel = path.relative(cwd, d.uri.fsPath).replace(/\\/g, '/');
    paint(d, core.diagnosticsForHooksFile(rel, parsed.findings, parsed.partial));
  }
}

// --- recording one decision ------------------------------------------------

// Approve or block a single package, as a normal editor edit: it lands in the
// undo stack, it shows in the diff, and it is the same bytes the CLI writes.
// Shelling out to the CLI for this would rewrite the file underneath any
// unsaved changes and give the user nothing to undo.
// `quiet` suppresses the per-package feedback and hands the caveat back
// instead, so a bulk run reports once rather than stacking one toast per
// package. Returns the note, or null.
async function decide(arg, { quiet = false } = {}) {
  // Reachable from a keybinding or another extension, where the argument is
  // whatever the caller passed. Failing here beats throwing inside a command
  // handler, which surfaces as an unexplained "command failed".
  const { cwd, name, version, allow } = arg || {};
  if (!cwd || !name) {
    vscode.window.showErrorMessage('npm-script-lens: a decision needs a project and a package. Use the panel, the hover, or Ctrl+. on a finding.');
    return null;
  }
  const manager = managerFor(cwd);
  const file = core.allowlistFileFor(manager);
  const target = vscode.Uri.file(path.join(cwd, file));
  const pkgText = liveText(cwd, PKG) || '{}';
  const yamlText = liveText(cwd, PNPM_WORKSPACE);

  let next;
  try {
    next = core.decisionEdit({ manager, name, version, allow, pkgText, yamlText });
  } catch (e) {
    vscode.window.showErrorMessage(`npm-script-lens: ${file} does not parse, so the decision was not recorded (${e.message})`);
    return null;
  }
  // yarn's caveat is that dependenciesMeta only means anything with
  // `enableScripts: false`. Once that is set, repeating it is just noise.
  if (manager === 'yarn' && /^enableScripts:\s*false\s*$/m.test(readIfPresent(cwd, '.yarnrc.yml'))) next.note = null;

  // pnpm is the only manager whose allowlist file may not exist yet.
  const edit = new vscode.WorkspaceEdit();
  const doc = await vscode.workspace.openTextDocument(target).then((d) => d, () => null);
  if (!doc) edit.createFile(target, { overwrite: false, ignoreIfExists: true });
  const whole = doc ? new vscode.Range(0, 0, doc.lineCount, 0) : new vscode.Range(0, 0, 0, 0);
  edit.replace(target, whole, next.text);
  if (!await vscode.workspace.applyEdit(edit)) {
    vscode.window.showErrorMessage(`npm-script-lens: could not write ${next.file}`);
    return null;
  }
  const saved = await vscode.workspace.openTextDocument(target);
  // A file VS Code creates gets the platform default line ending, which on
  // Windows is CRLF, while the CLI always writes LF. Left alone, the same
  // allowlist ends up spelled two ways depending on which end recorded the
  // decision, and every alternating write is a whole-file diff. Editing an
  // existing file already inherits that file's own ending, so this only has to
  // pin the one case that has no precedent to follow.
  if (!doc && saved.eol !== vscode.EndOfLine.LF) {
    const eol = new vscode.WorkspaceEdit();
    eol.set(target, [vscode.TextEdit.setEndOfLine(vscode.EndOfLine.LF)]);
    await vscode.workspace.applyEdit(eol);
  }
  // Saving is what makes the decision real: the CLI reads the file from disk,
  // so leaving it dirty would keep re-reporting a package you just ruled on.
  // The content is the user's own buffer plus this one entry, never a stale
  // copy from disk, so nothing of theirs is lost by writing it out.
  await saved.save();

  const verb = allow ? 'Approved' : 'Blocked';
  const detail = `${verb} ${name}@${version} in ${core.MANAGER_LABEL[manager]}'s ${next.file}.`;
  if (!quiet) {
    if (next.note) vscode.window.showWarningMessage(`${detail} ${next.note}`);
    else vscode.window.setStatusBarMessage(`npm-script-lens: ${detail}`, 4000);
  }
  schedule(cwd);
  return next.note;
}

// --- the panel -------------------------------------------------------------

const GROUP_ICON = {
  alarm: new vscode.ThemeIcon('error', new vscode.ThemeColor('list.errorForeground')),
  decide: new vscode.ThemeIcon('warning', new vscode.ThemeColor('list.warningForeground')),
  override: new vscode.ThemeIcon('unverified'),
  clean: new vscode.ThemeIcon('circle-outline'),
  settled: new vscode.ThemeIcon('verified'),
  blocked: new vscode.ThemeIcon('circle-slash'),
};

class InstallScriptsTree {
  constructor() {
    this._onDidChange = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChange.event;
  }

  refresh() { this._onDidChange.fire(); }

  // The project belonging to the file in front of you, falling back to the one
  // audited most recently (refreshProject keeps `audits` in recency order).
  // Which matters in a monorepo, where "the last audit that finished" and "the
  // project you are looking at" are routinely different.
  current() {
    const doc = vscode.window.activeTextEditor && vscode.window.activeTextEditor.document;
    const active = doc && projectDir(doc);
    if (active && audits.has(active)) return { cwd: active, ...audits.get(active) };
    const latest = [...audits.keys()].pop();
    return latest ? { cwd: latest, ...audits.get(latest) } : null;
  }

  getTreeItem(node) { return node.item; }

  getChildren(node) {
    const state = this.current();
    if (!state) return [];
    if (!node) {
      return core.treeFor(state.results, state.opts).map((group) => {
        const item = new vscode.TreeItem(`${group.label} (${group.items.length})`,
          group.id === 'decide' || group.id === 'alarm'
            ? vscode.TreeItemCollapsibleState.Expanded
            : vscode.TreeItemCollapsibleState.Collapsed);
        item.iconPath = GROUP_ICON[group.id];
        item.contextValue = `group:${group.id}`;
        return { item, group, cwd: state.cwd };
      });
    }
    if (!node.group) return [];
    return node.group.items.map((pkg) => {
      const item = new vscode.TreeItem(pkg.key, vscode.TreeItemCollapsibleState.None);
      item.description = pkg.via && pkg.via.length ? `${pkg.detail} · via ${pkg.via.join(' → ')}` : pkg.detail;
      item.tooltip = markdownFor({ markdown: pkg.explain, name: pkg.name, version: pkg.version }, node.cwd);
      item.iconPath = GROUP_ICON[pkg.state];
      // Drives which inline buttons show: nothing to approve on an already
      // approved package, nothing to block on an already blocked one.
      item.contextValue = `pkg:${pkg.state}`;
      item.command = {
        command: 'npmScriptLens.reveal',
        title: 'Go to the dependency',
        arguments: [{ cwd: node.cwd, name: pkg.name, via: pkg.via }],
      };
      return { item, pkg, cwd: node.cwd };
    });
  }
}

// Jump to the line that pulled a package in. A transitive dependency has no
// line of its own, so land on the direct dependency that brought it, which is
// the line you can actually change.
async function reveal(arg) {
  const { cwd, name, via } = arg || {};
  if (!cwd) return;
  const target = vscode.Uri.file(path.join(cwd, PKG));
  const doc = await vscode.workspace.openTextDocument(target).then((d) => d, () => null);
  if (!doc) return;
  const text = doc.getText();
  const line = [name, ...(via || [])].map((n) => core.findDepLine(text, n)).find((l) => l >= 0);
  const editor = await vscode.window.showTextDocument(doc);
  if (line === undefined || line < 0) return;
  const at = new vscode.Range(line, 0, line, 0);
  editor.revealRange(at, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
  editor.selection = new vscode.Selection(at.start, at.start);
}

// --- providers -------------------------------------------------------------

// Every file this extension can mark up: the two allowlist files and the two
// open-time hook surfaces.
const SELECTOR = [PKG, PNPM_WORKSPACE, ...core.HOOK_FILES].map((f) => ({ scheme: 'file', pattern: `**/${f}` }));

const hovers = {
  provideHover(doc, position) {
    const found = (explanations.get(doc.uri.toString()) || []).filter((e) => e.line === position.line);
    if (found.length === 0) return null;
    const cwd = projectDir(doc);
    return new vscode.Hover(found.map((e) => markdownFor(e, cwd)), doc.lineAt(position.line).range);
  },
};

// Ctrl+. on a flagged line, offering the decision the diagnostic is asking for.
// Neither offer is marked isPreferred on purpose: that would put one of them on
// Auto Fix, and "approve arbitrary install-time code" is not something a stray
// keystroke should do. Both decisions are one deliberate pick away, which is
// the whole point of the feature.
const OFFERS = [{ label: 'Approve', allow: true }, { label: 'Block', allow: false }];

const quickFixes = {
  provideCodeActions(doc, range, ctx) {
    const ours = ctx.diagnostics.filter((d) => d.source === 'npm-script-lens');
    if (ours.length === 0) return [];
    const cwd = projectDir(doc);
    const here = (explanations.get(doc.uri.toString()) || [])
      .filter((e) => e.name && ours.some((d) => d.range.start.line === e.line));

    const out = [];
    for (const e of here) {
      for (const { label, allow } of OFFERS) {
        const action = new vscode.CodeAction(`${label} ${e.name}@${e.version}`, vscode.CodeActionKind.QuickFix);
        action.command = {
          command: 'npmScriptLens.decide',
          title: label,
          arguments: [{ cwd, name: e.name, version: e.version, allow }],
        };
        action.diagnostics = ours;
        out.push(action);
      }
    }
    for (const [title, command] of ACTIONS) {
      const action = new vscode.CodeAction(`npm-script-lens: ${title}`, vscode.CodeActionKind.QuickFix);
      action.command = { command, title };
      action.diagnostics = ours;
      out.push(action);
    }
    return out;
  },
};

// A count above the dependency block, so the file tells you there is something
// to look at before you go hunting for coloured underlines. The emitter is not
// optional: an audit is asynchronous, so the first answer always arrives after
// VS Code has already asked, and without it the lens never appears.
const lensChanged = new vscode.EventEmitter();
const lenses = {
  onDidChangeCodeLenses: lensChanged.event,
  provideCodeLenses(doc) {
    if (path.basename(doc.uri.fsPath) !== PKG) return [];
    const state = audits.get(projectDir(doc));
    if (!state) return [];
    const { sum } = state;
    if (!sum.scripted) return [];
    const line = doc.getText().split(/\r?\n/).findIndex((l) => /^\s*"(dependencies|devDependencies)"\s*:/.test(l));
    if (line < 0) return [];
    const title = sum.undecided
      ? `$(shield) ${sum.undecided} of ${sum.scripted} install scripts still need a decision`
      : `$(shield) ${sum.scripted} install scripts, all decided`;
    return [new vscode.CodeLens(new vscode.Range(line, 0, line, 0),
      { title, command: 'npmScriptLens.focusPanel' })];
  },
};

// --- commands --------------------------------------------------------------

// A command that streams CLI output to the output channel. Lockfile commands
// run against the open package.json's own project; `hooks` walks a tree, so it
// keeps the whole workspace.
function cliCommand(title, argsFn, { writes = false, wholeWorkspace = false } = {}) {
  return async () => {
    const doc = vscode.window.activeTextEditor && vscode.window.activeTextEditor.document;
    const cwd = wholeWorkspace ? workspaceDir(doc) : projectDir(doc);
    if (!cwd) { vscode.window.showWarningMessage('npm-script-lens: open a workspace folder first'); return; }
    channel.show(true);
    channel.appendLine(`\n$ ${config().command} ${argsFn().join(' ')}  (in ${cwd})`);
    const { stdout, stderr } = await runCli(argsFn(), cwd);
    if (stdout) channel.appendLine(stdout.trimEnd());
    if (stderr) channel.appendLine(stderr.trimEnd());
    if (writes) for (const key of audits.keys()) schedule(key);
    vscode.window.showInformationMessage(`npm-script-lens: ${title} finished`);
  };
}

// A tree node → the decision it stands for. Null for anything that is not a
// package row, which decide() reports rather than throwing on.
const rowArg = (node, allow) => (node && node.pkg
  ? { cwd: node.cwd, name: node.pkg.name, version: node.pkg.version, allow }
  : null);

// Decide every package still waiting, in one pass, after showing what they are.
// The bulk answer people actually want ("yes, all of this is my own build
// tooling") without hiding what it covers.
async function decideAll(allow) {
  const state = tree.current();
  if (!state) { vscode.window.showWarningMessage('npm-script-lens: nothing audited yet'); return; }
  const waiting = core.treeFor(state.results, state.opts)
    .filter((g) => g.id === 'decide' || g.id === 'clean')
    .flatMap((g) => g.items);
  if (waiting.length === 0) { vscode.window.showInformationMessage('npm-script-lens: nothing is waiting on a decision'); return; }
  const verb = allow ? 'Approve' : 'Block';
  const listed = waiting.slice(0, 8).map((p) => p.key).join(', ');
  const pick = await vscode.window.showWarningMessage(
    `${verb} ${waiting.length} package(s)?`,
    { modal: true, detail: `${listed}${waiting.length > 8 ? `, +${waiting.length - 8} more` : ''}` },
    verb,
  );
  if (pick !== verb) return;

  // Sequential, because each decision is computed from the file the previous
  // one just wrote. Caveats are collected rather than announced: bun hands one
  // back for every denial it cannot spell, and twenty identical toasts say
  // nothing the first one did not.
  const notes = new Set();
  for (const pkg of waiting) {
    const note = await decide({ cwd: state.cwd, name: pkg.name, version: pkg.version, allow }, { quiet: true });
    if (note) notes.add(note);
  }
  const done = `${allow ? 'Approved' : 'Blocked'} ${waiting.length} package(s).`;
  if (notes.size) vscode.window.showWarningMessage(`npm-script-lens: ${done} ${[...notes].join(' ')}`);
  else vscode.window.showInformationMessage(`npm-script-lens: ${done}`);
}

function activate(context) {
  channel = vscode.window.createOutputChannel('npm-script-lens');
  diagnostics = vscode.languages.createDiagnosticCollection('npm-script-lens');
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  status.command = 'npmScriptLens.focusPanel';
  tree = new InstallScriptsTree();
  view = vscode.window.createTreeView('npmScriptLens.packages', { treeDataProvider: tree });
  context.subscriptions.push(channel, diagnostics, status, view, lensChanged);

  const rerun = (doc) => {
    if (doc && TRACKED.has(path.basename(doc.uri.fsPath)) && !isVendored(doc.uri.fsPath)) schedule(projectDir(doc));
    refreshHooks(doc).catch((e) => channel.appendLine(`error: ${e.message}`));
  };

  // A lockfile change is the moment new install scripts arrive, and it is the
  // one the editor would otherwise miss entirely: `npm install` rewrites it
  // without any document of yours being saved.
  const watcher = vscode.workspace.createFileSystemWatcher(
    `**/{${core.LOCKFILES.map(([f]) => f).join(',')}}`);
  const onLock = (uri) => { if (!isVendored(uri.fsPath)) schedule(path.dirname(uri.fsPath)); };

  const cmd = (name, fn) => vscode.commands.registerCommand(name, fn);
  context.subscriptions.push(
    watcher,
    watcher.onDidChange(onLock), watcher.onDidCreate(onLock),
    vscode.languages.registerHoverProvider(SELECTOR, hovers),
    vscode.languages.registerCodeActionsProvider(SELECTOR, quickFixes,
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.languages.registerCodeLensProvider({ scheme: 'file', pattern: `**/${PKG}` }, lenses),
    vscode.workspace.onDidOpenTextDocument(rerun),
    vscode.workspace.onDidSaveTextDocument(rerun),
    vscode.workspace.onDidCloseTextDocument((d) => explanations.delete(d.uri.toString())),
    vscode.window.onDidChangeActiveTextEditor(() => { tree.refresh(); syncViews(); }),
    cmd('npmScriptLens.audit', () => {
      const doc = vscode.window.activeTextEditor && vscode.window.activeTextEditor.document;
      const cwd = (doc && TRACKED.has(path.basename(doc.uri.fsPath)) && projectDir(doc))
        || (tree.current() && tree.current().cwd) || workspaceDir(doc);
      if (cwd) schedule(cwd);
      else vscode.window.showWarningMessage('npm-script-lens: open a workspace folder first');
    }),
    cmd('npmScriptLens.decide', (arg) => decide(arg)),
    // The menu `when` clauses only offer these on a package row, but a
    // keybinding can invoke them on anything, including a group header.
    cmd('npmScriptLens.approve', (node) => decide(rowArg(node, true))),
    cmd('npmScriptLens.block', (node) => decide(rowArg(node, false))),
    cmd('npmScriptLens.approveAll', () => decideAll(true)),
    cmd('npmScriptLens.blockAll', () => decideAll(false)),
    cmd('npmScriptLens.reveal', (arg) => reveal(arg)),
    cmd('npmScriptLens.focusPanel', () => vscode.commands.executeCommand('npmScriptLens.packages.focus')),
    cmd('npmScriptLens.showLog', () => channel.show(true)),
    cmd('npmScriptLens.allowWrite', cliCommand('generate allowlist', () => ['allow', '--write'], { writes: true })),
    cmd('npmScriptLens.review', cliCommand('review', () => ['review'])),
    cmd('npmScriptLens.doctor', cliCommand('doctor', () => ['doctor'])),
    cmd('npmScriptLens.sync', cliCommand('sync allowlist', () => ['sync', '--write'], { writes: true })),
    cmd('npmScriptLens.sources', cliCommand('sources', () => ['sources'])),
    cmd('npmScriptLens.publish', cliCommand('publish readiness', () => ['publish'])),
    cmd('npmScriptLens.hooks', cliCommand('open-time hooks', () => ['hooks'], { wholeWorkspace: true })),
    cmd('npmScriptLens.hooksDeps', cliCommand('open-time hooks (dependency tarballs)', () => ['hooks', '--deps'], { wholeWorkspace: true })),
  );

  if (config().auditOnOpen) for (const doc of vscode.workspace.textDocuments) rerun(doc);

  // vscode.extensions.getExtension('booyaka101.npm-script-lens').exports
  // `treeProvider` is the panel itself, not a copy of its data, so anything
  // driving it (the integration test in e2e/) exercises the same
  // getChildren/getTreeItem path a user's clicks do.
  return { treeProvider: tree, audit: refreshProject };
}

function deactivate() {
  for (const t of pending.values()) clearTimeout(t);
  pending.clear();
  audits.clear();
  explanations.clear();
  if (diagnostics) diagnostics.clear();
}

module.exports = { activate, deactivate };
