'use strict';
// VS Code host for npm-script-lens. Thin UI over the CLI: it shells out to
// `npm-script-lens audit --json` and renders the results as inline diagnostics
// on package.json, a status-bar summary, and a few commands. All analysis
// lives in the CLI; the pure mapping lives in core.js (unit-tested).
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

function config() {
  const c = vscode.workspace.getConfiguration('npmScriptLens');
  return { command: c.get('command', 'npx npm-script-lens'), trust: c.get('trust', false) };
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

// Run a CLI subcommand in the workspace, resolving { code, stdout, stderr }.
function runCli(args, cwd) {
  const { command } = config();
  return new Promise((resolve) => {
    cp.exec(`${command} ${args.join(' ')}`, { cwd, maxBuffer: 32 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      resolve({ code: err ? (err.code || 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

// Audit the workspace and return { results, recommended } (or null on failure).
async function audit(cwd) {
  const { trust } = config();
  // --path pins the audit to this project. Without it the CLI defaults to the
  // cwd, and a cwd holding no lockfile now audits every project underneath.
  const args = ['audit', '--json', '--path', JSON.stringify(cwd)];
  if (!trust) args.push('--no-trust');
  const { stdout, stderr, code } = await runCli(args, cwd);
  const parsed = core.parseAudit(stdout);
  if (!parsed) {
    channel.appendLine(`audit failed (exit ${code}): ${stderr.trim() || stdout.trim() || 'no output'}`);
    return null;
  }
  return parsed;
}

const readIfPresent = (cwd, file) => {
  try { return fs.readFileSync(path.join(cwd, file), 'utf8'); } catch { return ''; }
};

// Re-audit the workspace that `doc` belongs to and repaint EVERY open allowlist
// file in it, not just the one that was touched. The two files are one
// decision surface: denying a package in pnpm-workspace.yaml clears its warning
// over in package.json, so refreshing only the saved document would leave the
// other one asserting something that is no longer true. One audit, all views.
async function refresh(doc) {
  if (!doc || !TRACKED.has(path.basename(doc.uri.fsPath))) return;
  const cwd = projectDir(doc);
  if (!cwd) return;
  const parsed = await audit(cwd);
  if (!parsed) return;
  const { results, recommended } = parsed;

  // Only the files of this project. Grouping by workspace root would repaint a
  // sibling package's package.json from these results.
  const open = new Map([[doc.uri.toString(), doc]]);
  for (const d of vscode.workspace.textDocuments) {
    if (TRACKED.has(path.basename(d.uri.fsPath)) && projectDir(d) === cwd) open.set(d.uri.toString(), d);
  }

  // Prefer the live buffer over disk, so an unsaved allowlist edit is reflected
  // as soon as anything triggers a refresh.
  const textOf = (file) => {
    for (const d of open.values()) if (path.basename(d.uri.fsPath) === file) return d.getText();
    return readIfPresent(cwd, file);
  };
  const opts = {
    recommended,
    decisions: core.readDecisions(textOf(PKG) || '{}', textOf(PNPM_WORKSPACE)),
  };

  for (const d of open.values()) {
    const text = d.getText();
    const found = path.basename(d.uri.fsPath) === PKG
      ? core.diagnosticsForPackageJson(text, results, opts)
      : core.diagnosticsForWorkspaceYaml(text, results, opts);
    diagnostics.set(d.uri, found.map((f) => {
      const diag = new vscode.Diagnostic(d.lineAt(f.line).range, f.message,
        SEVERITY[f.severity] || vscode.DiagnosticSeverity.Information);
      diag.source = 'npm-script-lens';
      return diag;
    }));
  }

  const sum = core.summarize(results, opts);
  status.text = `$(shield) ${sum.text}`;
  status.tooltip = sum.undecided
    ? `npm-script-lens: ${sum.undecided} install script(s) awaiting a decision; click to re-audit`
    : 'npm-script-lens: click to audit install scripts';
  status.show();
}

// Diagnostics on the open-time surfaces themselves. When a .vscode/tasks.json
// or .claude/settings.json is opened or saved, run `hooks --json` (CLI 1.8.0)
// and paint the findings on their real lines. Every open hooks file in the
// workspace repaints from the one scan, same discipline as refresh(). On a CLI
// too old to know `hooks`, parseHooks returns null and nothing is painted.
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
    const found = core.diagnosticsForHooksFile(rel, parsed.findings, parsed.partial);
    diagnostics.set(d.uri, found.map((f) => {
      const line = Math.min(f.line, d.lineCount - 1);
      const diag = new vscode.Diagnostic(d.lineAt(line).range, f.message,
        SEVERITY[f.severity] || vscode.DiagnosticSeverity.Information);
      diag.source = 'npm-script-lens';
      return diag;
    }));
  }
}

// Re-audit after a command that writes an allowlist: the CLI edits the file on
// disk, so onDidSaveTextDocument never fires and the diagnostics would still be
// demanding a decision that was just made. One document per project, since
// refresh() repaints the rest of that project but knows nothing of its siblings.
const refreshOpen = () => {
  const byProject = new Map();
  for (const d of vscode.workspace.textDocuments) {
    if (TRACKED.has(path.basename(d.uri.fsPath))) byProject.set(projectDir(d), d);
  }
  return Promise.all([...byProject.values()].map((d) => refresh(d).catch(() => {})));
};

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
    if (writes) await refreshOpen();
    vscode.window.showInformationMessage(`npm-script-lens: ${title} finished`);
  };
}

function activate(context) {
  channel = vscode.window.createOutputChannel('npm-script-lens');
  diagnostics = vscode.languages.createDiagnosticCollection('npm-script-lens');
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  status.command = 'npmScriptLens.audit';
  context.subscriptions.push(channel, diagnostics, status);

  const rerun = (doc) => {
    refresh(doc).catch((e) => channel.appendLine(`error: ${e.message}`));
    refreshHooks(doc).catch((e) => channel.appendLine(`error: ${e.message}`));
  };
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(rerun),
    vscode.workspace.onDidSaveTextDocument(rerun),
    vscode.commands.registerCommand('npmScriptLens.audit', () => {
      const doc = vscode.window.activeTextEditor && vscode.window.activeTextEditor.document;
      if (doc && TRACKED.has(path.basename(doc.uri.fsPath))) rerun(doc);
      else cliCommand('audit', () => ['audit'])();
    }),
    vscode.commands.registerCommand('npmScriptLens.allowWrite', cliCommand('generate allowlist', () => ['allow', '--write'], { writes: true })),
    vscode.commands.registerCommand('npmScriptLens.review', cliCommand('review', () => ['review'])),
    vscode.commands.registerCommand('npmScriptLens.doctor', cliCommand('doctor', () => ['doctor'])),
    vscode.commands.registerCommand('npmScriptLens.sync', cliCommand('sync allowlist', () => ['sync', '--write'], { writes: true })),
    vscode.commands.registerCommand('npmScriptLens.sources', cliCommand('sources', () => ['sources'])),
    vscode.commands.registerCommand('npmScriptLens.publish', cliCommand('publish readiness', () => ['publish'])),
    vscode.commands.registerCommand('npmScriptLens.hooks', cliCommand('open-time hooks', () => ['hooks'], { wholeWorkspace: true })),
    vscode.commands.registerCommand('npmScriptLens.hooksDeps', cliCommand('open-time hooks (dependency tarballs)', () => ['hooks', '--deps'], { wholeWorkspace: true })),
  );

  // audit any package.json already open at activation
  for (const doc of vscode.workspace.textDocuments) rerun(doc);
}

function deactivate() { if (diagnostics) diagnostics.clear(); }

module.exports = { activate, deactivate };
