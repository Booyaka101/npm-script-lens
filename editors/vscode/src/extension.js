'use strict';
// VS Code host for npm-script-lens. Thin UI over the CLI: it shells out to
// `npm-script-lens audit --json` and renders the results as inline diagnostics
// on package.json, a status-bar summary, and a few commands. All analysis
// lives in the CLI; the pure mapping lives in core.js (unit-tested).
const vscode = require('vscode');
const cp = require('node:child_process');
const path = require('node:path');
const core = require('./core');

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

// Run a CLI subcommand in the workspace, resolving { code, stdout, stderr }.
function runCli(args, cwd) {
  const { command } = config();
  return new Promise((resolve) => {
    cp.exec(`${command} ${args.join(' ')}`, { cwd, maxBuffer: 32 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      resolve({ code: err ? (err.code || 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

// Audit the workspace and return the results array (or null on failure).
async function audit(cwd) {
  const { trust } = config();
  const args = ['audit', '--json'];
  if (!trust) args.push('--no-trust');
  const { stdout, stderr, code } = await runCli(args, cwd);
  const results = core.parseAuditJson(stdout);
  if (!results) {
    channel.appendLine(`audit failed (exit ${code}): ${stderr.trim() || stdout.trim() || 'no output'}`);
    return null;
  }
  return results;
}

// Refresh diagnostics for a package.json document.
async function refresh(doc) {
  if (!doc || path.basename(doc.uri.fsPath) !== 'package.json') return;
  const cwd = workspaceDir(doc);
  if (!cwd) return;
  const results = await audit(cwd);
  if (!results) return;
  const text = doc.getText();
  const items = core.diagnosticsForPackageJson(text, results).map((d) => {
    const range = doc.lineAt(d.line).range;
    const diag = new vscode.Diagnostic(range, d.message, SEVERITY[d.severity] || vscode.DiagnosticSeverity.Information);
    diag.source = 'npm-script-lens';
    return diag;
  });
  diagnostics.set(doc.uri, items);
  const sum = core.summarize(results);
  status.text = `$(shield) ${sum.text}`;
  status.tooltip = 'npm-script-lens — click to audit install scripts';
  status.show();
}

// A command that streams CLI output to the output channel.
function cliCommand(title, argsFn) {
  return async () => {
    const cwd = workspaceDir(vscode.window.activeTextEditor && vscode.window.activeTextEditor.document);
    if (!cwd) { vscode.window.showWarningMessage('npm-script-lens: open a workspace folder first'); return; }
    channel.show(true);
    channel.appendLine(`\n$ ${config().command} ${argsFn().join(' ')}  (in ${cwd})`);
    const { stdout, stderr } = await runCli(argsFn(), cwd);
    if (stdout) channel.appendLine(stdout.trimEnd());
    if (stderr) channel.appendLine(stderr.trimEnd());
    vscode.window.showInformationMessage(`npm-script-lens: ${title} finished`);
  };
}

function activate(context) {
  channel = vscode.window.createOutputChannel('npm-script-lens');
  diagnostics = vscode.languages.createDiagnosticCollection('npm-script-lens');
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  status.command = 'npmScriptLens.audit';
  context.subscriptions.push(channel, diagnostics, status);

  const rerun = (doc) => { refresh(doc).catch((e) => channel.appendLine(`error: ${e.message}`)); };
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(rerun),
    vscode.workspace.onDidSaveTextDocument(rerun),
    vscode.commands.registerCommand('npmScriptLens.audit', () => {
      const doc = vscode.window.activeTextEditor && vscode.window.activeTextEditor.document;
      if (doc && path.basename(doc.uri.fsPath) === 'package.json') rerun(doc);
      else cliCommand('audit', () => ['audit'])();
    }),
    vscode.commands.registerCommand('npmScriptLens.allowWrite', cliCommand('generate allowlist', () => ['allow', '--write'])),
    vscode.commands.registerCommand('npmScriptLens.review', cliCommand('review', () => ['review'])),
    vscode.commands.registerCommand('npmScriptLens.doctor', cliCommand('doctor', () => ['doctor'])),
  );

  // audit any package.json already open at activation
  for (const doc of vscode.workspace.textDocuments) rerun(doc);
}

function deactivate() { if (diagnostics) diagnostics.clear(); }

module.exports = { activate, deactivate };
