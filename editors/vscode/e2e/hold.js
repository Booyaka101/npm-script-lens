'use strict';
// Same launch path as suite.js, but instead of asserting and exiting it sets
// the window up the way a user would see it (panel open, package.json in the
// editor, a hover showing) and holds it there so the window can be looked at
// or screenshotted. Used by shot.ps1; not part of any automated run.
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');

const HOLD_MS = Number(process.env.NSL_HOLD_MS || 45000);

exports.run = async function run() {
  const ext = vscode.extensions.getExtension('booyaka101.npm-script-lens');
  const api = await ext.activate();

  const cliPath = path.resolve(__dirname, '../../../src/cli.js');
  const cfg = vscode.workspace.getConfiguration('npmScriptLens');
  await cfg.update('command', `node "${cliPath}"`, vscode.ConfigurationTarget.Workspace);
  await cfg.update('trust', false, vscode.ConfigurationTarget.Workspace);

  const workspace = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const doc = await vscode.workspace.openTextDocument(path.join(workspace, 'package.json'));
  const editor = await vscode.window.showTextDocument(doc);

  await vscode.commands.executeCommand('npmScriptLens.audit');
  for (let i = 0; i < 120; i++) {
    const groups = await api.treeProvider.getChildren();
    if (groups && groups.length) break;
    await new Promise((r) => setTimeout(r, 250));
  }
  await vscode.commands.executeCommand('npmScriptLens.packages.focus');

  // Park the cursor on a flagged line and pop the hover, so the screenshot
  // shows the thing this release rewrote.
  const flagged = vscode.languages.getDiagnostics(doc.uri).filter((d) => d.source === 'npm-script-lens');
  if (flagged.length) {
    const at = flagged[0].range.start;
    editor.selection = new vscode.Selection(at, at);
    editor.revealRange(flagged[0].range, vscode.TextEditorRevealType.InCenter);
    await vscode.commands.executeCommand('editor.action.showHover');
  }

  if (process.env.NSL_RESULT_FILE) fs.writeFileSync(process.env.NSL_RESULT_FILE, JSON.stringify({ ok: true, held: HOLD_MS }));
  await new Promise((r) => setTimeout(r, HOLD_MS));
};
