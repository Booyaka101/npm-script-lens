'use strict';
// Runs INSIDE a real VS Code extension host (see run.js). Everything here goes
// through the published API, so it exercises what a user's clicks exercise:
// the extension activating, the audit shelling out to the CLI, the panel's own
// TreeDataProvider building items, and Approve writing a real allowlist.
//
// No test framework on purpose. `extensionTestsPath` only needs a module with
// `run()`, and pulling mocha in would mean shipping node_modules to an
// extension that has none.
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');

const EXTENSION_ID = 'booyaka101.npm-script-lens';
const log = [];
const step = (msg) => { log.push(msg); console.log(`  ${msg}`); };

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// The audit is async and shells out, so every assertion about its result has
// to wait for it rather than assume a fixed delay.
async function until(what, predicate, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await predicate();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await wait(250);
  }
}

exports.run = async function run() {
  const workspace = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const pkgPath = path.join(workspace, 'package.json');
  const results = { workspace, checks: [] };
  const check = (name, fn) => {
    results.checks.push({ name, ok: true });
    step(`ok  ${name}`);
    return fn;
  };

  try {
    // --- activation ---------------------------------------------------------
    const ext = vscode.extensions.getExtension(EXTENSION_ID);
    assert.ok(ext, `extension ${EXTENSION_ID} not found`);
    const api = await ext.activate();
    assert.ok(api && api.treeProvider, 'activate() did not return the panel provider');
    check('extension activates and exposes the panel provider');

    // Point at the CLI in this repo instead of npx, and keep the audit offline
    // by leaving trust off: the fixture's tarballs are already cached.
    const cliPath = path.resolve(__dirname, '../../../src/cli.js');
    assert.ok(fs.existsSync(cliPath), `CLI not found at ${cliPath}`);
    const cfg = vscode.workspace.getConfiguration('npmScriptLens');
    await cfg.update('command', `node "${cliPath}"`, vscode.ConfigurationTarget.Workspace);
    await cfg.update('trust', false, vscode.ConfigurationTarget.Workspace);
    check('configured to run the local CLI');

    // --- the view is really registered --------------------------------------
    // An unknown view id makes this reject, which is the only way to tell from
    // in here that the container and view in package.json actually took.
    await vscode.commands.executeCommand('npmScriptLens.packages.focus');
    check('Install scripts view exists and can be focused');

    // --- audit --------------------------------------------------------------
    const doc = await vscode.workspace.openTextDocument(pkgPath);
    await vscode.window.showTextDocument(doc);
    await vscode.commands.executeCommand('npmScriptLens.audit');

    const tree = api.treeProvider;
    const groups = await until('the audit to populate the panel', async () => {
      const g = await tree.getChildren();
      return g && g.length ? g : null;
    });
    results.groups = groups.map((n) => n.item.label);
    check(`panel shows ${groups.length} group(s): ${results.groups.join(' | ')}`);

    const undecided = groups.find((n) => n.group.id === 'decide');
    assert.ok(undecided, `no "Needs a decision" group; got ${results.groups.join(', ')}`);
    assert.ok(/^Needs a decision \(\d+\)$/.test(undecided.item.label), `unexpected label ${undecided.item.label}`);
    assert.strictEqual(undecided.item.collapsibleState, vscode.TreeItemCollapsibleState.Expanded,
      'the group that needs action must not start collapsed');

    // --- the rows -----------------------------------------------------------
    const rows = await tree.getChildren(undecided);
    assert.ok(rows.length > 0, 'the group is empty');
    results.rows = rows.map((n) => ({
      label: n.item.label,
      description: n.item.description,
      contextValue: n.item.contextValue,
      command: n.item.command && n.item.command.command,
      tooltip: String(n.item.tooltip && n.item.tooltip.value || '').slice(0, 120),
    }));
    for (const row of rows) {
      assert.ok(/@/.test(row.item.label), `row label is not name@version: ${row.item.label}`);
      assert.ok(row.item.description, `row ${row.item.label} has no plain-English description`);
      assert.strictEqual(row.item.contextValue, 'pkg:decide');
      assert.strictEqual(row.item.command.command, 'npmScriptLens.reveal');
      assert.ok(row.item.tooltip instanceof vscode.MarkdownString, 'the hover detail is not markdown');
      assert.ok(row.item.tooltip.value.includes('**What to do**'), 'the tooltip does not end in an action');
    }
    check(`${rows.length} rows, each with a description, a tooltip and approve/block context`);

    // --- diagnostics on the file --------------------------------------------
    const diags = await until('diagnostics on package.json',
      async () => { const d = vscode.languages.getDiagnostics(doc.uri); return d.length ? d : null; });
    const mine = diags.filter((d) => d.source === 'npm-script-lens');
    assert.ok(mine.length > 0, 'no npm-script-lens diagnostics');
    results.diagnostic = mine[0].message;
    assert.ok(/runs code when you install it/.test(mine[0].message), `unexpected message: ${mine[0].message}`);
    assert.ok(!/·\s*(exec|env|fs|net):/.test(mine[0].message), 'raw analyzer signals leaked into the squiggle');
    check(`${mine.length} diagnostics, in plain English`);

    // --- the hover ----------------------------------------------------------
    const hovers = await vscode.commands.executeCommand('vscode.executeHoverProvider', doc.uri, mine[0].range.start);
    const ours = hovers.flatMap((h) => h.contents.map((c) => c.value || ''))
      .find((v) => v.includes('command:npmScriptLens.decide'));
    assert.ok(ours, 'no hover carrying the per-package decide buttons');
    assert.ok(/→ `[^`]+`/.test(ours), 'the hover does not show the install command');
    assert.ok(/\n- \w/.test(ours), 'the hover has no capability list');
    // The buttons have to be reachable without scrolling a capped hover, which
    // in practice means early and in a short block.
    const lines = ours.split('\n');
    const buttonLine = lines.findIndex((l) => l.includes('command:npmScriptLens.decide'));
    assert.ok(buttonLine >= 0 && buttonLine <= 10, `decide buttons are on line ${buttonLine} of the hover`);
    assert.ok(lines.length <= 18, `hover is ${lines.length} lines; it will be clipped`);
    results.hover = ours;
    check(`hover: command + capabilities, buttons on line ${buttonLine} of ${lines.length}`);

    // --- approving from the panel actually writes the allowlist -------------
    const target = rows[0];
    const key = target.item.label;
    const before = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    assert.ok(!before.allowScripts, 'fixture already had an allowScripts block');

    await vscode.commands.executeCommand('npmScriptLens.approve', target);
    await until('package.json to gain the decision', async () => {
      const after = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      return after.allowScripts && after.allowScripts[key] === true;
    });
    const writtenText = fs.readFileSync(pkgPath, 'utf8');
    results.written = JSON.parse(writtenText).allowScripts;
    assert.ok(!writtenText.includes('\r\n'), 'the edit converted an LF manifest to CRLF');
    check(`approve wrote allowScripts["${key}"] = true to the real file, endings intact`);

    // ...and the panel agrees on the next pass
    const moved = await until(`${key} to leave the undecided group`, async () => {
      const g = await tree.getChildren();
      const still = g.find((n) => n.group.id === 'decide');
      if (still && (await tree.getChildren(still)).some((n) => n.item.label === key)) return null;
      return g;
    });
    results.groupsAfter = moved.map((n) => n.item.label);
    const settled = moved.find((n) => ['settled', 'override'].includes(n.group.id));
    assert.ok(settled, `approved package did not land in a decided group; got ${results.groupsAfter.join(', ')}`);
    const settledRows = await tree.getChildren(settled);
    assert.ok(settledRows.some((n) => n.item.label === key), `${key} is not in ${settled.item.label}`);
    check(`panel re-grouped it under "${settled.item.label}" after the write`);

    // --- undo: it was a real editor edit ------------------------------------
    const opened = await vscode.workspace.openTextDocument(pkgPath);
    await vscode.window.showTextDocument(opened);
    await vscode.commands.executeCommand('undo');
    assert.ok(!JSON.parse(opened.getText()).allowScripts, 'the decision was not undoable');
    check('the decision is a normal undoable editor edit');
    await opened.save();

    // --- Ctrl+. on the squiggle ---------------------------------------------
    const actions = await vscode.commands.executeCommand('vscode.executeCodeActionProvider', doc.uri, mine[0].range);
    const titles = actions.map((a) => a.title);
    results.codeActions = titles;
    const approveTitle = titles.find((t) => t.startsWith('Approve '));
    const blockTitle = titles.find((t) => t.startsWith('Block '));
    assert.ok(approveTitle && blockTitle, `no per-package quick fixes; got ${titles.join(' | ')}`);
    assert.ok(!actions.some((a) => a.isPreferred),
      'a preferred action would put "approve arbitrary install code" on Auto Fix');
    check(`quick fixes offered: ${titles.join(' · ')}`);

    // Blocking through the quick fix has to record `false`, not just drop the
    // entry: an absent name is undecided, and would be asked again tomorrow.
    const blocker = actions.find((a) => a.title === blockTitle);
    await vscode.commands.executeCommand(blocker.command.command, ...blocker.command.arguments);
    const blockedKey = blockTitle.replace('Block ', '');
    await until(`${blockedKey} to be recorded as blocked`, async () => {
      const after = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      return after.allowScripts && after.allowScripts[blockedKey] === false;
    });
    check(`quick fix recorded allowScripts["${blockedKey}"] = false`);

    // A blocked package stops being a diagnostic: the script never runs, so
    // there is nothing left to warn about.
    await until('the blocked package to lose its squiggle', async () => {
      const still = vscode.languages.getDiagnostics(doc.uri)
        .some((d) => d.source === 'npm-script-lens' && d.message.startsWith(blockedKey));
      return !still;
    });
    check('blocking clears the warning it was answering');

    // --- the CodeLens over the dependency block -----------------------------
    const codeLenses = await until('a CodeLens on package.json', async () => {
      const l = await vscode.commands.executeCommand('vscode.executeCodeLensProvider', doc.uri);
      return l && l.length ? l : null;
    });
    const lens = codeLenses.find((l) => l.command && /install scripts/.test(l.command.title));
    assert.ok(lens, `no npm-script-lens CodeLens; got ${codeLenses.map((l) => l.command && l.command.title).join(' | ')}`);
    results.codeLens = lens.command.title;
    check(`CodeLens reads "${lens.command.title.replace(/\$\([a-z-]+\)\s*/, '')}"`);

    // --- the lockfile watcher -----------------------------------------------
    // `npm install` rewrites the lockfile without saving any document of yours,
    // so this is the one refresh trigger nothing else can stand in for. Write a
    // decision straight to disk (no save event fires for that) and touch the
    // lockfile: only the watcher can bring the panel back in sync.
    const onDisk = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    const sneaky = rows.find((n) => n.item.label !== blockedKey).item.label;
    onDisk.allowScripts = { ...onDisk.allowScripts, [sneaky]: true };
    fs.writeFileSync(pkgPath, `${JSON.stringify(onDisk, null, 2)}\n`);

    const lockPath = path.join(workspace, 'package-lock.json');
    fs.writeFileSync(lockPath, fs.readFileSync(lockPath, 'utf8'));
    await until(`the watcher to re-audit after the lockfile changed`, async () => {
      const g = await tree.getChildren();
      const undec = g.find((n) => n.group.id === 'decide');
      if (!undec) return g;
      const names = (await tree.getChildren(undec)).map((n) => n.item.label);
      return names.includes(sneaky) ? null : g;
    });
    check(`lockfile change re-audited the project (${sneaky} picked up without a save)`);

    // --- a dependency's own package.json is not a project -------------------
    // Every package under node_modules ships one, and each would otherwise
    // queue a CLI run about a package the reader does not own.
    const vendored = path.join(workspace, 'node_modules', 'left-pad');
    fs.mkdirSync(vendored, { recursive: true });
    fs.writeFileSync(path.join(vendored, 'package.json'), '{\n  "name": "left-pad"\n}\n');
    const auditedBefore = (await tree.getChildren()).length;
    await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(path.join(vendored, 'package.json')));
    await wait(2000);
    assert.ok(!fs.existsSync(path.join(vendored, 'allowScripts')), 'sanity');
    assert.strictEqual((await tree.getChildren()).length, auditedBefore,
      'opening a vendored package.json audited it as its own project');
    await vscode.window.showTextDocument(doc);
    check('opening a package.json under node_modules does not audit it');

    // --- pnpm: the allowlist file may not exist yet -------------------------
    // The only decision path that has to CREATE a file rather than edit one.
    const pnpmDir = path.join(workspace, 'pnpm-project');
    fs.mkdirSync(pnpmDir, { recursive: true });
    fs.writeFileSync(path.join(pnpmDir, 'package.json'), '{\n  "name": "p"\n}\n');
    fs.writeFileSync(path.join(pnpmDir, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n");
    const wsFile = path.join(pnpmDir, 'pnpm-workspace.yaml');
    assert.ok(!fs.existsSync(wsFile), 'fixture already had a pnpm-workspace.yaml');

    await vscode.commands.executeCommand('npmScriptLens.decide',
      { cwd: pnpmDir, name: 'sharp', version: '0.33.5', allow: true });
    await until('pnpm-workspace.yaml to be created', async () => fs.existsSync(wsFile));
    results.pnpmWorkspace = fs.readFileSync(wsFile, 'utf8');
    // Byte-exact, line endings included. A file VS Code creates would otherwise
    // pick up the platform default (CRLF on Windows) while the CLI writes LF,
    // and the same allowlist would be spelled two ways.
    assert.strictEqual(results.pnpmWorkspace, 'allowBuilds:\n  sharp: true\n');
    // ...and it went to pnpm's file, not package.json, because a lockfile said so
    assert.ok(!JSON.parse(fs.readFileSync(path.join(pnpmDir, 'package.json'), 'utf8')).allowScripts,
      'a pnpm decision leaked into package.json');
    check('a pnpm decision creates pnpm-workspace.yaml with the right block');

    results.ok = true;
  } catch (err) {
    results.ok = false;
    results.error = `${err.message}\n${err.stack}`;
    console.log(`  FAIL ${err.message}`);
  }

  fs.writeFileSync(process.env.NSL_RESULT_FILE, JSON.stringify(results, null, 2));
  if (!results.ok) throw new Error(results.error);
};
