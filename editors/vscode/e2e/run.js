'use strict';
// Launch the installed VS Code as an Extension Development Host and run
// suite.js inside it. This is the only way to check the panel, the hovers and
// the allowlist writes against the real API rather than against my reading of
// it: node --test can only reach core.js, which by design knows nothing about
// vscode.
//
//   node e2e/run.js [path-to-Code.exe]
//
// Uses the VS Code already on this machine rather than @vscode/test-electron,
// so it needs no devDependencies and no 120MB download. Exit code 0 means
// every check in suite.js passed.
const cp = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const extensionDevelopmentPath = path.resolve(__dirname, '..');
const extensionTestsPath = path.resolve(__dirname, 'suite.js');
const fixture = path.resolve(extensionDevelopmentPath, '../../fixtures/demo');

const CANDIDATES = [
  process.argv[2],
  process.env.VSCODE_PATH,
  path.join(os.homedir(), 'AppData/Local/Programs/Microsoft VS Code/Code.exe'),
  'C:/Program Files/Microsoft VS Code/Code.exe',
  '/usr/share/code/code',
  '/Applications/Visual Studio Code.app/Contents/MacOS/Electron',
].filter(Boolean);

const code = CANDIDATES.find((p) => fs.existsSync(p));
if (!code) {
  console.error(`VS Code not found. Looked in:\n  ${CANDIDATES.join('\n  ')}\nPass the path as argv[2].`);
  process.exit(2);
}

// A throwaway workspace, so the run never edits the committed fixture: the
// suite approves a package and asserts package.json changed.
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'nsl-vscode-'));
for (const file of ['package.json', 'package-lock.json']) {
  fs.copyFileSync(path.join(fixture, file), path.join(workspace, file));
}
// Fresh profile: the host must not inherit this machine's extensions or state.
const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsl-userdata-'));
const resultFile = path.join(workspace, 'result.json');

const args = [
  `--extensionDevelopmentPath=${extensionDevelopmentPath}`,
  `--extensionTestsPath=${extensionTestsPath}`,
  `--user-data-dir=${userDataDir}`,
  `--extensions-dir=${path.join(userDataDir, 'extensions')}`,
  '--disable-workspace-trust',
  '--disable-gpu',
  '--no-sandbox',
  '--skip-welcome',
  '--skip-release-notes',
  workspace,
];

console.log(`VS Code:   ${code}`);
console.log(`extension: ${extensionDevelopmentPath}`);
console.log(`workspace: ${workspace}\n`);

const child = cp.spawn(code, args, {
  env: { ...process.env, NSL_RESULT_FILE: resultFile, ELECTRON_ENABLE_LOGGING: '1' },
  stdio: 'inherit',
});

child.on('exit', (exitCode) => {
  let results = null;
  try { results = JSON.parse(fs.readFileSync(resultFile, 'utf8')); } catch { /* host died early */ }

  if (results) {
    console.log(`\n${'-'.repeat(60)}`);
    for (const c of results.checks) console.log(`  ok   ${c.name}`);
    if (results.diagnostic) console.log(`\n  squiggle: ${results.diagnostic}`);
    if (results.rows) {
      console.log('\n  panel rows:');
      for (const r of results.rows) console.log(`    ${r.label}  —  ${r.description}`);
    }
    if (results.groupsAfter) console.log(`\n  groups after approve: ${results.groupsAfter.join(' | ')}`);
    if (results.error) console.log(`\n  FAILED: ${results.error}`);
    console.log(`${'-'.repeat(60)}\n${results.ok ? 'PASS' : 'FAIL'}`);
  } else {
    console.log('\nno result file: the extension host exited before the suite wrote one');
  }

  fs.rmSync(userDataDir, { recursive: true, force: true });
  if (results && results.ok) fs.rmSync(workspace, { recursive: true, force: true });
  else console.log(`workspace kept for inspection: ${workspace}`);
  process.exit(results && results.ok ? 0 : (exitCode || 1));
});
