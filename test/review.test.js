'use strict';
const http = require('node:http');
const zlib = require('node:zlib');
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const tar = require('tar-stream');
const { parseDryRun, isCovered } = require('../src/review');
const { commandEntryFiles } = require('../src/analyzer');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
let server, tmp, fakeNpm12, failNpm, coveredNpm12;

function makeTgz(entries) {
  return new Promise((resolve, reject) => {
    const pack = tar.pack();
    for (const [name, content] of Object.entries(entries)) pack.entry({ name }, content);
    pack.finalize();
    const gz = zlib.createGzip();
    const chunks = [];
    pack.pipe(gz);
    gz.on('data', (c) => chunks.push(c));
    gz.on('end', () => resolve(Buffer.concat(chunks)));
    gz.on('error', reject);
  });
}

function runCli(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd: ROOT, timeout: 60000, env: { ...process.env, ...env } });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdin.end();
    child.on('exit', (status) => resolve({ status, stdout, stderr }));
  });
}

const writeProj = (name, packages, pkgJson = { name: 'proj', version: '1.0.0' }) => {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  if (packages) {
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { name: 'proj', version: '1.0.0' }, ...packages },
    }, null, 2));
  }
  fs.writeFileSync(path.join(dir, 'package.json'), `${JSON.stringify(pkgJson, null, 2)}\n`);
  return dir;
};

// 45-line install script: 43 comment lines then a child_process.exec, HIGH,
// and long enough to prove the 40-line display cap.
const LONG_INSTALL = [...Array.from({ length: 43 }, (_, i) => `// filler line ${i + 1}`),
  "require('child_process').exec('echo built');", ''].join('\n');

before(async () => {
  const tarballs = {
    '/scripted.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'node scripts/install.js' } }),
      'package/scripts/install.js': LONG_INSTALL,
    }),
    '/lowpkg.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'node l.js' } }),
      'package/l.js': 'const v = process.env.HOME;\n',
    }),
    '/evilpkg.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'node x.js' } }),
      'package/x.js': 'console.log("hello");\n',
    }),
  };
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const port = server.address().port;
      if (tarballs[req.url]) return res.writeHead(200).end(tarballs[req.url]);
      if (req.url === '/v1/querybatch') {
        const queries = JSON.parse(body).queries;
        return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
          results: queries.map((q) => (q.package.name === 'evilpkg' && q.version === '1.0.0'
            ? { vulns: [{ id: 'MAL-2026-9999' }] } : {})),
        }));
      }
      const doc = {
        '/scripted/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node scripts/install.js' },
          dist: { tarball: `http://127.0.0.1:${port}/scripted.tgz` } },
        '/lowpkg/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node l.js' },
          dist: { tarball: `http://127.0.0.1:${port}/lowpkg.tgz` } },
        '/evilpkg/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node x.js' },
          dist: { tarball: `http://127.0.0.1:${port}/evilpkg.tgz` } },
        '/cleanpkg/1.0.0': { version: '1.0.0', scripts: {} },
      }[req.url];
      if (!doc) return res.writeHead(404).end('{}');
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(doc));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  process.env.NPM_SCRIPT_LENS_REGISTRY = base;
  process.env.NPM_SCRIPT_LENS_OSV_API = base;
  process.env.NPM_SCRIPT_LENS_DL_API = base;
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-review-'));
  process.env.NPM_SCRIPT_LENS_CACHE_DIR = path.join(tmp, 'cache');
  // Stub npms: one speaks npm v12's dialect (--version probe, then human
  // noise + JSON with unreviewedScripts), one fails like a broken/ancient npm.
  fakeNpm12 = path.join(tmp, 'fake-npm12.js');
  fs.writeFileSync(fakeNpm12, `
    if (process.argv.includes('--version')) { console.log('12.0.1'); process.exit(0); }
    console.log('add scripted 1.0.0');
    console.log('add evilpkg 1.0.0');
    console.log(JSON.stringify({ added: 2, audited: 0, unreviewedScripts: [
      { name: 'scripted', version: '1.0.0', path: '/x/scripted', scripts: { postinstall: 'node scripts/install.js' } },
      { name: 'evilpkg', version: '1.0.0', path: '/x/evilpkg', scripts: { postinstall: 'node x.js' } },
    ] }, null, 2));
  `);
  failNpm = path.join(tmp, 'fail-npm.js');
  fs.writeFileSync(failNpm, 'process.exit(7);\n');
  // npm v12 with everything covered: OMITS the unreviewedScripts key entirely
  // (verified against npm 12.0.1), must read as "nothing pending", not as
  // "cannot answer".
  coveredNpm12 = path.join(tmp, 'covered-npm12.js');
  fs.writeFileSync(coveredNpm12, `
    if (process.argv.includes('--version')) { console.log('12.0.1'); process.exit(0); }
    console.log('add scripted 1.0.0');
    console.log(JSON.stringify({ added: 1, audited: 0, changed: 0 }, null, 2));
  `);
});

after(() => server.close());

test('parseDryRun extracts unreviewedScripts from noisy npm v12 output', () => {
  const noisy = ['add sharp 0.33.5', 'add color 4.2.3', JSON.stringify({
    added: 10, unreviewedScripts: [{ name: 'sharp', version: '0.33.5', path: 'x', scripts: { install: 'node install/check' } }],
  }, null, 2)].join('\n');
  assert.deepStrictEqual(parseDryRun(noisy), [{ name: 'sharp', version: '0.33.5', scripts: { install: 'node install/check' } }]);
  // nothing pending: explicit empty array, or a successful summary omitting
  // the key entirely (npm 12.0.1's actual behavior when all covered)
  assert.deepStrictEqual(parseDryRun('{"added":0,"unreviewedScripts":[]}'), []);
  assert.deepStrictEqual(parseDryRun('add sharp 0.33.5\n{"added":10,"audited":0,"removed":0}'), []);
  // errors and garbage are not an answer
  assert.strictEqual(parseDryRun('{"error":{"code":"ENETDOWN"}}'), null);
  assert.strictEqual(parseDryRun('npm ERR! network refused'), null);
  assert.strictEqual(parseDryRun(''), null);
});

test('isCovered accepts bare, pinned, and false-valued allowScripts keys', () => {
  assert.ok(isCovered({ sharp: true }, 'sharp', '0.33.5'));
  assert.ok(isCovered({ 'sharp@0.33.5': false }, 'sharp', '0.33.5'));
  assert.ok(!isCovered({ 'sharp@0.33.4': true }, 'sharp', '0.33.5'));
  assert.ok(!isCovered({}, 'sharp', '0.33.5'));
});

test('commandEntryFiles resolves the file a script command runs', () => {
  const files = new Map([['scripts/install.js', 'x'], ['l.js', 'y']]);
  assert.deepStrictEqual(commandEntryFiles('node scripts/install.js', files), ['scripts/install.js']);
  assert.deepStrictEqual(commandEntryFiles('FOO=1 node ./l.js --flag', files), ['l.js']);
  assert.deepStrictEqual(commandEntryFiles('node -e "process.exit(0)"', files), []);
  assert.deepStrictEqual(commandEntryFiles('node-gyp rebuild', files), []);
});

test('review via npm v12 dry-run: content + OSV verdict, no lockfile needed', async () => {
  const dir = writeProj('npm12proj', null); // package.json only, no lockfile
  const out = await runCli(['review', '--path', dir], { NPM_SCRIPT_LENS_NPM: `node ${fakeNpm12}` });
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stdout.includes('source: npm install --dry-run --json'), out.stdout);
  assert.ok(out.stdout.includes('── scripted@1.0.0'), out.stdout);
  assert.ok(out.stdout.includes('postinstall: node scripts/install.js'));
  // the content npm's own pending list cannot show, capped at 40 lines
  assert.ok(out.stdout.includes('┌─ scripts/install.js (first 40 of 45 lines)'), out.stdout);
  assert.ok(out.stdout.includes('// filler line 40'));
  assert.ok(!out.stdout.includes('// filler line 41'), 'display cap at 40 lines');
  // behavioral verdict from the existing scanner + OSV verdicts
  assert.ok(out.stdout.includes('🔴 HIGH'));
  assert.ok(out.stdout.includes('OSV: no known malicious advisories'));
  assert.ok(out.stdout.includes('⛔ KNOWN MALICIOUS: MAL-2026-9999'), out.stdout);
  // suggested block: HIGH and malicious default to false
  const block = JSON.parse(out.stdout.match(/\{[\s\S]*"allowScripts"[\s\S]*?\n\}/)[0]);
  assert.strictEqual(block.allowScripts['scripted@1.0.0'], false);
  assert.strictEqual(block.allowScripts['evilpkg@1.0.0'], false);
});

test('review falls back to lockfile + allowScripts when npm cannot answer', async () => {
  const dir = writeProj('fallbackproj', {
    'node_modules/scripted': { version: '1.0.0' },
    'node_modules/lowpkg': { version: '1.0.0' },
    'node_modules/cleanpkg': { version: '1.0.0' },
  });
  const out = await runCli(['review', '--path', dir], { NPM_SCRIPT_LENS_NPM: `node ${failNpm}` });
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stdout.includes('source: lockfile + allowScripts'), out.stdout);
  assert.ok(out.stdout.includes('── scripted@1.0.0'));
  assert.ok(out.stdout.includes('── lowpkg@1.0.0'));
  assert.ok(!out.stdout.includes('cleanpkg'), 'packages without install scripts are not pending');
  assert.ok(out.stdout.includes('┌─ scripts/install.js (first 40 of 45 lines)'));
  assert.ok(out.stdout.includes('┌─ l.js'));
});

test('review reads npm v12 output without unreviewedScripts as nothing pending', async () => {
  const dir = writeProj('allcovered', null); // no lockfile, npm's answer is the only source
  const out = await runCli(['review', '--path', dir], { NPM_SCRIPT_LENS_NPM: `node ${coveredNpm12}` });
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stdout.includes('🟢 nothing pending'), out.stdout);
});

test('review honors existing allowScripts decisions in fallback mode', async () => {
  const dir = writeProj('coveredproj', {
    'node_modules/scripted': { version: '1.0.0' },
  }, { name: 'proj', version: '1.0.0', allowScripts: { 'scripted@1.0.0': false } });
  const out = await runCli(['review', '--path', dir], { NPM_SCRIPT_LENS_NPM: `node ${failNpm}` });
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stdout.includes('🟢 nothing pending'), out.stdout);
});

test('review --output-allowscripts merges decisions into package.json', async () => {
  const dir = writeProj('writeproj', {
    'node_modules/scripted': { version: '1.0.0' },
    'node_modules/lowpkg': { version: '1.0.0' },
  }, { name: 'proj', version: '1.0.0', allowScripts: { 'keepme@2.0.0': true } });
  const out = await runCli(['review', '--path', dir, '--output-allowscripts'], { NPM_SCRIPT_LENS_NPM: `node ${failNpm}` });
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(out.stderr.includes('wrote 2 allowScripts entries'), out.stderr);
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  assert.strictEqual(pkg.allowScripts['keepme@2.0.0'], true, 'existing entries preserved');
  assert.strictEqual(pkg.allowScripts['scripted@1.0.0'], false, 'HIGH defaults to false');
  assert.strictEqual(pkg.allowScripts['lowpkg@1.0.0'], true, 'LOW defaults to true');
});

test('review --json carries risk, content, and the allowScripts block', async () => {
  const dir = writeProj('jsonproj', {
    'node_modules/scripted': { version: '1.0.0' },
  });
  const out = await runCli(['review', '--path', dir, '--json'], { NPM_SCRIPT_LENS_NPM: `node ${failNpm}` });
  assert.strictEqual(out.status, 0, out.stderr);
  const j = JSON.parse(out.stdout);
  assert.ok(j.source.startsWith('lockfile'));
  assert.strictEqual(j.pending.length, 1);
  assert.strictEqual(j.pending[0].name, 'scripted');
  assert.strictEqual(j.pending[0].risk, 'HIGH');
  const content = j.pending[0].content.find((c) => c.file === 'scripts/install.js');
  assert.strictEqual(content.totalLines, 45);
  assert.strictEqual(content.lines.length, 40);
  assert.strictEqual(j.allowScripts['scripted@1.0.0'], false);
});

test('review with no lockfile and no npm v12 is a clean error', async () => {
  const dir = writeProj('nolockproj', null);
  const out = await runCli(['review', '--path', dir], { NPM_SCRIPT_LENS_NPM: `node ${failNpm}` });
  assert.strictEqual(out.status, 2);
  assert.ok(out.stderr.includes('no lockfile found'), out.stderr);
});
