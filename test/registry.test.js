'use strict';
const http = require('node:http');
const zlib = require('node:zlib');
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const tar = require('tar-stream');

let server;
const requests = [];

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

before(async () => {
  const tarballs = {
    '/mock-gyp.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ name: 'mock-gyp', version: '1.0.0' }),
      'package/binding.gyp': '{ "targets": [] }',
    }),
    '/override.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ scripts: { postinstall: 'node real.js' } }),
      'package/real.js': 'require("https").get("https://x.io");',
    }),
    '/shebang.tgz': await makeTgz({
      'package/package.json': JSON.stringify({ name: 'shebang', bin: { tool: 'bin/tool' } }),
      'package/bin/tool': '#!/usr/bin/env node\nrequire("../lib/run.js");\n',
      'package/bin/crc.njs': '#!/usr/bin/env node\n',
      'package/logo.png': '\x89PNG',
      'package/LICENSE': 'MIT',
      'package/dist/huge.js': 'x'.repeat(2 * 1024 * 1024 + 1),
    }),
  };
  server = http.createServer((req, res) => {
    requests.push(req.url);
    const port = server.address().port;
    if (tarballs[req.url]) return res.writeHead(200).end(tarballs[req.url]);
    if (req.url.startsWith('/limited')) {
      const hits = requests.filter((u) => u === req.url).length;
      if (req.url === '/limited-always/1.0.0' || hits === 1) return res.writeHead(429, { 'retry-after': '0' }).end('{}');
      return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ version: '1.0.0', scripts: {} }));
    }
    const doc = {
      '/mock-gyp/1.0.0': { version: '1.0.0', scripts: {}, hasInstallScript: true,
        dist: { tarball: `http://127.0.0.1:${port}/mock-gyp.tgz` } },
      '/clean-pkg/1.0.0': { version: '1.0.0', scripts: { test: 'jest' },
        dist: { tarball: `http://127.0.0.1:${port}/never-fetched.tgz` } },
      '/override/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node registry-copy.js' },
        dist: { tarball: `http://127.0.0.1:${port}/override.tgz` } },
      '/shebang/1.0.0': { version: '1.0.0', scripts: {}, dist: { tarball: `http://127.0.0.1:${port}/shebang.tgz` } },
    }[req.url];
    if (!doc) return res.writeHead(404).end('{}');
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(doc));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  process.env.NPM_SCRIPT_LENS_REGISTRY = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

test('implicit node-gyp build is synthesized and scores HIGH', async () => {
  const { fetchPackage } = require('../src/registry');
  const { analyzePackage } = require('../src/analyzer');
  const pkg = await fetchPackage('mock-gyp', '1.0.0');
  assert.strictEqual(pkg.implicitGyp, true);
  assert.strictEqual(pkg.scripts.install, 'node-gyp rebuild');
  const row = analyzePackage(pkg)[0];
  assert.strictEqual(row.risk, 'HIGH');
  assert.ok(row.signals.some((s) => s.includes('exec: node-gyp rebuild')));
});

test('packages without install-time scripts skip the tarball download', async () => {
  const { fetchPackage } = require('../src/registry');
  const pkg = await fetchPackage('clean-pkg', '1.0.0');
  assert.deepStrictEqual(pkg.scripts, {});
  assert.strictEqual(pkg.files.size, 0);
  assert.ok(!requests.includes('/never-fetched.tgz'), 'tarball must not be requested');
});

test('tarball package.json overrides the registry script copy', async () => {
  const { fetchPackage } = require('../src/registry');
  const { analyzePackage } = require('../src/analyzer');
  const pkg = await fetchPackage('override', '1.0.0');
  assert.strictEqual(pkg.scripts.postinstall, 'node real.js');
  assert.strictEqual(analyzePackage(pkg)[0].risk, 'MEDIUM');
});

test('a 429 is retried once, then named as a rate limit', async () => {
  const { fetchPackage } = require('../src/registry');
  const pkg = await fetchPackage('limited', '1.0.0');
  assert.deepStrictEqual(pkg.scripts, {});
  assert.strictEqual(requests.filter((u) => u === '/limited/1.0.0').length, 2);
  await assert.rejects(() => fetchPackage('limited-always', '1.0.0'), /HTTP 429 \(rate limited by the registry\)/);
  assert.strictEqual(requests.filter((u) => u === '/limited-always/1.0.0').length, 2);
});

test('missing package rejects without retry storm', async () => {
  const { fetchPackage } = require('../src/registry');
  const countBefore = requests.length;
  await assert.rejects(() => fetchPackage('ghost', '9.9.9'), /HTTP 404/);
  assert.strictEqual(requests.length, countBefore + 1, 'a 404 is final, exactly one request');
});

test('the tarball index keeps #! scripts whatever their name, and names the files too large to read', async () => {
  const { fetchPackage } = require('../src/registry');
  const pkg = await fetchPackage('shebang', '1.0.0', { forceTarball: true });
  assert.deepStrictEqual([...pkg.files.keys()].sort(), ['bin/crc.njs', 'bin/tool', 'package.json']);
  assert.deepStrictEqual(pkg.skipped, ['dist/huge.js']);
});

test('the offline index keeps the same files as the tarball index', () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const { loadLocalPackage } = require('../src/registry');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lens-local-'));
  const pkg = path.join(dir, 'node_modules', 'shebang');
  fs.mkdirSync(path.join(pkg, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(pkg, 'dist'));
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: 'shebang', version: '1.0.0', bin: 'bin/crc.njs' }));
  fs.writeFileSync(path.join(pkg, 'bin', 'crc.njs'), '#!/usr/bin/env node\n');
  fs.writeFileSync(path.join(pkg, 'logo.png'), '\x89PNG');
  fs.writeFileSync(path.join(pkg, 'dist', 'huge.js'), 'x'.repeat(2 * 1024 * 1024 + 1));
  try {
    const local = loadLocalPackage('shebang', '1.0.0', dir, null, { forceFiles: true });
    assert.deepStrictEqual([...local.files.keys()].sort(), ['bin/crc.njs', 'package.json']);
    assert.deepStrictEqual(local.skipped, ['dist/huge.js']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
