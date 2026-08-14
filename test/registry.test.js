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
  };
  server = http.createServer((req, res) => {
    requests.push(req.url);
    const port = server.address().port;
    if (tarballs[req.url]) return res.writeHead(200).end(tarballs[req.url]);
    const doc = {
      '/mock-gyp/1.0.0': { version: '1.0.0', scripts: {}, hasInstallScript: true,
        dist: { tarball: `http://127.0.0.1:${port}/mock-gyp.tgz` } },
      '/clean-pkg/1.0.0': { version: '1.0.0', scripts: { test: 'jest' },
        dist: { tarball: `http://127.0.0.1:${port}/never-fetched.tgz` } },
      '/override/1.0.0': { version: '1.0.0', scripts: { postinstall: 'node registry-copy.js' },
        dist: { tarball: `http://127.0.0.1:${port}/override.tgz` } },
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

test('missing package rejects without retry storm', async () => {
  const { fetchPackage } = require('../src/registry');
  const countBefore = requests.length;
  await assert.rejects(() => fetchPackage('ghost', '9.9.9'), /HTTP 404/);
  assert.strictEqual(requests.length, countBefore + 1, 'a 404 is final, exactly one request');
});
