'use strict';
// A mock npm registry that serves the runtime-bootstrap fixtures as in-memory
// tarballs, so `audit`/`--diff` can run against them exactly as the acceptance
// commands describe, with nothing ChainDrop-shaped written to disk. Used by
// test/bootstrap.test.js and for manual e2e:
//   node scripts/serve-bootstrap-fixtures.js            # prints the base URL
//   NPM_SCRIPT_LENS_REGISTRY=<url> node src/cli.js audit --json --path fixtures/bootstrap/chaindrop-shape
const http = require('node:http');
const zlib = require('node:zlib');
const tar = require('tar-stream');
const { SHAPES } = require('../fixtures/bootstrap/payloads');

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

// Build every version doc + tarball once, keyed by request path.
async function buildRoutes(port) {
  const meta = new Map();
  const tarballs = new Map();
  for (const s of SHAPES) {
    for (const [version, v] of Object.entries(s.versions)) {
      const tgzPath = `/${s.name}/-/${s.name}-${version}.tgz`;
      tarballs.set(tgzPath, await makeTgz({
        'package/package.json': JSON.stringify({ name: s.name, version, scripts: v.scripts }),
        ...Object.fromEntries(Object.entries(v.files).map(([f, c]) => [`package/${f}`, c])),
      }));
      meta.set(`/${s.name}/${version}`, {
        version, scripts: v.scripts, hasInstallScript: true,
        dist: { tarball: `http://127.0.0.1:${port}${tgzPath}` },
      });
    }
  }
  return { meta, tarballs };
}

async function start() {
  let routes;
  const server = http.createServer((req, res) => {
    if (routes.tarballs.has(req.url)) return res.writeHead(200).end(routes.tarballs.get(req.url));
    const doc = routes.meta.get(req.url);
    if (!doc) return res.writeHead(404).end('{}');
    return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(doc));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  routes = await buildRoutes(port);
  return { server, url: `http://127.0.0.1:${port}` };
}

module.exports = { start, makeTgz };

if (require.main === module) {
  start().then(({ url }) => process.stdout.write(`${url}\n`));
}
