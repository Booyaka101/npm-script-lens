'use strict';
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { Readable } = require('node:stream');
const tar = require('tar-stream');

const REGISTRY = process.env.NPM_SCRIPT_LENS_REGISTRY || 'https://registry.npmjs.org';
// What npm actually runs when installing a dependency from the registry
// (prepare only runs for git/local sources, so auditing it would false-alarm
// on the many packages that publish leftover "prepare": "husky install").
const LIFECYCLE = ['preinstall', 'install', 'postinstall'];
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const TEXT_FILE = /\.(js|cjs|mjs|ts|mts|cts|json|gyp|gypi)$/;
// Node runs a bin by its #! line whatever its name (bin/cli, bin/crc32.njs),
// so any other file is kept when it opens with one.
const isScript = (buf) => buf[0] === 0x23 && buf[1] === 0x21;

function pickLifecycle(scripts) {
  const out = {};
  for (const k of LIFECYCLE) if (scripts && typeof scripts[k] === 'string') out[k] = scripts[k];
  return out;
}

// One retry on transient network failures and on a 429, after its
// Retry-After (capped); hung connections get cut by the abort timeout instead
// of stalling the whole audit.
async function fetchOk(url, timeoutMs, attempt = 0) {
  let wait = 1000;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/json' } });
    if (res.status === 429) {
      if (attempt > 0) throw Object.assign(new Error(`HTTP 429 (rate limited by the registry) for ${url}`), { final: true });
      wait = Math.min(Number(res.headers.get('retry-after')) || 1, 30) * 1000;
      throw new Error('HTTP 429');
    }
    if (res.status >= 500 && attempt === 0) throw new Error(`HTTP ${res.status}`);
    if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status} for ${url}`), { final: true });
    return res;
  } catch (err) {
    if (err.final || attempt > 0) throw err;
    await new Promise((r) => setTimeout(r, wait));
    return fetchOk(url, timeoutMs, 1);
  }
}

// Download a tarball and index its text files (js/ts/json/gyp/gypi, and
// #! scripts) into a Map of path (without the leading "package/"
// folder) -> file content string. .gypi is indexed too because binding.gyp
// routinely `includes` one (better-sqlite3's deps/common.gypi) and the gyp
// scanner follows those; .ts because deno/tsx/bun entry points are
// TypeScript. Resolves { files, skipped }: skipped lists the files over the
// size cap, so a missing entry point can say why.
async function downloadTarball(url) {
  const res = await fetchOk(url, 120000);
  return new Promise((resolve, reject) => {
    const files = new Map();
    const skipped = [];
    const extract = tar.extract();
    extract.on('entry', (header, stream, next) => {
      const p = header.name.replace(/^[^/]+\//, '');
      const text = TEXT_FILE.test(p);
      const fits = header.size <= MAX_FILE_BYTES;
      if (header.type === 'file' && !fits) skipped.push(p);
      let keep = fits && (text || header.type === 'file');
      const chunks = [];
      stream.on('data', (c) => {
        if (keep && !text && chunks.length === 0 && !isScript(c)) keep = false;
        if (keep) chunks.push(c);
      });
      stream.on('end', () => {
        if (keep) files.set(p, Buffer.concat(chunks).toString('utf8'));
        next();
      });
      stream.resume();
    });
    extract.on('finish', () => resolve({ files, skipped }));
    extract.on('error', reject);
    Readable.fromWeb(res.body).pipe(zlib.createGunzip()).on('error', reject).pipe(extract);
  });
}

// The whole packument for one name: every version doc plus per-version publish
// times. One GET, shared by trust enrichment (fetchTrust) and the
// trust-downgrade check, which both read versions[v].dist and time[v].
async function fetchPackument(name) {
  const res = await fetchOk(`${REGISTRY}/${name.replace(/\//g, '%2f')}`, 30000);
  return res.json();
}

// Fetch one package version: its lifecycle scripts plus the tarball file index
// needed for deep analysis. Packages with no install-time behavior skip the
// tarball download entirely (the registry's hasInstallScript flag covers
// implicit node-gyp builds too).
const normalizeBin = (bin, name) => (typeof bin === 'string' ? { [name.split('/').pop()]: bin } : (bin || {}));

async function fetchPackage(name, version, { forceTarball = false } = {}) {
  const meta = await fetchOk(`${REGISTRY}/${name.replace('/', '%2f')}/${encodeURIComponent(version)}`, 30000)
    .then((r) => r.json());
  let scripts = pickLifecycle(meta.scripts);
  let allScripts = meta.scripts || {};
  let bin = normalizeBin(meta.bin, name);
  if ((Object.keys(scripts).length === 0 && !meta.hasInstallScript && !forceTarball) || !meta.dist || !meta.dist.tarball) {
    return { name, version, scripts, allScripts, bin, files: new Map(), skipped: [], implicitGyp: false };
  }
  const { files, skipped } = await downloadTarball(meta.dist.tarball);
  const pkgJson = files.get('package.json');
  if (pkgJson) {
    try {
      const parsed = JSON.parse(pkgJson);
      allScripts = parsed.scripts || {};
      scripts = pickLifecycle(allScripts);
      bin = normalizeBin(parsed.bin, name);
    } catch { /* keep registry copy */ }
  }
  // npm runs an implicit `node-gyp rebuild` for packages shipping a root
  // binding.gyp without their own install/preinstall script: npm v12 blocks
  // these too, so surface them as a synthetic install script.
  const implicitGyp = files.has('binding.gyp') && !scripts.install && !scripts.preinstall;
  if (implicitGyp) scripts.install = 'node-gyp rebuild';
  return { name, version, scripts, allScripts, bin, files, skipped, implicitGyp };
}

function opensWithShebang(file) {
  const fd = fs.openSync(file, 'r');
  try {
    const head = Buffer.alloc(2);
    return isScript(head.subarray(0, fs.readSync(fd, head, 0, 2, 0)));
  } finally {
    fs.closeSync(fd);
  }
}

// Offline mode: index the package already unpacked in node_modules the same
// way downloadTarball indexes a tarball (same files, size-capped), stopping
// at `limit` files. skipped lists the oversize ones; capped means the limit
// cut the walk short.
function indexLocalDir(dir, limit) {
  const files = new Map();
  const skipped = [];
  let capped = false;
  const walk = (d, rel) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (files.size >= limit) {
        capped = true;
        return;
      }
      if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
      const full = path.join(d, e.name);
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(full, r);
      else if (e.isFile()) {
        if (fs.statSync(full).size > MAX_FILE_BYTES) skipped.push(r);
        else if (TEXT_FILE.test(e.name) || opensWithShebang(full)) files.set(r, fs.readFileSync(full, 'utf8'));
      }
    }
  };
  walk(dir, '');
  return { files, skipped, capped };
}

// Same contract as fetchPackage, sourced from disk. lockKey (npm lockfiles
// only) points at the exact install path, which finds nested/deduped copies;
// otherwise the top-level node_modules/<name> is tried.
// maxFiles: runtime callers raise it, since entry points can sit anywhere.
function loadLocalPackage(name, version, projectDir, lockKey, { forceFiles = false, maxFiles = 400 } = {}) {
  const candidates = [];
  if (lockKey) candidates.push(path.join(projectDir, ...lockKey.split('/')));
  candidates.push(path.join(projectDir, 'node_modules', ...name.split('/')));
  const dir = candidates.find((c) => fs.existsSync(path.join(c, 'package.json')));
  if (!dir) throw new Error('not found in node_modules (offline mode)');
  const pkgJson = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  if (pkgJson.version !== version) {
    throw new Error(`node_modules has ${pkgJson.version}, lockfile wants ${version} (offline mode)`);
  }
  const allScripts = pkgJson.scripts || {};
  const scripts = pickLifecycle(allScripts);
  const bin = normalizeBin(pkgJson.bin, name);
  const hasGyp = fs.existsSync(path.join(dir, 'binding.gyp'));
  if (Object.keys(scripts).length === 0 && !hasGyp && !forceFiles) {
    return { name, version, scripts, allScripts, bin, files: new Map(), skipped: [], implicitGyp: false };
  }
  const { files, skipped, capped } = indexLocalDir(dir, maxFiles);
  const implicitGyp = hasGyp && !scripts.install && !scripts.preinstall;
  if (implicitGyp) scripts.install = 'node-gyp rebuild';
  return { name, version, scripts, allScripts, bin, files, skipped, capped, implicitGyp };
}

module.exports = { fetchPackage, fetchPackument, loadLocalPackage, LIFECYCLE, REGISTRY };
