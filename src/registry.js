'use strict';
const zlib = require('node:zlib');
const { Readable } = require('node:stream');
const tar = require('tar-stream');

const REGISTRY = process.env.NPM_SCRIPT_LENS_REGISTRY || 'https://registry.npmjs.org';
// What npm actually runs when installing a dependency from the registry
// (prepare only runs for git/local sources, so auditing it would false-alarm
// on the many packages that publish leftover "prepare": "husky install").
const LIFECYCLE = ['preinstall', 'install', 'postinstall'];
const MAX_FILE_BYTES = 2 * 1024 * 1024;

function pickLifecycle(scripts) {
  const out = {};
  for (const k of LIFECYCLE) if (scripts && typeof scripts[k] === 'string') out[k] = scripts[k];
  return out;
}

// One retry on transient network failures; hung connections get cut by the
// abort timeout instead of stalling the whole audit.
async function fetchOk(url, timeoutMs, attempt = 0) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/json' } });
    if (res.status >= 500 && attempt === 0) throw new Error(`HTTP ${res.status}`);
    if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status} for ${url}`), { final: true });
    return res;
  } catch (err) {
    if (err.final || attempt > 0) throw err;
    await new Promise((r) => setTimeout(r, 1000));
    return fetchOk(url, timeoutMs, 1);
  }
}

// Download a tarball and index its text files (js/json/gyp) into a Map of
// path (without the leading "package/" folder) -> file content string.
async function downloadTarball(url) {
  const res = await fetchOk(url, 120000);
  return new Promise((resolve, reject) => {
    const files = new Map();
    const extract = tar.extract();
    extract.on('entry', (header, stream, next) => {
      const p = header.name.replace(/^[^/]+\//, '');
      const keep = /\.(js|cjs|mjs|json|gyp)$/.test(p) && header.size <= MAX_FILE_BYTES;
      const chunks = [];
      if (keep) stream.on('data', (c) => chunks.push(c));
      stream.on('end', () => {
        if (keep) files.set(p, Buffer.concat(chunks).toString('utf8'));
        next();
      });
      stream.resume();
    });
    extract.on('finish', () => resolve(files));
    extract.on('error', reject);
    Readable.fromWeb(res.body).pipe(zlib.createGunzip()).on('error', reject).pipe(extract);
  });
}

// Fetch one package version: its lifecycle scripts plus the tarball file index
// needed for deep analysis. Packages with no install-time behavior skip the
// tarball download entirely (the registry's hasInstallScript flag covers
// implicit node-gyp builds too).
async function fetchPackage(name, version) {
  const meta = await fetchOk(`${REGISTRY}/${name.replace('/', '%2f')}/${encodeURIComponent(version)}`, 30000)
    .then((r) => r.json());
  let scripts = pickLifecycle(meta.scripts);
  let allScripts = meta.scripts || {};
  if ((Object.keys(scripts).length === 0 && !meta.hasInstallScript) || !meta.dist || !meta.dist.tarball) {
    return { name, version, scripts, allScripts, files: new Map(), implicitGyp: false };
  }
  const files = await downloadTarball(meta.dist.tarball);
  const pkgJson = files.get('package.json');
  if (pkgJson) {
    try {
      allScripts = JSON.parse(pkgJson).scripts || {};
      scripts = pickLifecycle(allScripts);
    } catch { /* keep registry copy */ }
  }
  // npm runs an implicit `node-gyp rebuild` for packages shipping a root
  // binding.gyp without their own install/preinstall script — npm v12 blocks
  // these too, so surface them as a synthetic install script.
  const implicitGyp = files.has('binding.gyp') && !scripts.install && !scripts.preinstall;
  if (implicitGyp) scripts.install = 'node-gyp rebuild';
  return { name, version, scripts, allScripts, files, implicitGyp };
}

module.exports = { fetchPackage, LIFECYCLE, REGISTRY };
