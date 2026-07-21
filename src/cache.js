'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const TOOL_VERSION = require('../package.json').version;

// Published tarballs are immutable, so analysis rows for name@version are
// deterministic per analyzer version — cache entries never expire, they are
// invalidated wholesale by a tool version bump.
function cacheDir() {
  if (process.env.NPM_SCRIPT_LENS_CACHE_DIR) return process.env.NPM_SCRIPT_LENS_CACHE_DIR;
  const base = process.env.XDG_CACHE_HOME ||
    (process.platform === 'win32'
      ? (process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'))
      : path.join(os.homedir(), '.cache'));
  return path.join(base, 'npm-script-lens');
}

const fileFor = (name, version) => path.join(cacheDir(), `${name.replace('/', '+')}@${version}.json`);

function cacheGet(name, version) {
  try {
    const doc = JSON.parse(fs.readFileSync(fileFor(name, version), 'utf8'));
    return doc.tool === TOOL_VERSION ? doc.rows : null;
  } catch {
    return null;
  }
}

function cacheSet(name, version, rows) {
  try {
    fs.mkdirSync(cacheDir(), { recursive: true });
    fs.writeFileSync(fileFor(name, version), JSON.stringify({ tool: TOOL_VERSION, rows }));
  } catch { /* cache is best-effort */ }
}

module.exports = { cacheGet, cacheSet, cacheDir };
