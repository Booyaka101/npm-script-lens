'use strict';
const acorn = require('acorn');
const loose = require('acorn-loose');
const walk = require('acorn-walk');
const { builtinModules } = require('node:module');
const { collectGypFindings } = require('./gyp');
const BUILTINS = new Set(builtinModules);

const EXEC_FNS = new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']);
// "exec"/"get"/"request"/"open" are too generic as member props (regex.exec,
// map.get...), so those require a recognizable receiver; the rest are
// distinctive enough to flag on any receiver (survives bundled/renamed code).
const AMBIGUOUS = new Set(['exec', 'get', 'request', 'open']);
const EXEC_RECV = /^(child_process|childProcess|cp|proc|shell|sh)$/;
const EXEC_PKGS = new Set(['child_process', 'execa', 'cross-spawn', 'shelljs', 'zx']);
const NET_PKGS = new Set(['http', 'https', 'http2', 'net', 'tls', 'dgram', 'dns', 'node-fetch', 'axios', 'got',
  'undici', 'needle', 'superagent', 'request', 'bent', 'phin', 'simple-get', 'download', '@prisma/fetch-engine']);
const NET_RECV = new Set(['http', 'https', 'http2']);
// vm executes arbitrary constructed strings — an eval by another name.
const OBF_PKGS = new Set(['vm']);
const DYNAMIC = Symbol('dynamic-require');
const NET_FNS = new Set(['request', 'get']);
const FS_FNS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'open', 'openSync',
  'createWriteStream', 'chmodSync', 'chmod']);
const EXEC_BINS = new Set(['node-gyp', 'node-pre-gyp', 'prebuild-install', 'make', 'cmake', 'sh', 'bash',
  'python', 'python3', 'cmd', 'powershell']);
const NET_BINS = new Set(['curl', 'wget']);
const NOISE_BINS = new Set(['true', 'echo', 'exit', 'set']);
const RUNNERS = new Set(['npm', 'yarn', 'pnpm']);
const MAX_DEPTH = 3, MAX_FILES = 30;

const short = (s) => (s.length > 60 ? `${s.slice(0, 57)}...` : s);

// Best-effort literal text of a call argument ("node-gyp rebuild ..." out of a
// string or the fixed head of a template literal).
function argText(arg) {
  if (!arg) return '';
  if (arg.type === 'Literal' && typeof arg.value === 'string') return arg.value;
  if (arg.type === 'TemplateLiteral' && arg.quasis[0]) return arg.quasis[0].value.cooked || '';
  return '';
}

// A required/imported module specifier: flag known exec/network packages,
// queue relative sources for deep analysis.
function classifySpec(spec, kw, signals, follow) {
  const bare = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0];
  const plain = bare.replace(/^node:/, '');
  if (EXEC_PKGS.has(plain)) signals.add(`exec: ${kw}('${plain}')`);
  else if (NET_PKGS.has(plain)) signals.add(`net: ${kw}('${plain}')`);
  else if (OBF_PKGS.has(plain)) signals.add(`obf: ${kw}('${plain}')`);
  else if (/^\.\.?\//.test(spec) && !spec.endsWith('.json')) follow.add(spec);
  // breadcrumb for --deep mode: a bare package require the lists don't know.
  // 'ref' never scores and is stripped from final rows; with --deep the CLI
  // resolves it against the lockfile and analyzes that package's entry file.
  else if (!spec.startsWith('.') && !BUILTINS.has(plain) && !spec.startsWith('node:')) signals.add(`ref: ${bare}`);
}

// The literal specifier of a require() call, DYNAMIC when the specifier is
// built from strings at runtime (concatenation, template interpolation — the
// classic way to hide what gets loaded), or null. Plain identifier arguments
// are NOT flagged: bundler interop and binding-path loaders use them
// constantly, and the path.join(__dirname, …) case is already followed.
function requireTarget(node) {
  const c = node.callee;
  const isRequire = (c.type === 'Identifier' && c.name === 'require') ||
    (c.type === 'MemberExpression' && !c.computed && c.property.name === 'require');
  if (!isRequire || node.arguments.length === 0) return null;
  const arg = node.arguments[0];
  if (arg.type === 'Literal' && typeof arg.value === 'string') return arg.value;
  if (arg.type === 'TemplateLiteral') {
    return arg.expressions.length === 0 ? (arg.quasis[0].value.cooked || null) : DYNAMIC;
  }
  if (arg.type === 'BinaryExpression') return DYNAMIC;
  return null;
}

// Resolve "./x" against the tarball file index, trying .js/.cjs/.mjs and
// index files the way require() would.
function resolveFile(files, from, spec) {
  const base = from.split('/').slice(0, -1);
  for (const part of spec.split('/')) {
    if (part === '..') base.pop();
    else if (part !== '.') base.push(part);
  }
  const p = base.join('/');
  for (const cand of [p, `${p}.js`, `${p}.cjs`, `${p}.mjs`, `${p}/index.js`, `${p}/index.cjs`]) {
    if (files.has(cand)) return cand;
  }
  return null;
}

// A decoded literal that parses as real JS (strict, not loose) is a hidden
// payload — analyze it like any other source file instead of only flagging
// the decode call.
function looksLikeJs(text) {
  if (!text || text.length < 6 || /[^\x09\x0a\x0d\x20-\x7e -￿]/.test(text)) return false;
  try {
    acorn.parse(text, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true });
    return true;
  } catch {
    try {
      acorn.parse(text, { ecmaVersion: 'latest', sourceType: 'script' });
      return true;
    } catch { return false; }
  }
}

// Statically walk one JS file from the tarball, collecting behavior signals
// and the relative modules it pulls in (require/import/path.join(__dirname..)).
// depth guards decoded-payload recursion (base64 inside base64).
function analyzeJs(source, signals, follow, depth = 0) {
  if (depth > 2) return;
  const decodeAndAnalyze = (text) => {
    if (looksLikeJs(text)) analyzeJs(text, signals, follow, depth + 1);
  };
  let ast;
  try { ast = loose.parse(source, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true }); } catch { return; }
  walk.full(ast, (node) => {
    if ((node.type === 'ImportDeclaration' || node.type === 'ExportNamedDeclaration' ||
         node.type === 'ExportAllDeclaration') && node.source && typeof node.source.value === 'string') {
      classifySpec(node.source.value, 'import', signals, follow);
    }
    if (node.type === 'ImportExpression') {
      const spec = argText(node.source);
      if (spec) classifySpec(spec, 'import', signals, follow);
    }
    if (node.type === 'MemberExpression' && !node.computed &&
        node.object.type === 'Identifier' && node.object.name === 'process' && node.property.name === 'env') {
      signals.add('env: process.env');
    }
    if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Function') {
      signals.add('obf: new Function() constructor');
    }
    if (node.type !== 'CallExpression') return;
    const spec = requireTarget(node);
    if (spec === DYNAMIC) {
      signals.add('obf: require(<string-built specifier>)');
      return;
    }
    if (spec !== null) {
      classifySpec(spec, 'require', signals, follow);
      return;
    }
    const c = node.callee;
    if (c.type === 'Identifier') {
      if (EXEC_FNS.has(c.name)) {
        const cmd = argText(node.arguments[0]);
        signals.add(`exec: ${short(cmd.trim()) || `${c.name}()`}`);
      } else if (c.name === 'fetch') signals.add('net: fetch()');
      else if (c.name === 'eval') {
        signals.add('obf: eval()');
        const body = argText(node.arguments[0]);
        if (body) decodeAndAnalyze(body);
      } else if (c.name === 'Function') signals.add('obf: new Function() constructor');
      else if (c.name === 'atob') {
        signals.add('obf: atob() base64 decode');
        const arg = argText(node.arguments[0]);
        if (arg) { try { decodeAndAnalyze(Buffer.from(arg, 'base64').toString('utf8')); } catch { /* not base64 */ } }
      }
    } else if (c.type === 'MemberExpression' && !c.computed && c.property.type === 'Identifier') {
      const prop = c.property.name;
      const recv = c.object.type === 'Identifier' ? c.object.name : '';
      // path.join(__dirname, ...) computing a .js path = an indirect local require
      if (prop === 'join' && recv === 'path' && node.arguments[0] &&
          node.arguments[0].type === 'Identifier' && node.arguments[0].name === '__dirname') {
        const parts = node.arguments.slice(1).map(argText);
        if (parts.every(Boolean) && /\.(js|cjs|mjs)$/.test(parts[parts.length - 1])) {
          follow.add(`./${parts.join('/')}`);
        }
      }
      if (recv === 'String' && prop === 'fromCharCode' && node.arguments.length >= 8) {
        signals.add('obf: String.fromCharCode(…) built string');
        if (node.arguments.every((a) => a.type === 'Literal' && typeof a.value === 'number')) {
          decodeAndAnalyze(String.fromCharCode(...node.arguments.map((a) => a.value)));
        }
      } else if (recv === 'Buffer' && prop === 'from' && argText(node.arguments[1]) === 'base64') {
        signals.add("obf: Buffer.from(…, 'base64') decode");
        const arg = argText(node.arguments[0]);
        if (arg) { try { decodeAndAnalyze(Buffer.from(arg, 'base64').toString('utf8')); } catch { /* not base64 */ } }
      } else if (EXEC_FNS.has(prop) && (!AMBIGUOUS.has(prop) || EXEC_RECV.test(recv))) {
        const cmd = argText(node.arguments[0]);
        signals.add(`exec: ${short(cmd.trim()) || `${recv || '?'}.${prop}()`}`);
      } else if (NET_RECV.has(recv) && NET_FNS.has(prop)) {
        signals.add(`net: ${recv}.${prop}`);
      } else if (FS_FNS.has(prop) && (!AMBIGUOUS.has(prop) || /^fs/i.test(recv) || recv === 'promises')) {
        signals.add(`fs: ${recv ? `${recv}.` : ''}${prop}`);
      }
    }
  });
}

// Split a shell line on top-level && || ; | — but not inside quotes, so
// `node -e "a;b"` stays whole.
function splitShell(cmd) {
  const parts = [];
  let cur = '', q = null;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (q) {
      cur += ch;
      if (ch === q && cmd[i - 1] !== '\\') q = null;
    } else if (ch === "'" || ch === '"') {
      q = ch; cur += ch;
    } else if ((ch === '&' && cmd[i + 1] === '&') || (ch === '|' && cmd[i + 1] === '|')) {
      parts.push(cur); cur = ''; i++;
    } else if (ch === ';' || ch === '|') {
      parts.push(cur); cur = '';
    } else cur += ch;
  }
  parts.push(cur);
  return parts;
}

// Analyze one shell command line: known binaries are flagged directly,
// `npm run x` recurses into the package's own scripts, and `node <file>`
// scripts are opened from the tarball and walked (following relative requires
// up to MAX_DEPTH / MAX_FILES).
function analyzeCommand(cmd, files, signals, scripts = {}, visited = new Set()) {
  const queue = [];
  const evalFollow = new Set();
  for (const part of splitShell(cmd)) {
    let tokens = part.trim().split(/\s+/).filter(Boolean);
    // strip FOO=bar prefixes and transparent cross-env wrappers
    while (tokens.length > 0 && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0]) || tokens[0] === 'cross-env')) tokens.shift();
    if (tokens.length === 0) continue;
    const clean = tokens.join(' ');
    const bin = tokens[0].split(/[\\/]/).pop().replace(/\.(exe|cmd|bat)$/i, '');
    if (EXEC_BINS.has(bin)) signals.add(`exec: ${short(clean)}`);
    else if (NET_BINS.has(bin)) signals.add(`net: ${short(clean)}`);
    else if (bin === 'npx') {
      signals.add(`exec: ${short(clean)}`);
      signals.add('net: npx (may download the package it runs)');
    } else if (RUNNERS.has(bin) && (tokens[1] === 'run' || tokens[1] === 'run-script') && tokens[2]) {
      const target = tokens[2];
      if (typeof scripts[target] === 'string' && !visited.has(target)) {
        visited.add(target);
        analyzeCommand(scripts[target], files, signals, scripts, visited);
      } else if (!visited.has(target)) signals.add(`exec: ${short(clean)} (script not found)`);
    } else if (bin === 'node' || bin === 'nodejs') {
      const evalIdx = tokens.findIndex((t) => ['-e', '--eval', '-p', '--print'].includes(t));
      if (evalIdx > 0 && tokens[evalIdx + 1]) {
        analyzeJs(part.trim().replace(/^.*?(?:-e|--eval|-p|--print)\s+/, '').replace(/^(['"])([\s\S]*)\1$/, '$2'),
          signals, evalFollow);
      } else {
        const file = tokens.slice(1).find((t) => !t.startsWith('-'));
        const resolved = file && resolveFile(files, 'x', `./${file.replace(/^\.\//, '')}`);
        if (resolved) queue.push({ path: resolved, depth: 0 });
        else if (file) signals.add(`exec: node ${short(file)} (source not in tarball)`);
      }
    } else if (!NOISE_BINS.has(bin)) {
      signals.add(`exec: ${short(clean)} (unresolved binary)`);
    }
  }
  for (const spec of evalFollow) {
    const resolved = resolveFile(files, 'x', spec);
    if (resolved) queue.push({ path: resolved, depth: 0 });
  }
  walkFiles(files, queue.map((q) => q.path), signals);
}

// The local files a shell line directly executes via `node <file>` — the
// "what does node install.js actually contain" surface the review command
// displays. Mirrors analyzeCommand's resolution without collecting signals.
function commandEntryFiles(cmd, files) {
  const out = [];
  for (const part of splitShell(cmd)) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    while (tokens.length > 0 && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0]) || tokens[0] === 'cross-env')) tokens.shift();
    if (tokens.length === 0) continue;
    const bin = tokens[0].split(/[\\/]/).pop().replace(/\.(exe|cmd|bat)$/i, '');
    if (bin !== 'node' && bin !== 'nodejs') continue;
    if (tokens.some((t) => ['-e', '--eval', '-p', '--print'].includes(t))) continue;
    const file = tokens.slice(1).find((t) => !t.startsWith('-'));
    const resolved = file && resolveFile(files, 'x', `./${file.replace(/^\.\//, '')}`);
    if (resolved && !out.includes(resolved)) out.push(resolved);
  }
  return out;
}

// Walk entry files from the tarball index, following relative requires up to
// MAX_DEPTH / MAX_FILES. Shared by script analysis and cross-package bin/deep
// resolution.
function walkFiles(files, entryPaths, signals) {
  const queue = entryPaths.map((p) => ({ path: p, depth: 0 }));
  const seen = new Set(entryPaths);
  while (queue.length > 0 && seen.size <= MAX_FILES) {
    const { path, depth } = queue.shift();
    const follow = new Set();
    analyzeJs(files.get(path), signals, follow);
    if (depth >= MAX_DEPTH) continue;
    for (const spec of follow) {
      const resolved = resolveFile(files, path, spec);
      if (resolved && !seen.has(resolved)) {
        seen.add(resolved);
        queue.push({ path: resolved, depth: depth + 1 });
      }
    }
  }
}

function score(signals) {
  const kinds = new Set([...signals].map((s) => s.split(':')[0]));
  // obf ranks with exec: code that decodes/constructs itself at install time
  // can do anything once it runs, and hiding is itself the signal. gyp joins
  // them: a binding.gyp command expansion is a shell command node-gyp runs
  // during configure, before a single line of C is compiled.
  if (kinds.has('exec') || kinds.has('obf') || kinds.has('gyp')) return 'HIGH';
  if (kinds.has('net')) return 'MEDIUM';
  if (kinds.has('fs') || kinds.has('env')) return 'LOW';
  return 'SAFE';
}

// A script that hands control to node-gyp — explicitly (`node-gyp rebuild`,
// `prebuild-install || node-gyp rebuild`) or via the implicit rebuild npm runs
// for a package shipping a root binding.gyp with no install script.
const RUNS_NODE_GYP = /(^|\s)node-gyp(\s|$)/;

// pkg: { name, version, scripts, files } -> rows of { script, command, risk, signals }
function analyzePackage(pkg) {
  // Read INSIDE binding.gyp (and the .gypi files it includes) when node-gyp
  // will actually run: gyp executes `<!(...)`-style expansions during
  // configure, so the build file is install-time code, not just a manifest.
  let gypSignals = [];
  if (pkg.files && pkg.files.has('binding.gyp')) {
    const { findings, partial, notes } = collectGypFindings(pkg.files);
    gypSignals = findings.map((f) => `gyp: ${f.channel} ${short(String(f.command).trim())}`);
    if (partial) gypSignals.push('gyp: binding.gyp did not parse — scanned as raw text');
    for (const n of notes) if (/not scanned/.test(n)) gypSignals.push(`gyp: ${short(n)}`);
  }
  return Object.entries(pkg.scripts).map(([script, command]) => {
    const signals = new Set();
    analyzeCommand(command, pkg.files, signals, pkg.allScripts || pkg.scripts, new Set([script]));
    if (RUNS_NODE_GYP.test(command)) for (const s of gypSignals) signals.add(s);
    return { script, command, risk: score(signals), signals: [...signals].sort() };
  });
}

module.exports = { analyzePackage, analyzeCommand, analyzeJs, walkFiles, resolveFile, splitShell, score, commandEntryFiles };
