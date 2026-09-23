'use strict';
const acorn = require('acorn');
const loose = require('acorn-loose');
const walk = require('acorn-walk');
const { builtinModules } = require('node:module');
const { posix } = require('node:path');
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
// vm executes arbitrary constructed strings, an eval by another name.
const OBF_PKGS = new Set(['vm']);
const NET_FNS = new Set(['request', 'get']);
const FS_FNS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'open', 'openSync',
  'createWriteStream', 'chmodSync', 'chmod']);
const EXEC_BINS = new Set(['node-gyp', 'node-pre-gyp', 'prebuild-install', 'make', 'cmake', 'sh', 'bash',
  'python', 'python3', 'cmd', 'powershell']);
const NET_BINS = new Set(['curl', 'wget']);
const NOISE_BINS = new Set(['true', 'echo', 'exit', 'set']);
const RUNNERS = new Set(['npm', 'yarn', 'pnpm']);
const MAX_DEPTH = 3, MAX_FILES = 30;

// The runtimes an install script can hand a JS/TS file to. ChainDrop's escape
// was exactly this table being one entry long: `node setup.mjs` was followed,
// the bun/deno/tsx equivalents were not.
const DIRECT_RUNTIMES = new Set(['node', 'nodejs', 'bun', 'tsx', 'ts-node']);
const RUNTIME_PKGS = new Set(['bun', 'deno', 'tsx', 'ts-node']);
const BUN_CMDS = new Set(['install', 'i', 'add', 'remove', 'rm', 'update', 'outdated', 'link', 'unlink',
  'pm', 'test', 'init', 'create', 'upgrade', 'repl', 'build', 'exec']);
const EVAL_FLAGS = new Set(['-e', '--eval', '-p', '--print']);

// Where JavaScript runtimes are distributed. Fetching one of these from a
// lifecycle script (or the JS it runs) bootstraps an interpreter the approval
// model never sees: ChainDrop (2026-08-04) pulled a signed bun 1.3.13 release
// zip from oven-sh/bun and ran its bundled 710 KB payload under it.
const RUNTIME_DIST = [
  { re: /github\.com\/oven-sh\/bun\/releases/i, runtime: 'bun', via: 'oven-sh/bun releases' },
  { re: /\bbun-(?:linux|darwin|windows)-(?:x64|aarch64)(?:-[a-z0-9]+)*\.zip/i, runtime: 'bun', via: 'a bun release archive' },
  { re: /\bbun\.(?:sh|com)\/install/i, runtime: 'bun', via: 'bun.sh/install' },
  { re: /\bdeno\.land\/(?:x\/)?install|\bdl\.deno\.land/i, runtime: 'deno', via: 'deno.land/install' },
];

// Where a runtime payload phones home. The btree loader (Checkmarx,
// 2026-09-17) read its C2 from a Sepolia contract over alchemy/infura RPC and
// posted stolen data to Telegram and Slack bots. Hosts, not bare words: a
// chain named 'sepolia' in a web3 library's config is not an endpoint, and
// docs.alchemy.com is not RPC.
const RPC_HOSTS = [
  /(?:^|[.-])(?:sepolia|goerli|holesky)(?:[.-]|$)/,
  /^(?!(?:docs|app|www|blog|status|support)\.)[a-z0-9-]+\.infura\.io$/,
  /\.g\.alchemy\.com$|\.alchemyapi\.io$/,
  /(?:^|[.-])rpc\.publicnode\.com$/,
  /^rpc\.ankr\.com$/,
];
const EXFIL_ENDPOINTS = [
  'api.telegram.org/bot', 'hooks.slack.com/services', 'slack.com/api/chat.postMessage',
  'discord.com/api/webhooks', 'discordapp.com/api/webhooks',
];
const URL_HOSTS = /\b(?:https?|wss?):\/\/([a-z0-9.-]+)/gi;
const CONTRACT = /\b0x[0-9a-fA-F]{40}\b/g;

// Where publish and cloud credentials live. Shai-Hulud and the keyv/cacheable
// payload read ~/.npmrc and NPM_TOKEN, then sent them out or published with
// them. A path as a whole literal, not a mention inside a message.
const CRED_FILES = /(?:^|[\\/~])(\.npmrc|\.yarnrc\.yml|\.netrc|\.git-credentials|\.aws[\\/]credentials|\.docker[\\/]config\.json|\.kube[\\/]config|\.config[\\/]gh[\\/]hosts\.yml|\.ssh[\\/]id_[a-z0-9]+)$/i;
// Someone else's credentials only: a vendor reading its own NX_CLOUD_ACCESS_TOKEN
// or FIREBASE_TOKEN is configuration.
const CRED_ENV = /^(?:NPM_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN|ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|OPENAI_API_KEY|ANTHROPIC_API_KEY)$|_authtoken$/i;
// process.binding() names that hand out the raw spawn and socket handles.
const RAW_BINDINGS = new Map([['spawn_sync', 'exec'], ['process_wrap', 'exec'],
  ['tcp_wrap', 'net'], ['tls_wrap', 'net'], ['udp_wrap', 'net'], ['cares_wrap', 'net']]);
// Receivers a global function can be called through: globalThis['eval'](s).
const GLOBAL_OBJECTS = new Set(['globalThis', 'global', 'window', 'self']);

// The payload-ish parts of one string literal: RPC hosts, exfil endpoints,
// eth_call and 40-hex contract addresses (the last only count next to RPC),
// and credential file paths.
function literalIocs(text, iocs) {
  for (const m of text.matchAll(URL_HOSTS)) {
    const host = m[1].toLowerCase();
    if (RPC_HOSTS.some((re) => re.test(host))) iocs.rpc.add(host);
  }
  for (const e of EXFIL_ENDPOINTS) if (text.includes(e)) iocs.exfil.add(e);
  if (/\beth_call\b/.test(text)) iocs.ethCall = true;
  for (const m of text.matchAll(CONTRACT)) iocs.contracts.add(m[0]);
  const cred = CRED_FILES.exec(text);
  if (cred) iocs.cred.add(cred[1].replace(/\\/g, '/'));
}

const isProcessEnv = (n) => n.type === 'MemberExpression' && !n.computed && n.object.type === 'Identifier' &&
  n.object.name === 'process' && n.property.name === 'env';

const binName = (t) => t.split(/[\\/]/).pop().replace(/\.(exe|cmd|bat)$/i, '');

// runtime -> "fetched from <where>" for every distribution source named in
// `text`, first match per runtime wins.
function bootstrapHits(text) {
  const hits = new Map();
  for (const d of RUNTIME_DIST) if (!hits.has(d.runtime) && d.re.test(text)) hits.set(d.runtime, `fetched from ${d.via}`);
  return hits;
}

const bootstrapSignal = (runtime, how, runs = []) =>
  `bootstrap: ${runtime} ${how}${runs.length > 0 ? `, then runs ${runs.slice(0, 3).join(', ')}` : ''}`;

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

// The specifier argument of a require() call, or null.
function requireArg(node) {
  const c = node.callee;
  const isRequire = (c.type === 'Identifier' && c.name === 'require') ||
    (c.type === 'MemberExpression' && !c.computed && c.property.name === 'require');
  return isRequire && node.arguments.length > 0 ? node.arguments[0] : null;
}

// A specifier written out as a plain string, or null.
function literalSpec(arg) {
  if (arg.type === 'Literal' && typeof arg.value === 'string') return arg.value;
  if (arg.type === 'TemplateLiteral' && arg.expressions.length === 0) return arg.quasis[0].value.cooked || null;
  return null;
}

// A require()/import() specifier that is not a plain string, once the whole
// file's bindings are known. Folded to a string, it is classified like any
// other; built by concatenation, interpolation or a decode, that is also the
// classic way to hide what gets loaded (obf). An unresolved identifier is NOT
// flagged: bundler interop and binding-path loaders use them constantly, and
// the path.join(__dirname, …) case is already followed.
function lateSpec(kw, arg, bindings, signals, follow) {
  const spec = foldValue(arg, { bindings });
  let src = arg;
  for (let h = 0; src && src.type === 'Identifier' && h < 2; h++) src = bindings.get(src.name);
  const built = (kw === 'require' && (arg.type === 'BinaryExpression' || arg.type === 'TemplateLiteral')) ||
    (typeof spec === 'string' && src && src.type === 'CallExpression');
  if (built) signals.add(`obf: ${kw}(<string-built specifier>)`);
  if (typeof spec === 'string' && spec) classifySpec(spec, kw, signals, follow);
  else if (kw === 'import' && argText(arg)) classifySpec(argText(arg), kw, signals, follow);
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
  for (const cand of [p, `${p}.js`, `${p}.cjs`, `${p}.mjs`, `${p}/index.js`, `${p}/index.cjs`, `${p}.ts`, `${p}/index.ts`]) {
    if (files.has(cand)) return cand;
  }
  return null;
}

// A decoded literal that parses as real JS (strict, not loose) is a hidden
// payload: analyze it like any other source file instead of only flagging
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

// A file the package itself ships, named by an exec argument: a path built
// off __dirname / import.meta, or a path.join / path.resolve or .js/.cjs/.mjs
// literal that resolves in the tarball. One variable hop is followed, because
// the btree loader held the path in `loadPath`. Returns { label, resolved }
// or null.
function localFile(el, bindings, where, hops = 0) {
  if (!el) return null;
  if (el.type === 'Identifier' && bindings.has(el.name) && hops < 2) {
    return localFile(bindings.get(el.name), bindings, where, hops + 1);
  }
  let anchored = false;
  const parts = [];
  // arguments only: the callee of require('path').join(...) is not a segment
  for (const root of el.type === 'CallExpression' ? el.arguments : [el]) {
    walk.full(root, (n) => {
      if ((n.type === 'Identifier' && (n.name === '__dirname' || n.name === '__filename')) ||
          (n.type === 'MetaProperty' && n.meta.name === 'import')) anchored = true;
      else if (n.type === 'Literal' && typeof n.value === 'string') parts.push(n.value);
      else if (n.type === 'TemplateElement' && n.value.cooked) parts.push(n.value.cooked);
    });
  }
  const pathCall = el.type === 'CallExpression' && el.callee.type === 'MemberExpression' && !el.callee.computed &&
    ['join', 'resolve'].includes(el.callee.property.name) && /path/i.test(el.callee.object.name || '');
  const label = parts.join('/').replace(/\\/g, '/').replace(/\/{2,}/g, '/').replace(/^(?:\.?\/)+/, '');
  const literal = el.type === 'Literal' && /\.[cm]?js$/.test(label);
  if (!anchored && !pathCall && !literal) return null;
  const resolved = where && label
    ? resolveFile(where.files, where.from, `./${label}`) || resolveFile(where.files, 'x', `./${label}`) : null;
  // path.resolve(process.cwd(), file) runs the user's file, not the package's
  if (!anchored && !resolved) return null;
  return { label: resolved || label || '<computed path>', resolved };
}

// exec-local: a JS runtime (process.execPath, or node/bun/tsx by name) handed
// a file from the package's own tarball. A library that runs git is routine;
// a sorted map that starts a detached node on a bundled .min.js is the btree
// loader: spawn("node", [loadPath, String(key)]).
function localExec(call, bindings, where) {
  const [bin, args, options] = call.arguments;
  const execPath = bin && bin.type === 'MemberExpression' && !bin.computed && bin.object.type === 'Identifier' &&
    bin.object.name === 'process' && bin.property.name === 'execPath';
  const named = binName(argText(bin));
  const runtime = execPath ? 'process.execPath' : (DIRECT_RUNTIMES.has(named) ? named : null);
  if (!runtime || !args || args.type !== 'ArrayExpression') return null;
  const detached = Boolean(options && options.type === 'ObjectExpression' && options.properties.some((p) =>
    p.key && (p.key.name === 'detached' || p.key.value === 'detached') && (
      (p.value.type === 'Literal' && p.value.value === true) ||
      // minifiers write true as !0
      (p.value.type === 'UnaryExpression' && p.value.operator === '!' && p.value.argument.value === 0))));
  for (const el of args.elements) {
    const file = localFile(el, bindings, where);
    if (file) return { runtime, file, detached };
  }
  return null;
}

const MAX_FOLD = 10000;

// The string (or string array) an expression always evaluates to when every
// input is a literal: concatenation, templates, and the spellings used to hide
// a specifier or URL from a plain text match ([...].join, .split('').reverse(),
// String.fromCharCode, Buffer.from(…, 'hex').toString(), atob). Anything
// computed at runtime stays opaque (null).
// memo holds the folds of '+' nodes already visited (the walk is post-order);
// bindings, once the walk is done, lets a name bound once stand for its value.
function foldValue(node, { memo = null, bindings = null } = {}, hops = 0) {
  if (!node) return null;
  const fold = (n, h = hops) => foldValue(n, { memo, bindings }, h);
  const str = (n) => { const v = fold(n); return typeof v === 'string' ? v : null; };
  let out = null;
  if (node.type === 'Literal') out = typeof node.value === 'string' ? node.value : null;
  else if (node.type === 'TemplateLiteral') {
    out = node.quasis[0].value.cooked;
    for (let i = 0; out != null && i < node.expressions.length; i++) {
      const e = str(node.expressions[i]);
      const q = node.quasis[i + 1].value.cooked;
      out = e === null || q == null ? null : out + e + q;
    }
  } else if (node.type === 'BinaryExpression' && node.operator === '+') {
    if (memo && memo.has(node)) return memo.get(node);
    const l = str(node.left);
    const r = l === null ? null : str(node.right);
    out = r === null ? null : l + r;
  } else if (node.type === 'Identifier' && bindings && bindings.get(node.name) && hops < 2) {
    return fold(bindings.get(node.name), hops + 1);
  } else if (node.type === 'ArrayExpression') {
    const parts = node.elements.map((el) => (el ? str(el) : null));
    return parts.every((p) => p !== null) ? parts : null;
  } else if (node.type === 'CallExpression') {
    out = foldCall(node, fold, str);
  }
  if (Array.isArray(out)) return out;
  return typeof out === 'string' && out.length <= MAX_FOLD ? out : null;
}

function foldCall(node, fold, str) {
  const c = node.callee;
  const args = node.arguments;
  if (c.type === 'Identifier' && c.name === 'atob') {
    const s = str(args[0]);
    return s === null ? null : Buffer.from(s, 'base64').toString('latin1');
  }
  const prop = propName(c);
  if (!prop) return null;
  if (prop === 'fromCharCode' && c.object.type === 'Identifier' && c.object.name === 'String') {
    return args.every((a) => a.type === 'Literal' && typeof a.value === 'number')
      ? String.fromCharCode(...args.map((a) => a.value)) : null;
  }
  // Buffer.from(data, enc).toString([enc])
  const inner = c.object;
  if (prop === 'toString' && inner.type === 'CallExpression' && propName(inner.callee) === 'from' &&
      inner.callee.object.type === 'Identifier' && inner.callee.object.name === 'Buffer') {
    const data = str(inner.arguments[0]);
    const from = inner.arguments[1] ? str(inner.arguments[1]) : 'utf8';
    const to = args[0] ? str(args[0]) : 'utf8';
    return data !== null && Buffer.isEncoding(from) && Buffer.isEncoding(to) ? Buffer.from(data, from).toString(to) : null;
  }
  const recv = fold(inner);
  if (prop === 'join' && Array.isArray(recv)) {
    const sep = args[0] ? str(args[0]) : ',';
    return sep === null ? null : recv.join(sep);
  }
  if (prop === 'reverse' && Array.isArray(recv)) return [...recv].reverse();
  if (prop === 'split' && typeof recv === 'string') {
    const sep = str(args[0]);
    return sep === null ? null : recv.split(sep);
  }
  return null;
}

// The property a member expression names: a.b, a['b'], a['ev' + 'al'].
function propName(m) {
  if (m.type !== 'MemberExpression') return null;
  if (!m.computed) return m.property.type === 'Identifier' ? m.property.name : null;
  const v = foldValue(m.property);
  return typeof v === 'string' ? v : null;
}

// obfuscator.io's string-array prelude: a loop that rotates the encoded array
// (a.push(a.shift())) until a parseInt checksum over decoded entries matches.
// It is what hides every literal in the file, so it is the one thing left to
// see. A bare push(shift()) is a routine round-robin; the parseInt is the tell.
const STRING_ARRAY_ROTATION = 'obf: string-array rotation (obfuscator.io)';
function rotatesStringArray(loop) {
  let rotate = false;
  let parse = false;
  walk.full(loop.body, (n) => {
    if (n.type !== 'CallExpression') return;
    if (n.callee.type === 'Identifier' && n.callee.name === 'parseInt') parse = true;
    const arg = n.arguments[0];
    if (propName(n.callee) === 'push' && n.arguments.length === 1 && arg.type === 'CallExpression' &&
        propName(arg.callee) === 'shift' && n.callee.object.type === 'Identifier' &&
        arg.callee.object.type === 'Identifier' && n.callee.object.name === arg.callee.object.name) rotate = true;
  });
  return rotate && parse;
}

// Statically walk one JS file from the tarball, collecting behavior signals
// and the relative modules it pulls in (require/import/path.join(__dirname..)).
// depth guards decoded-payload recursion (base64 inside base64). `where`
// ({ files, from }) lets exec-local resolve a literal path in the tarball.
function analyzeJs(source, signals, follow, depth = 0, where = null) {
  if (depth > 2) return;
  const boots = new Map();
  const spawnRuns = [];
  const iocs = { rpc: new Set(), exfil: new Set(), contracts: new Set(), ethCall: false, cred: new Set() };
  // Flat, scope-blind: a name bound twice (or as a parameter) could be either
  // value where it is used, so it resolves to nothing.
  const bindings = new Map();
  const bind = (id, init) => {
    if (id.type !== 'Identifier') return;
    bindings.set(id.name, bindings.has(id.name) && bindings.get(id.name) !== init ? null : init);
  };
  const folds = new Map();
  const foldParent = new Map();
  const execCalls = [];
  const lateSpecs = [];
  // A string literal handed to an exec call that names a JS/TS source is an
  // entry point like any other: ChainDrop's stage 2 was spawned under the
  // downloaded bun, never require()d, so the specifier walk alone missed it.
  const followSpawnFiles = (text) => {
    for (const tok of String(text).split(/\s+/)) {
      const t = tok.replace(/^['"]|['"]$/g, '').replace(/^\.?\//, '');
      if (!/\.(?:js|cjs|mjs|ts|mts|cts)$/i.test(t)) continue;
      follow.add(`./${t}`);
      if (!spawnRuns.includes(t)) spawnRuns.push(t);
    }
  };
  const spawnArgFiles = (args) => {
    for (const a of args) {
      const elements = a && a.type === 'ArrayExpression' ? (a.elements || []) : [a];
      for (const el of elements) {
        if (!el) continue;
        if (el.type === 'Literal' && typeof el.value === 'string') followSpawnFiles(el.value);
        else if (el.type === 'TemplateLiteral') for (const q of el.quasis) followSpawnFiles(q.value.cooked || '');
      }
    }
  };
  const decodeAndAnalyze = (text) => {
    if (looksLikeJs(text)) analyzeJs(text, signals, follow, depth + 1, where);
  };
  let ast;
  try { ast = loose.parse(source, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true }); } catch { return; }
  walk.full(ast, (node) => {
    if ((node.type === 'ImportDeclaration' || node.type === 'ExportNamedDeclaration' ||
         node.type === 'ExportAllDeclaration') && node.source && typeof node.source.value === 'string') {
      classifySpec(node.source.value, 'import', signals, follow);
    }
    if (node.type === 'ImportExpression') {
      const spec = literalSpec(node.source);
      if (spec !== null) classifySpec(spec, 'import', signals, follow);
      else lateSpecs.push(['import', node.source]);
    }
    if (isProcessEnv(node)) signals.add('env: process.env');
    if (node.type === 'MemberExpression' && isProcessEnv(node.object)) {
      const name = propName(node);
      if (name && CRED_ENV.test(name)) signals.add(`cred: process.env.${name}`);
    }
    if (node.type === 'VariableDeclarator' && node.init && isProcessEnv(node.init) && node.id.type === 'ObjectPattern') {
      for (const p of node.id.properties) {
        const name = p.key && (p.key.name || p.key.value);
        if (typeof name === 'string' && CRED_ENV.test(name)) signals.add(`cred: process.env.${name}`);
      }
    }
    if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Function') {
      signals.add('obf: new Function() constructor');
    }
    if ((node.type === 'WhileStatement' || node.type === 'ForStatement' || node.type === 'DoWhileStatement') &&
        rotatesStringArray(node)) {
      signals.add(STRING_ARRAY_ROTATION);
    }
    if (node.type === 'Literal' && typeof node.value === 'string') {
      for (const [rt, how] of bootstrapHits(node.value)) if (!boots.has(rt)) boots.set(rt, how);
      literalIocs(node.value, iocs);
    }
    if (node.type === 'TemplateLiteral') {
      const text = node.quasis.map((q) => q.value.cooked || '').join('');
      for (const [rt, how] of bootstrapHits(text)) if (!boots.has(rt)) boots.set(rt, how);
      literalIocs(text, iocs);
    }
    if (node.type === 'BinaryExpression' && node.operator === '+') {
      folds.set(node, foldValue(node, { memo: folds }));
      foldParent.set(node.left, node).set(node.right, node);
    }
    if (node.type === 'VariableDeclarator' && node.init) bind(node.id, node.init);
    if (node.type === 'AssignmentExpression') bind(node.left, node.right);
    if (node.params) for (const param of node.params) bind(param, null);
    if (node.type !== 'CallExpression') return;
    const reqArg = requireArg(node);
    if (reqArg) {
      const spec = literalSpec(reqArg);
      if (spec !== null) classifySpec(spec, 'require', signals, follow);
      else lateSpecs.push(['require', reqArg]);
      return;
    }
    // (0, eval)(s) and (0, _cp.execSync)(cmd): the sequence only drops `this`
    const c = node.callee.type === 'SequenceExpression' ? node.callee.expressions.at(-1) : node.callee;
    const fn = c.type === 'Identifier' ? c.name
      : c.type === 'MemberExpression' && c.object.type === 'Identifier' && GLOBAL_OBJECTS.has(c.object.name) ? propName(c)
        : null;
    if (fn) {
      if (EXEC_FNS.has(fn)) {
        const cmd = argText(node.arguments[0]);
        signals.add(`exec: ${short(cmd.trim()) || `${fn}()`}`);
        spawnArgFiles(node.arguments);
        execCalls.push(node);
      } else if (fn === 'fetch') signals.add('net: fetch()');
      else if (fn === 'eval') {
        signals.add('obf: eval()');
        const body = argText(node.arguments[0]);
        if (body) decodeAndAnalyze(body);
      } else if (fn === 'Function') signals.add('obf: new Function() constructor');
      else if (fn === 'atob') {
        signals.add('obf: atob() base64 decode');
        const arg = argText(node.arguments[0]);
        if (arg) { try { decodeAndAnalyze(Buffer.from(arg, 'base64').toString('utf8')); } catch { /* not base64 */ } }
      }
    } else if (c.type === 'MemberExpression' && propName(c)) {
      const prop = propName(c);
      const recv = c.object.type === 'Identifier' ? c.object.name : '';
      // path.join(__dirname, ...) computing a .js path = an indirect local require
      if (prop === 'join' && recv === 'path' && node.arguments[0] &&
          node.arguments[0].type === 'Identifier' && node.arguments[0].name === '__dirname') {
        const parts = node.arguments.slice(1).map(argText);
        if (parts.every(Boolean) && /\.(js|cjs|mjs|ts|mts|cts)$/.test(parts[parts.length - 1])) {
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
      } else if (recv === 'process' && (prop === 'binding' || prop === '_linkedBinding')) {
        const name = foldValue(node.arguments[0]);
        if (RAW_BINDINGS.has(name)) signals.add(`${RAW_BINDINGS.get(name)}: process.${prop}('${name}')`);
      } else if (EXEC_FNS.has(prop) && (!AMBIGUOUS.has(prop) || EXEC_RECV.test(recv))) {
        const cmd = argText(node.arguments[0]);
        signals.add(`exec: ${short(cmd.trim()) || `${recv || '?'}.${prop}()`}`);
        spawnArgFiles(node.arguments);
        execCalls.push(node);
      } else if (NET_RECV.has(recv) && NET_FNS.has(prop)) {
        signals.add(`net: ${recv}.${prop}`);
      } else if (FS_FNS.has(prop) && (!AMBIGUOUS.has(prop) || /^fs/i.test(recv) || recv === 'promises')) {
        signals.add(`fs: ${recv ? `${recv}.` : ''}${prop}`);
      }
    }
  });
  for (const [kw, arg] of lateSpecs) lateSpec(kw, arg, bindings, signals, follow);
  // Only the widest literal chain: its inner links are substrings of it.
  for (const [node, text] of folds) if (text && !folds.get(foldParent.get(node))) literalIocs(text, iocs);
  for (const [rt, how] of boots) signals.add(bootstrapSignal(rt, how, spawnRuns));
  for (const call of execCalls) {
    const hit = localExec(call, bindings, where);
    if (!hit) continue;
    signals.add(`exec-local: ${hit.runtime} ${short(hit.file.label)}${hit.detached ? ' (detached)' : ''}`);
    if (hit.file.resolved) {
      const rel = posix.relative(posix.dirname(where.from), hit.file.resolved);
      follow.add(rel.startsWith('.') ? rel : `./${rel}`);
    }
  }
  for (const host of iocs.rpc) signals.add(`c2: ${host}`);
  if (iocs.ethCall) signals.add('c2: eth_call');
  if (iocs.rpc.size > 0) for (const addr of iocs.contracts) signals.add(`c2: contract ${addr}`);
  for (const e of iocs.exfil) signals.add(`exfil: ${e}`);
  for (const f of iocs.cred) signals.add(`cred: ${f}`);
}

// Split a shell line on top-level && || ; |, but not inside quotes, so
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

// What a shell part hands to a JavaScript runtime, before tarball resolution.
// null when the part does not invoke one; otherwise { runtime, kind, wrapper }
// plus `file` / `body` / `target`, where kind is:
//   file   a source file argument      eval   an inline -e/--eval/deno eval body
//   run    `bun run <target>`          other  a runtime subcommand with no file
//   none   a bare runtime (REPL), nothing to open
function runtimeInvocation(part, tokens) {
  let bin = binName(tokens[0]);
  let rest = tokens.slice(1);
  let wrapper = null;
  if (bin === 'npx' || bin === 'bunx' || (bin === 'bun' && rest[0] === 'x')) {
    wrapper = bin === 'npx' ? 'npx' : 'bunx';
    if (bin === 'bun') rest = rest.slice(1);
    const i = rest.findIndex((t) => !t.startsWith('-'));
    if (i < 0) return null;
    bin = binName(rest[i]).replace(/@.*$/, '');
    rest = rest.slice(i + 1);
    if (!DIRECT_RUNTIMES.has(bin) && bin !== 'deno') return null;
  }
  if (bin === 'deno') {
    if (rest[0] === 'eval' && rest[1]) return { runtime: 'deno', kind: 'eval', body: evalBody(part, true), wrapper };
    if (rest[0] !== 'run') return { runtime: 'deno', kind: 'other', wrapper };
    const file = rest.slice(1).find((t) => !t.startsWith('-'));
    return { runtime: 'deno', kind: file ? 'file' : 'other', file, wrapper };
  }
  if (!DIRECT_RUNTIMES.has(bin)) return null;
  const runtime = bin === 'nodejs' ? 'node' : bin;
  const evalIdx = rest.findIndex((t) => EVAL_FLAGS.has(t));
  if (evalIdx >= 0 && rest[evalIdx + 1]) return { runtime, kind: 'eval', body: evalBody(part, false), wrapper };
  if (bin === 'bun' && rest[0] === 'run') {
    const target = rest.slice(1).find((t) => !t.startsWith('-'));
    return { runtime, kind: target ? 'run' : 'other', target, wrapper };
  }
  if (bin === 'bun' && BUN_CMDS.has(rest[0])) return { runtime, kind: 'other', wrapper };
  const file = rest.find((t) => !t.startsWith('-'));
  return { runtime, kind: file ? 'file' : 'none', file, wrapper };
}

// The eval body after -e/--eval/-p/--print (or deno's `eval` subcommand),
// with one layer of shell quoting stripped.
const evalBody = (part, denoEval) => part.trim()
  .replace(denoEval ? /^.*?\beval\s+/ : /^.*?(?:-e|--eval|-p|--print)\s+/, '')
  .replace(/^(['"])([\s\S]*)\1$/, '$2');

// `npm i -g bun`: installing a runtime through the package manager is the
// same bootstrap as downloading its release archive.
function globalRuntimeInstalls(bin, tokens) {
  if (!RUNNERS.has(bin)) return [];
  const global = tokens.some((t) => t === '-g' || t === '--global') || (bin === 'yarn' && tokens[1] === 'global');
  const sub = bin === 'yarn' && tokens[1] === 'global' ? tokens[2] : tokens[1];
  if (!global || !['install', 'i', 'add'].includes(sub)) return [];
  return tokens.slice(2).map((t) => t.replace(/@.*$/, '')).filter((t) => RUNTIME_PKGS.has(t));
}

// Analyze one shell command line: known binaries are flagged directly,
// `npm run x` recurses into the package's own scripts, and a file handed to
// any runtime in the table (node, bun, deno run, tsx, ts-node, and the
// npx/bunx wrapper forms) is opened from the tarball and walked (following
// relative requires up to MAX_DEPTH / MAX_FILES).
function analyzeCommand(cmd, files, signals, scripts = {}, visited = new Set()) {
  const queue = [];
  const evalFollow = new Set();
  const boots = new Map();
  const runs = [];
  for (const part of splitShell(cmd)) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    // strip FOO=bar prefixes and transparent cross-env wrappers
    while (tokens.length > 0 && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0]) || tokens[0] === 'cross-env')) tokens.shift();
    if (tokens.length === 0) continue;
    const clean = tokens.join(' ');
    const bin = binName(tokens[0]);
    for (const [rt, how] of bootstrapHits(part)) if (!boots.has(rt)) boots.set(rt, how);
    const inv = runtimeInvocation(part, tokens);
    if (inv) {
      if (inv.wrapper) {
        signals.add(`exec: ${short(clean)}`);
        signals.add(`net: ${inv.wrapper} (may download the package it runs)`);
      }
      if (inv.kind === 'eval') {
        analyzeJs(inv.body, signals, evalFollow);
      } else if (inv.kind === 'run' && typeof scripts[inv.target] === 'string' && !visited.has(inv.target)) {
        visited.add(inv.target);
        analyzeCommand(scripts[inv.target], files, signals, scripts, visited);
      } else if (inv.kind === 'file' || inv.kind === 'run') {
        const file = inv.kind === 'run' ? inv.target : inv.file;
        const resolved = resolveFile(files, 'x', `./${file.replace(/^\.\//, '')}`);
        if (resolved) {
          queue.push({ path: resolved, depth: 0 });
          runs.push(resolved);
        } else if (inv.kind === 'run') {
          if (!visited.has(inv.target)) signals.add(`exec: ${short(clean)} (script not found)`);
        } else signals.add(`exec: ${inv.runtime} ${short(file)} (source not in tarball)`);
      } else if (inv.kind === 'other') {
        signals.add(`exec: ${short(clean)}`);
      }
    } else if (EXEC_BINS.has(bin)) signals.add(`exec: ${short(clean)}`);
    else if (NET_BINS.has(bin)) signals.add(`net: ${short(clean)}`);
    else if (bin === 'npx' || bin === 'bunx') {
      signals.add(`exec: ${short(clean)}`);
      signals.add(`net: ${bin} (may download the package it runs)`);
    } else if (RUNNERS.has(bin) && (tokens[1] === 'run' || tokens[1] === 'run-script') && tokens[2]) {
      const target = tokens[2];
      if (typeof scripts[target] === 'string' && !visited.has(target)) {
        visited.add(target);
        analyzeCommand(scripts[target], files, signals, scripts, visited);
      } else if (!visited.has(target)) signals.add(`exec: ${short(clean)} (script not found)`);
    } else if (!NOISE_BINS.has(bin)) {
      for (const rt of globalRuntimeInstalls(bin, tokens)) if (!boots.has(rt)) boots.set(rt, `installed via ${bin} -g`);
      signals.add(`exec: ${short(clean)} (unresolved binary)`);
    }
  }
  for (const spec of evalFollow) {
    const resolved = resolveFile(files, 'x', spec);
    if (resolved) queue.push({ path: resolved, depth: 0 });
  }
  for (const [rt, how] of boots) signals.add(bootstrapSignal(rt, how, [...new Set(runs)]));
  walkFiles(files, queue.map((q) => q.path), signals);
}

// The local files a shell line directly hands to a runtime, the "what does
// `node install.js` actually contain" surface the review command displays.
// Same runtime table as analyzeCommand (via runtimeInvocation), without
// collecting signals.
function commandEntryFiles(cmd, files) {
  const out = [];
  for (const part of splitShell(cmd)) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    while (tokens.length > 0 && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0]) || tokens[0] === 'cross-env')) tokens.shift();
    if (tokens.length === 0) continue;
    const inv = runtimeInvocation(part, tokens);
    if (!inv || (inv.kind !== 'file' && inv.kind !== 'run')) continue;
    const file = inv.kind === 'run' ? inv.target : inv.file;
    const resolved = resolveFile(files, 'x', `./${file.replace(/^\.\//, '')}`);
    if (resolved && !out.includes(resolved)) out.push(resolved);
  }
  return out;
}

// Walk entry files from the tarball index, following relative requires up to
// maxDepth / maxFiles. Shared by script analysis, cross-package bin/deep
// resolution and runtime-code analysis. byFile (a Map) collects each file's
// own signals; a shared `seen` lets several walks spend one file budget.
// partial means a limit cut the walk short.
function walkFiles(files, entryPaths, signals, byFile = null, { seen = new Set(), maxFiles = MAX_FILES, maxDepth = MAX_DEPTH } = {}) {
  const fresh = entryPaths.filter((p) => !seen.has(p));
  for (const p of fresh) seen.add(p);
  const queue = fresh.map((p) => ({ path: p, depth: 0 }));
  let partial = false;
  while (queue.length > 0 && seen.size <= maxFiles) {
    const { path, depth } = queue.shift();
    const follow = new Set();
    const own = byFile ? new Set() : signals;
    analyzeJs(files.get(path), own, follow, 0, { files, from: path });
    if (byFile) {
      byFile.set(path, own);
      for (const s of own) signals.add(s);
    }
    for (const spec of follow) {
      const resolved = resolveFile(files, path, spec);
      if (!resolved || seen.has(resolved)) continue;
      if (depth >= maxDepth) {
        partial = true;
        continue;
      }
      seen.add(resolved);
      queue.push({ path: resolved, depth: depth + 1 });
    }
  }
  return { partial: partial || queue.length > 0 };
}

// runtime: the signals come from main/exports/bin rather than a lifecycle
// script, where a library spawning node on its own worker file is routine
// enough that only the runtime diff and audit weigh it.
function score(signals, { runtime = false } = {}) {
  const kinds = new Set([...signals].map((s) => s.split(':')[0]));
  // c2 and exfil are endpoints, not capabilities: a literal Telegram bot URL
  // or Sepolia RPC host in shipped code is the payload's address book.
  if (kinds.has('c2') || kinds.has('exfil') || (runtime && kinds.has('exec-local'))) return 'HIGH';
  // A credential store read next to network access at install time is the
  // worm shape (Shai-Hulud, keyv/cacheable). Runtime code is exempt: every
  // registry client reads .npmrc and talks to the registry.
  if (!runtime && kinds.has('cred') && kinds.has('net')) return 'HIGH';
  // obf ranks with exec: code that decodes/constructs itself at install time
  // can do anything once it runs, and hiding is itself the signal. gyp joins
  // them: a binding.gyp command expansion is a shell command node-gyp runs
  // during configure, before a single line of C is compiled. bootstrap too:
  // installing another JS runtime at install time is how ChainDrop stepped
  // outside every Node-focused monitor.
  if (kinds.has('exec') || kinds.has('obf') || kinds.has('gyp') || kinds.has('bootstrap')) return 'HIGH';
  if (kinds.has('net')) return 'MEDIUM';
  if (kinds.has('fs') || kinds.has('env') || kinds.has('cred')) return 'LOW';
  return 'SAFE';
}

// A script that hands control to node-gyp, explicitly (`node-gyp rebuild`,
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
    for (const f of findings) {
      for (const [rt, how] of bootstrapHits(String(f.command))) gypSignals.push(bootstrapSignal(rt, how));
    }
    if (partial) gypSignals.push('gyp: binding.gyp did not parse, scanned as raw text');
    for (const n of notes) if (/not scanned/.test(n)) gypSignals.push(`gyp: ${short(n)}`);
  }
  return Object.entries(pkg.scripts).map(([script, command]) => {
    const signals = new Set();
    analyzeCommand(command, pkg.files, signals, pkg.allScripts || pkg.scripts, new Set([script]));
    if (RUNS_NODE_GYP.test(command)) for (const s of gypSignals) signals.add(s);
    return { script, command, risk: score(signals), signals: [...signals].sort() };
  });
}

// RUNTIME_BOOTSTRAP findings for one package's rows: one entry per runtime,
// detail carrying every distinct way it is obtained (and what it then runs).
function runtimeBootstrapFindings(rows) {
  const byRuntime = new Map();
  for (const row of rows || []) {
    for (const s of row.signals || []) {
      if (!s.startsWith('bootstrap: ')) continue;
      const rest = s.slice('bootstrap: '.length);
      const runtime = rest.split(/\s+/)[0];
      const detail = rest.slice(runtime.length + 1);
      const prev = byRuntime.get(runtime);
      if (!prev) byRuntime.set(runtime, [detail]);
      else if (!prev.includes(detail)) prev.push(detail);
    }
  }
  return [...byRuntime].map(([runtime, details]) => ({ runtime, detail: details.join('; ') }));
}

module.exports = {
  analyzePackage, analyzeCommand, analyzeJs, walkFiles, resolveFile, splitShell, score,
  commandEntryFiles, runtimeInvocation, runtimeBootstrapFindings, MAX_FILES,
  STRING_ARRAY_ROTATION,
};
