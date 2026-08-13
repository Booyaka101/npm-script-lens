'use strict';
// binding.gyp / .gypi content scanner. Until now the tool only checked that a
// binding.gyp EXISTS (the implicit `node-gyp rebuild`); this module reads what
// is inside it. GYP files are Python-literal dicts, NOT JSON, single-quoted
// strings, `#` line comments, trailing commas, so JSON.parse cannot read the
// real ones (better-sqlite3's opens with a `#` banner and single-quoted keys).
//
// The expansion signature set is taken from gyp-next pylib/gyp/input.py
// (early_variable_re / late_variable_re / latelate_variable_re): prefixes `<`
// (early), `>` (late), `^` (latelate); modifiers `!` (command expansion
// gyp runs the inner text via subprocess.run(..., shell=use_shell)), `!@`
// (command expansion split into a list), `|` (listfile). `<!pymod_do_main(mod
// args)` imports `mod` as a Python module and calls its DoMain(). Plain
// `<(var)` / `>(var)` / `^(var)` / `<@(var)` are ordinary variable
// interpolation and MUST NOT be flagged (bufferutil's `<(clang_version)`).
//
// Structural channels (the Aikido 2026-06-09 teardown's full list): explicit
// `actions[].action` / `rules[].action` / `postbuilds[].action` command
// steps, `make_global_settings` compiler/linker hijack, and `conditions`
// strings that reach for the Python eval sandbox escape
// (__class__/__subclasses__/__import__/__builtins__).

const MAX_FILE_BYTES = 2 * 1024 * 1024; // matches registry.js indexing cap
const MAX_GYP_FILES = 10;

const KIND_LABEL = {
  command: 'command expansion',
  pymod: 'Python module DoMain() call',
  listfile: 'listfile expansion',
  action: 'build action',
  toolchain: 'toolchain override',
  pyeval: 'Python eval escape in condition',
};

const shortCmd = (s) => (s.length > 100 ? `${s.slice(0, 97)}...` : s);

// --- tolerant GYP tokenizer/parser -----------------------------------------
// Produces plain dicts/arrays; string values are String OBJECTS carrying a
// .line property so both the literal scan and the structural walk can anchor
// findings to a line. Dicts carry a hidden __keyLines__ map for key anchors.

function tokenize(text) {
  const tokens = [];
  let line = 1;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\n') { line++; continue; }
    if (ch === ' ' || ch === '\t' || ch === '\r') continue;
    if (ch === '#') { // line comment (only reachable outside a string literal)
      while (i < text.length && text[i] !== '\n') i++;
      i--; continue;
    }
    if (ch === "'" || ch === '"') {
      const startLine = line;
      let value = '';
      i++;
      for (; i < text.length; i++) {
        const c = text[i];
        if (c === '\\') {
          const n = text[i + 1];
          // Python semantics: recognized escapes resolve, unknown ones keep
          // the backslash (bufferutil has both \' and \\. in one string)
          if (n === ch || n === '\\') { value += n; i++; }
          else if (n === 'n') { value += '\n'; i++; }
          else if (n === 't') { value += '\t'; i++; }
          else if (n === 'r') { value += '\r'; i++; }
          else value += c;
        } else if (c === ch) break;
        else {
          if (c === '\n') line++;
          value += c;
        }
      }
      if (i >= text.length) throw new Error(`unterminated string at line ${startLine}`);
      tokens.push({ type: 'string', value, line: startLine });
      continue;
    }
    if ('{}[],:'.includes(ch)) { tokens.push({ type: ch, line }); continue; }
    if (/[-0-9]/.test(ch)) {
      let j = i;
      while (j < text.length && /[-0-9.eE+]/.test(text[j])) j++;
      tokens.push({ type: 'number', value: Number(text.slice(i, j)), line });
      i = j - 1; continue;
    }
    if (/[A-Za-z_]/.test(ch)) { // tolerate bare true/false/null
      let j = i;
      while (j < text.length && /[A-Za-z_]/.test(text[j])) j++;
      const word = text.slice(i, j);
      if (word === 'true' || word === 'True') tokens.push({ type: 'number', value: true, line });
      else if (word === 'false' || word === 'False') tokens.push({ type: 'number', value: false, line });
      else if (word === 'null' || word === 'None') tokens.push({ type: 'number', value: null, line });
      else throw new Error(`unexpected token "${word}" at line ${line}`);
      i = j - 1; continue;
    }
    throw new Error(`unexpected character "${ch}" at line ${line}`);
  }
  return tokens;
}

function parseGyp(text) {
  const tokens = tokenize(text);
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];
  const expect = (type) => {
    const t = next();
    if (!t || t.type !== type) throw new Error(`expected "${type}" at line ${t ? t.line : '<eof>'}`);
    return t;
  };
  function parseValue() {
    const t = peek();
    if (!t) throw new Error('unexpected end of input');
    if (t.type === 'string') { next(); return Object.assign(new String(t.value), { line: t.line }); }
    if (t.type === 'number') { next(); return t.value; }
    if (t.type === '{') {
      next();
      const dict = {};
      const keyLines = {};
      Object.defineProperty(dict, '__keyLines__', { value: keyLines, enumerable: false });
      while (peek() && peek().type !== '}') {
        const key = expect('string');
        expect(':');
        dict[key.value] = parseValue();
        keyLines[key.value] = key.line;
        if (peek() && peek().type === ',') next(); // trailing commas tolerated
        else break;
      }
      expect('}');
      return dict;
    }
    if (t.type === '[') {
      next();
      const arr = [];
      while (peek() && peek().type !== ']') {
        arr.push(parseValue());
        if (peek() && peek().type === ',') next();
        else break;
      }
      expect(']');
      return arr;
    }
    throw new Error(`unexpected "${t.type}" at line ${t.line}`);
  }
  const value = parseValue();
  if (pos < tokens.length) throw new Error(`trailing content at line ${tokens[pos].line}`);
  return value;
}

// --- (a) string-literal expansion scan --------------------------------------

// Mirror of gyp's variable regexes: prefix, optional modifier, optional
// command_string, opening paren. `@` alone (array variable, e.g. `<@(deps)`)
// and no modifier at all are plain interpolation, skipped below.
const EXPANSION_RE = /([<>^])(!@?|\||@)?([-a-zA-Z0-9_.]+)?\(/g;

// Balance-count from `start` (index just past the opening paren): nested
// parens inside the command, bufferutil's `<!(perl -e 'print <(clang_version)
// cmp 12.0.0')`, must not stop at the first `)`.
function readBalanced(s, start) {
  let depth = 1;
  for (let i = start; i < s.length; i++) {
    if (s[i] === '(') depth++;
    else if (s[i] === ')' && --depth === 0) return { command: s.slice(start, i), truncated: false };
  }
  return { command: s.slice(start), truncated: true };
}

// Scan one string literal for expansion signatures. `line` anchors findings.
function scanString(value, { file = null, line = null } = {}) {
  const findings = [];
  EXPANSION_RE.lastIndex = 0;
  let m;
  while ((m = EXPANSION_RE.exec(value)) !== null) {
    const [, prefix, modifier, commandString] = m;
    if (!modifier || modifier === '@') continue; // plain <(var) / <@(var): interpolation, not execution
    if (modifier === '|') {
      const { command, truncated } = readBalanced(value, m.index + m[0].length);
      const f = { kind: 'listfile', channel: `${prefix}|(`, command, file, line, snippet: shortCmd(value.slice(m.index)) };
      if (truncated) f.truncated = true;
      findings.push(f);
    } else { // '!' or '!@'
      const kind = commandString === 'pymod_do_main' ? 'pymod' : 'command';
      const channel = `${prefix}${modifier}${commandString || ''}(`;
      const { command, truncated } = readBalanced(value, m.index + m[0].length);
      const f = { kind, channel, command, file, line, snippet: shortCmd(value.slice(m.index)) };
      if (truncated) f.truncated = true;
      findings.push(f);
    }
  }
  return findings;
}

// Fallback when structural parsing fails: scan raw text line by line (comments
// can't be reliably stripped without the tokenizer, but a `#` comment naming
// an expansion is a hit worth surfacing over a silent pass).
function scanRawText(text, file) {
  const findings = [];
  text.split(/\r?\n/).forEach((l, idx) => {
    findings.push(...scanString(l, { file, line: idx + 1 }));
  });
  return findings;
}

// --- (b) structural walk -----------------------------------------------------

const PYEVAL_RE = /__class__|__subclasses__|__import__|__builtins__/;
const ACTION_KEYS = { actions: 'actions[].action', rules: 'rules[].action', postbuilds: 'postbuilds[].action' };

const strVal = (v) => (v instanceof String || typeof v === 'string' ? String(v) : null);
const lineOfVal = (v) => (v instanceof String && v.line ? v.line : null);

function flattenStrings(v, out = []) {
  if (v instanceof String || typeof v === 'string') out.push(String(v));
  else if (Array.isArray(v)) for (const e of v) flattenStrings(e, out);
  else if (v && typeof v === 'object') for (const e of Object.values(v)) flattenStrings(e, out);
  return out;
}

function walkStructure(node, file, findings) {
  if (Array.isArray(node)) {
    for (const e of node) walkStructure(e, file, findings);
    return;
  }
  if (!node || typeof node !== 'object' || node instanceof String) return;
  const keyLines = node.__keyLines__ || {};
  for (const [key, value] of Object.entries(node)) {
    if (ACTION_KEYS[key] && Array.isArray(value)) {
      for (const step of value) {
        if (!step || typeof step !== 'object' || !Array.isArray(step.action)) continue;
        const cmd = step.action.map((a) => strVal(a) ?? '').join(' ').trim();
        const nameLine = step.action.map(lineOfVal).find(Boolean) || keyLines[key] || null;
        findings.push({ kind: 'action', channel: ACTION_KEYS[key], command: cmd, file, line: nameLine, snippet: shortCmd(cmd) });
      }
    } else if (key === 'make_global_settings') {
      const cmd = flattenStrings(value).join(' ');
      findings.push({ kind: 'toolchain', channel: 'make_global_settings', command: cmd, file, line: keyLines[key] || null, snippet: shortCmd(cmd) });
    } else if (key === 'conditions' && Array.isArray(value)) {
      // each entry: [condStr, dict] or [condStr, dict, elseDict]
      for (const entry of value) {
        if (!Array.isArray(entry)) continue;
        const cond = strVal(entry[0]);
        if (cond && PYEVAL_RE.test(cond)) {
          findings.push({ kind: 'pyeval', channel: 'conditions', command: cond, file, line: lineOfVal(entry[0]) || keyLines[key] || null, snippet: shortCmd(cond) });
        }
      }
    }
    walkStructure(value, file, findings);
  }
}

// --- public API ---------------------------------------------------------------

// Scan one gyp/gypi file's text. Returns { findings, partial, includes }.
// partial=true means the structural parse failed and only the string-literal
// scan ran (never a silent pass). includes = files this one pulls in
// (`includes` arrays + `dependencies` entries of the form "path/x.gyp:target"),
// unresolved, for collectGypFindings to follow.
function scanGyp(text, { file = null } = {}) {
  let parsed;
  try { parsed = parseGyp(text); } catch {
    return { findings: scanRawText(text, file), partial: true, includes: [] };
  }
  const findings = [];
  const strings = [];
  const includes = [];
  const collect = (node) => {
    if (node instanceof String) { strings.push(node); return; }
    if (Array.isArray(node)) { for (const e of node) collect(e); return; }
    if (!node || typeof node !== 'object') return;
    for (const [key, value] of Object.entries(node)) {
      if (key === 'includes' && Array.isArray(value)) {
        for (const inc of value) { const s = strVal(inc); if (s) includes.push(s); }
      } else if (key === 'dependencies' && Array.isArray(value)) {
        for (const dep of value) {
          const s = strVal(dep);
          const m = s && s.match(/^([^:]+\.gypi?)(?::|$)/);
          if (m) includes.push(m[1]);
        }
      }
      collect(value);
    }
  };
  collect(parsed);
  for (const s of strings) findings.push(...scanString(String(s), { file, line: s.line || null }));
  walkStructure(parsed, file, findings);
  return { findings, partial: false, includes };
}

// Resolve "deps/common.gypi" against the directory of the file including it,
// with the same forward-slash keys the tarball index uses.
function resolveInclude(from, spec) {
  const base = from.split('/').slice(0, -1);
  for (const part of spec.replace(/\\/g, '/').split('/')) {
    if (part === '..') base.pop();
    else if (part !== '.' && part !== '') base.push(part);
  }
  return base.join('/');
}

// Scan a package's binding.gyp plus the .gyp/.gypi files it pulls in, one
// include level, resolved against the tarball/node_modules file index, at most
// MAX_GYP_FILES files, cycle-guarded (better-sqlite3 keeps its real payload in
// deps/common.gypi behind `'includes': ['deps/common.gypi']`).
// Returns { findings, partial, notes }.
function collectGypFindings(files, entry = 'binding.gyp') {
  const findings = [];
  const notes = [];
  let partial = false;
  const visited = new Set();
  const scanFile = (name) => {
    if (visited.has(name) || visited.size >= MAX_GYP_FILES) return null;
    visited.add(name);
    const text = files.get(name);
    if (typeof text !== 'string') {
      notes.push(`${name}: referenced but not in the package file index (missing or over the ${MAX_FILE_BYTES / 1024 / 1024} MB cap) — not scanned`);
      return null;
    }
    if (text.length > MAX_FILE_BYTES) {
      notes.push(`${name}: over the ${MAX_FILE_BYTES / 1024 / 1024} MB cap — not scanned`);
      return null;
    }
    const result = scanGyp(text, { file: name });
    findings.push(...result.findings);
    if (result.partial) {
      partial = true;
      notes.push(`${name}: did not parse as a GYP structure — string-literal scan only`);
    }
    return result;
  };
  const root = scanFile(entry);
  if (root) {
    for (const inc of root.includes) scanFile(resolveInclude(entry, inc));
  }
  return { findings, partial, notes };
}

module.exports = { scanGyp, collectGypFindings, scanString, parseGyp, resolveInclude, KIND_LABEL };
