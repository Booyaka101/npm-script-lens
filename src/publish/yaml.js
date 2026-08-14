'use strict';
// The tolerant YAML-subset reader the CI-config scanners run on.
//
// Indentation-based mappings, `- ` list items, `|`/`>` block scalars (kept
// line-by-line so findings anchor to real line numbers), quoted keys/values,
// comments. Not a YAML parser but a structural reader for the small dialect CI
// configs actually use. Skips what it cannot read.

function stripComment(line) {
  let inS = false, inD = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "'" && !inD) inS = !inS;
    else if (c === '"' && !inS) inD = !inD;
    else if (c === '#' && !inS && !inD && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

const unquote = (s) => {
  const t = String(s).trim();
  if (t.length >= 2 && ((t[0] === '"' && t.endsWith('"')) || (t[0] === "'" && t.endsWith("'")))) return t.slice(1, -1);
  return t;
};

// node: { key, value, line, indent, children, item?, blockLines? }
function parseYamlish(text) {
  const root = { key: null, value: null, line: 0, indent: -1, children: [] };
  const stack = [root];
  let block = null; // active `|`/`>` scalar: { node, indent }
  text.split(/\r?\n/).forEach((raw, idx) => {
    const lineNo = idx + 1;
    if (block) {
      if (raw.trim() === '') { block.node.blockLines.push({ line: lineNo, text: '' }); return; }
      const ind = raw.match(/^ */)[0].length;
      if (ind > block.indent) { block.node.blockLines.push({ line: lineNo, text: raw.trim() }); return; }
      block = null; // dedented: fall through to normal handling
    }
    const noComment = stripComment(raw);
    if (noComment.trim() === '' || /^\s*---\s*$/.test(noComment)) return;
    if (/^\t/.test(noComment)) return; // tabs are invalid YAML indentation, skip, stay tolerant
    let indent = noComment.match(/^ */)[0].length;
    let rest = noComment.slice(indent).trimEnd();
    while (stack[stack.length - 1].indent >= indent) stack.pop();
    // `- ` list items (possibly nested `- - x`); the item's children indent
    // from the column after the dash
    while (rest === '-' || rest.startsWith('- ')) {
      const item = { key: null, value: null, line: lineNo, indent, children: [], item: true };
      stack[stack.length - 1].children.push(item);
      stack.push(item);
      indent += 2;
      rest = rest === '-' ? '' : rest.slice(2).trim();
    }
    if (rest === '') return;
    const m = rest.match(/^("[^"]*"|'[^']*'|[^\s:][^:]*?)\s*:(?:\s+(.*))?$/);
    if (!m) {
      // a bare scalar: the value of the list item we just opened (e.g.
      // `- npm publish` in a gitlab script array)
      const top = stack[stack.length - 1];
      if (top.item && top.value === null && top.children.length === 0) { top.value = rest; top.line = lineNo; }
      return;
    }
    const node = { key: unquote(m[1]), value: m[2] === undefined || m[2] === '' ? null : m[2].trim(), line: lineNo, indent, children: [] };
    if (node.value !== null && /^[|>][+-]?\d*$/.test(node.value)) {
      node.value = null;
      node.blockLines = [];
      block = { node, indent: node.indent };
    }
    stack[stack.length - 1].children.push(node);
    stack.push(node);
  });
  return root;
}

const child = (node, key) => (node ? node.children.find((c) => c.key === key) : undefined);

// Every scalar line under a node that could hold shell commands: the node's
// own value, its block-scalar lines, and bare list items (gitlab script:).
function commandLines(node) {
  if (!node) return [];
  const out = [];
  if (node.value !== null && node.value !== undefined) out.push({ line: node.line, text: node.value });
  for (const b of node.blockLines || []) if (b.text) out.push({ line: b.line, text: b.text });
  for (const c of node.children) {
    if (c.item && c.value) out.push({ line: c.line, text: c.value });
  }
  return out;
}
module.exports = { stripComment, unquote, parseYamlish, child, commandLines };
