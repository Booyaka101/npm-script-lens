'use strict';
// Terminal layout for the text reports. Renderers emit one logical line per
// fact; this reflows the prose ones to the terminal width at the point they
// are written.
//
// Wrapping happens ONLY when stdout is a TTY. Piped and redirected output
// (CI logs, `> report.md`, the test suite) stays byte-identical to what the
// renderer produced, so nothing downstream has to parse a reflowed line.

const MIN_WIDTH = 60;
const MAX_WIDTH = 100;

function terminalWidth(stream = process.stdout) {
  if (!stream || !stream.isTTY || !stream.columns) return null;
  return Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, stream.columns - 1));
}

// Lines that must survive intact: diff/patch bodies, JSON, markdown tables,
// code, and anything too short to be a sentence.
const NOT_PROSE = /^\s*([-+|{}[\]"'`]|\d+\.\s)/;

// Continuation lines align under where the text starts, so a wrapped
// `gate:    AUTO: ...` reads like the hand-aligned fix blocks beside it. The
// prefix is the indent, any leading glyph (⛔, ℹ️, ✅) and a `label:` run; it
// is copied verbatim onto the first line, so column alignment survives.
//
// Labels are matched as ASCII on purpose. Every label this tool emits is
// ASCII, and the Unicode letter class is not a safe way to tell a glyph from
// a label: `ℹ` (U+2139) is categorized as a letter, so \p{L} claims it.
const PREFIX = /^(\s*)((?:[^A-Za-z0-9\s][^A-Za-z0-9]*\s+)?)((?:[A-Za-z][A-Za-z0-9 ./-]*:[ \t]+)?)/;

// Aligned columns after the prefix mean the line is a data row, not prose;
// reflowing it would destroy the alignment it was built with.
const isAligned = (rest) => /\S {2,}\S/.test(rest);

function isProse(line) {
  if (NOT_PROSE.test(line)) return false;
  const m = line.match(PREFIX);
  if (isAligned(line.slice(m ? m[0].length : 0))) return false;
  return line.trim().split(/\s+/).length >= 8;
}

// Variation selectors (U+FE0F in `ℹ️`, `⚠️`) take a code unit but no column,
// so they must not count toward the continuation indent.
const columns = (s) => s.replace(/️/g, '').length;

function splitPrefix(line) {
  const m = line.match(PREFIX);
  const prefix = m ? m[0] : '';
  // a "prefix" past the halfway mark is a false positive, keep the indent only
  if (prefix.length > line.length / 2) {
    const indent = line.match(/^\s*/)[0];
    return { prefix: indent, hang: `${indent}  ` };
  }
  return { prefix, hang: ' '.repeat(columns(prefix)) };
}

function wrapLine(line, width) {
  const { prefix, hang } = splitPrefix(line);
  const words = line.slice(prefix.length).split(/\s+/).filter(Boolean);
  const out = [];
  let current = prefix;
  let empty = true;
  for (const word of words) {
    const candidate = empty ? current + word : `${current} ${word}`;
    // a word longer than the remaining width gets its own line rather than
    // being broken mid-token (URLs, file paths, `--flags`)
    if (candidate.length > width && !empty) {
      out.push(current);
      current = hang + word;
    } else {
      current = candidate;
    }
    empty = false;
  }
  if (current.trim() !== '') out.push(current);
  return out.join('\n');
}

function wrapReport(text, width = terminalWidth()) {
  if (!width) return text;
  return text.split('\n')
    .map((line) => (line.length > width && isProse(line) ? wrapLine(line, width) : line))
    .join('\n');
}

// The one place a text report reaches the user.
function writeReport(text, stream = process.stdout) {
  stream.write(`${wrapReport(text, terminalWidth(stream))}\n`);
}

module.exports = { writeReport, wrapReport, wrapLine, isProse, terminalWidth, MIN_WIDTH, MAX_WIDTH };
