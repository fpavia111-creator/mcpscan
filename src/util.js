'use strict';
const fs = require('fs');

/** Strip // and /* *\/ comments and trailing commas from JSONC, respecting strings. */
function stripJsonc(text) {
  let out = '';
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i], n = text[i + 1];
    if (inStr) {
      out += c;
      if (c === '\\') { out += n || ''; i++; } else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === '/' && n === '/') { while (i < text.length && text[i] !== '\n') i++; out += '\n'; continue; }
    if (c === '/' && n === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i++; continue; }
    out += c;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

function parseJsonc(text) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  try { return JSON.parse(text); } catch { return JSON.parse(stripJsonc(text)); }
}

function readJsonFile(file) {
  return parseJsonc(fs.readFileSync(file, 'utf8'));
}

function isFile(p) { try { return fs.statSync(p).isFile(); } catch { return false; } }
function isDir(p) { try { return fs.statSync(p).isDirectory(); } catch { return false; } }

/** Mask a secret: never print it in full. */
function mask(value) {
  const s = String(value);
  if (s.length <= 8) return '*'.repeat(Math.max(4, s.length)) + ` (${s.length} chars)`;
  return `${s.slice(0, 4)}${'*'.repeat(8)} (${s.length} chars)`;
}

/** 1-based line number of a character offset. */
function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

module.exports = { stripJsonc, parseJsonc, readJsonFile, isFile, isDir, mask, lineOf };
