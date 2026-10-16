'use strict';
// A small JSON / JSONC parser that reports what JSON.parse hides.
//
// Why not JSON.parse: it silently keeps the LAST of two duplicate keys and rejects a byte-order
// mark, while other consumers of the same file (VS Code's JSONC reader, Python, editors) may
// disagree. A guard must notice every place where two tools could read one file two ways, so
// this parser returns the value AND the list of duplicate key paths, and it accepts comments
// and trailing commas only when asked (MCP configs are JSONC in VS Code and Cursor).
//
// parseJson(text, { jsonc }) -> { value, duplicates: [path...], bom: bool }
// Throws SyntaxError on anything else. Iterative depth is capped to bound the stack.
//
// Every object is null-prototype, and the keys "__proto__", "constructor" and "prototype" are
// refused outright (SyntaxError, which callers report as unknown:ambiguous): a key that some
// reader would treat as a prototype instead of data is evasion-shaped, never a dependency.

const MAX_DEPTH = 256;
const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function parseJson(text, { jsonc = false } = {}) {
  let s = String(text);
  const bom = s.charCodeAt(0) === 0xfeff;
  if (bom) s = s.slice(1);
  let i = 0;
  const duplicates = [];

  const fail = (msg) => { throw new SyntaxError(`${msg} at offset ${i}`); };

  function ws() {
    for (;;) {
      const c = s.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) { i++; continue; }
      if (jsonc && c === 0x2f /* / */) {
        const n = s.charCodeAt(i + 1);
        if (n === 0x2f) { const e = s.indexOf('\n', i + 2); i = e < 0 ? s.length : e + 1; continue; }
        if (n === 0x2a) { const e = s.indexOf('*/', i + 2); if (e < 0) fail('unterminated comment'); i = e + 2; continue; }
      }
      return;
    }
  }

  function str() {
    // s[i] === '"'
    i++;
    let out = '';
    let start = i;
    for (;;) {
      if (i >= s.length) fail('unterminated string');
      const c = s.charCodeAt(i);
      if (c === 0x22) { out += s.slice(start, i); i++; return out; }
      if (c < 0x20) fail('control character in string');
      if (c === 0x5c) {
        out += s.slice(start, i);
        const e = s[i + 1];
        const map = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
        if (e === 'u') {
          const h = s.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) fail('bad \\u escape');
          out += String.fromCharCode(parseInt(h, 16));
          i += 6;
        } else if (e !== undefined && Object.prototype.hasOwnProperty.call(map, e)) { out += map[e]; i += 2; }
        else fail('bad escape');
        start = i;
        continue;
      }
      i++;
    }
  }

  const NUM = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

  function value(pathStr, depth) {
    if (depth > MAX_DEPTH) fail('nesting too deep');
    ws();
    const c = s[i];
    if (c === '{') {
      i++;
      const obj = Object.create(null);
      const seen = new Set();
      ws();
      if (s[i] === '}') { i++; return obj; }
      for (;;) {
        ws();
        if (s[i] !== '"') { if (jsonc && s[i] === '}') { i++; return obj; } fail('expected key'); }
        const k = str();
        if (RESERVED_KEYS.has(k)) fail(`reserved key "${k}" (prototype-shaped keys are refused)`);
        const kp = pathStr ? `${pathStr}.${k}` : k;
        if (seen.has(k)) duplicates.push(kp);
        seen.add(k);
        ws();
        if (s[i] !== ':') fail('expected :');
        i++;
        obj[k] = value(kp, depth + 1); // last wins, exactly like JSON.parse; the duplicate is reported
        ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === '}') { i++; return obj; }
        fail('expected , or }');
      }
    }
    if (c === '[') {
      i++;
      const arr = [];
      ws();
      if (s[i] === ']') { i++; return arr; }
      for (;;) {
        ws();
        if (jsonc && s[i] === ']' && arr.length) { i++; return arr; }
        arr.push(value(`${pathStr}[${arr.length}]`, depth + 1));
        ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === ']') { i++; return arr; }
        fail('expected , or ]');
      }
    }
    if (c === '"') return str();
    if (s.startsWith('true', i)) { i += 4; return true; }
    if (s.startsWith('false', i)) { i += 5; return false; }
    if (s.startsWith('null', i)) { i += 4; return null; }
    NUM.lastIndex = i;
    const m = NUM.exec(s);
    if (m && m[0]) { i += m[0].length; return Number(m[0]); }
    fail('unexpected token');
  }


  const v = value('', 0);
  ws();
  if (i !== s.length) fail('trailing data');
  return { value: v, duplicates, bom };
}

module.exports = { parseJson };
