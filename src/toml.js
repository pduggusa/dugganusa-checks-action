'use strict';
// A strict, dependency-free TOML 1.0 parser, sized for pyproject.toml and poetry.lock.
//
// The previous line-regex reader could be steered by a "]" inside a comment, a multi-line
// string, an inline table or a dotted key into closing an array early, so later entries were
// never seen while pip/uv/poetry still installed them. A real parser removes that whole class:
// either we read the document the way tomllib does, or we throw and the caller reports the
// file as UNKNOWN. Duplicate keys and table redefinition throw, as they do in tomllib.

const MAX_DEPTH = 128;

function parseToml(text) {
  let s = String(text);
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  let i = 0;
  const root = {};
  const explicit = new Set();   // tables defined by a [header]
  const inline = new WeakSet(); // inline tables/arrays: closed once written
  const arrayTables = new WeakSet();
  let cur = root;

  const fail = (msg) => { const line = s.slice(0, i).split('\n').length; throw new SyntaxError(`TOML: ${msg} (line ${line})`); };
  const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const isTable = (v) => v && typeof v === 'object' && !Array.isArray(v);

  function wsInline() { while (i < s.length && (s[i] === ' ' || s[i] === '\t')) i++; }
  function comment() { if (s[i] === '#') { while (i < s.length && s[i] !== '\n') { const c = s.charCodeAt(i); if ((c < 0x20 && c !== 0x09) || c === 0x7f) fail('control character in comment'); i++; } } }
  function eol() {
    wsInline(); comment();
    if (i >= s.length) return;
    if (s[i] === '\r' && s[i + 1] === '\n') { i += 2; return; }
    if (s[i] === '\n') { i++; return; }
    fail('expected end of line');
  }
  // whitespace, newlines and comments (inside arrays)
  function wsAll() { for (;;) { wsInline(); comment(); if (s[i] === '\n') { i++; continue; } if (s[i] === '\r' && s[i + 1] === '\n') { i += 2; continue; } return; } }

  function basicString() {
    // s[i] === '"', not a multi-line opener
    i++;
    let out = '';
    for (;;) {
      if (i >= s.length || s[i] === '\n') fail('unterminated string');
      const c = s[i];
      if (c === '"') { i++; return out; }
      if (c === '\\') { out += escape(); continue; }
      const cc = c.charCodeAt(0);
      if ((cc < 0x20 && cc !== 0x09) || cc === 0x7f) fail('control character in string');
      out += c; i++;
    }
  }
  function escape() {
    const e = s[i + 1];
    const map = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };
    if (e !== undefined && own(map, e)) { i += 2; return map[e]; }
    if (e === 'u' || e === 'U') {
      const n = e === 'u' ? 4 : 8;
      const h = s.slice(i + 2, i + 2 + n);
      if (!new RegExp(`^[0-9a-fA-F]{${n}}$`).test(h)) fail('bad unicode escape');
      const cp = parseInt(h, 16);
      if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) fail('bad unicode scalar');
      i += 2 + n;
      return String.fromCodePoint(cp);
    }
    fail('bad escape');
  }
  function mlBasic() {
    i += 3;
    if (s[i] === '\n') i++; else if (s[i] === '\r' && s[i + 1] === '\n') i += 2;
    let out = '';
    for (;;) {
      if (i >= s.length) fail('unterminated multi-line string');
      if (s.startsWith('"""', i)) {
        let q = 3; while (s[i + q] === '"' && q < 5) q++;
        out += '"'.repeat(q - 3); i += q; return out;
      }
      const c = s[i];
      if (c === '\\') {
        // line-ending backslash: trim whitespace and newlines up to the next content
        let j = i + 1; while (s[j] === ' ' || s[j] === '\t') j++;
        if (s[j] === '\n' || (s[j] === '\r' && s[j + 1] === '\n')) {
          i = j; while (i < s.length && /[ \t\r\n]/.test(s[i])) i++;
          continue;
        }
        out += escape(); continue;
      }
      const cc = c.charCodeAt(0);
      if ((cc < 0x20 && cc !== 0x09 && cc !== 0x0a && cc !== 0x0d) || cc === 0x7f) fail('control character in string');
      out += c; i++;
    }
  }
  function literal() {
    i++;
    const e = s.indexOf("'", i);
    const nl = s.indexOf('\n', i);
    if (e < 0 || (nl >= 0 && nl < e)) fail('unterminated literal string');
    const out = s.slice(i, e);
    if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(out)) fail('control character in literal string');
    i = e + 1;
    return out;
  }
  function mlLiteral() {
    i += 3;
    if (s[i] === '\n') i++; else if (s[i] === '\r' && s[i + 1] === '\n') i += 2;
    const e = s.indexOf("'''", i);
    if (e < 0) fail('unterminated multi-line literal');
    let end = e; let q = 3; while (s[e + q] === "'" && q < 5) q++;
    end = e + q - 3;
    const out = s.slice(i, end);
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(out)) fail('control character in literal string');
    i = e + q;
    return out;
  }

  function key() {
    // dotted key -> array of parts
    const parts = [];
    for (;;) {
      wsInline();
      if (s[i] === '"') { if (s.startsWith('"""', i)) fail('multi-line key'); parts.push(basicString()); }
      else if (s[i] === "'") { if (s.startsWith("'''", i)) fail('multi-line key'); parts.push(literal()); }
      else {
        const m = /[A-Za-z0-9_-]+/y; m.lastIndex = i;
        const r = m.exec(s); if (!r) fail('expected key');
        parts.push(r[0]); i += r[0].length;
      }
      wsInline();
      if (s[i] === '.') { i++; continue; }
      return parts;
    }
  }

  const DATE = /(\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:[Zz]|[+-]\d{2}:\d{2})?)?|\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)/y;
  const NUMBER = /[+-]?(?:0x[0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0o[0-7](?:_?[0-7])*|0b[01](?:_?[01])*|inf|nan|(?:0|[1-9](?:_?\d)*)(?:\.\d(?:_?\d)*)?(?:[eE][+-]?\d(?:_?\d)*)?)/y;

  function val(depth) {
    if (depth > MAX_DEPTH) fail('nesting too deep');
    const c = s[i];
    if (c === '"') return s.startsWith('"""', i) ? mlBasic() : basicString();
    if (c === "'") return s.startsWith("'''", i) ? mlLiteral() : literal();
    if (c === '[') {
      i++;
      const arr = [];
      inline.add(arr);
      for (;;) {
        wsAll();
        if (s[i] === ']') { i++; return arr; }
        arr.push(val(depth + 1));
        wsAll();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === ']') { i++; return arr; }
        fail('expected , or ] in array');
      }
    }
    if (c === '{') {
      i++;
      const t = {};
      inline.add(t);
      wsInline();
      if (s[i] === '}') { i++; return t; }
      for (;;) {
        const k = key();
        if (s[i] !== '=') fail('expected = in inline table');
        i++; wsInline();
        assign(t, k, val(depth + 1), true);
        wsInline();
        if (s[i] === ',') { i++; wsInline(); continue; }
        if (s[i] === '}') { i++; return t; }
        fail('expected , or } in inline table');
      }
    }
    if (s.startsWith('true', i) && !/[A-Za-z0-9_]/.test(s[i + 4] || '')) { i += 4; return true; }
    if (s.startsWith('false', i) && !/[A-Za-z0-9_]/.test(s[i + 5] || '')) { i += 5; return false; }
    DATE.lastIndex = i;
    const d = DATE.exec(s);
    if (d && d[0].length >= 5 && /[-:]/.test(d[0])) { i += d[0].length; return d[0]; }
    NUMBER.lastIndex = i;
    const n = NUMBER.exec(s);
    if (n && n[0]) { i += n[0].length; return Number(n[0].replace(/_/g, '')); }
    fail('unexpected value');
  }

  function assign(table, parts, v, inInline) {
    let t = table;
    for (let k = 0; k < parts.length - 1; k++) {
      const p = parts[k];
      if (!own(t, p)) { t[p] = {}; }
      else if (!isTable(t[p]) || (inline.has(t[p]) && !inInline) || explicit.has(t[p])) fail(`key ${parts.join('.')} redefines a value`);
      t = t[p];
    }
    const last = parts[parts.length - 1];
    if (own(t, last)) fail(`duplicate key ${parts.join('.')}`);
    t[last] = v;
  }

  function header(isArray) {
    i += isArray ? 2 : 1;
    const parts = key();
    if (isArray) { if (!s.startsWith(']]', i)) fail('expected ]]'); i += 2; }
    else { if (s[i] !== ']') fail('expected ]'); i++; }
    let t = root;
    for (let k = 0; k < parts.length - 1; k++) {
      const p = parts[k];
      if (!own(t, p)) t[p] = {};
      let nx = t[p];
      if (Array.isArray(nx)) { if (!arrayTables.has(nx)) fail('cannot extend a static array'); nx = nx[nx.length - 1]; }
      if (!isTable(nx) || inline.has(nx)) fail(`table ${parts.join('.')} conflicts with a value`);
      t = nx;
    }
    const last = parts[parts.length - 1];
    if (isArray) {
      if (!own(t, last)) { t[last] = []; arrayTables.add(t[last]); }
      if (!Array.isArray(t[last]) || !arrayTables.has(t[last])) fail(`array table ${parts.join('.')} conflicts with a value`);
      const nt = {};
      t[last].push(nt);
      cur = nt;
    } else {
      if (own(t, last)) {
        const ex = t[last];
        if (!isTable(ex) || explicit.has(ex) || inline.has(ex)) fail(`table ${parts.join('.')} defined twice`);
        // an implicitly created table may be defined once, unless dotted keys made it
        cur = ex;
      } else { t[last] = {}; cur = t[last]; }
      explicit.add(cur);
    }
  }

  for (;;) {
    wsAll();
    if (i >= s.length) break;
    if (s[i] === '[') { header(s[i + 1] === '['); eol(); continue; }
    const k = key();
    if (s[i] !== '=') fail('expected =');
    i++; wsInline();
    assign(cur, k, val(0), false);
    eol();
  }
  return root;
}

module.exports = { parseToml };
