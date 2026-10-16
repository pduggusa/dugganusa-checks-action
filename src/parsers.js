'use strict';
// Manifest and MCP-config parsers. Zero dependencies on purpose: this code guards installs,
// so it must not need one.
//
// INVARIANT (not enumeration): every entry the installer would act on is classified as exactly
// one of
//   { kind: 'package', ecosystem: 'npm'|'pypi'|'rubygems', name, version|null, spec, note? }
//       a registry package whose identity is exactly what the installer fetches;
//   { kind: 'mcp', key, where, server, version|null, via }
//       an MCP server whose identity came from the package it launches (never from its key);
//   { kind: 'skip', spec, reason, unverifiable }
//       unverifiable=true  -> reported as UNKNOWN (git/URL/archive/private index/unparsed);
//       unverifiable=false -> an in-repository local path, reported as a notice.
// Anything a parser cannot classify becomes an UNKNOWN skip. Nothing is dropped silently and
// nothing unresolved is ever judged by a name the installer would not use.

const path = require('path');
const { parseJson } = require('./jsonsafe');
const { parseToml } = require('./toml');

const EXACT_SEMVER = /^v?=?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const MAX_LINE = 65536;   // longer requirement lines are refused (UNKNOWN)
const MAX_RUBY_LINE = 4096; // Gemfile lines: bounds regex backtracking
const MAX_INCLUDE_DEPTH = 10;

function pep503(name) { return String(name).toLowerCase().replace(/[-_.]+/g, '-'); }

function pkgKey(ecosystem, name, version) {
  const n = ecosystem === 'pypi' ? pep503(name) : String(name).toLowerCase();
  return `${ecosystem}:${n}@${version || ''}`;
}

function base(file) { return path.posix.basename(String(file).replace(/\\/g, '/')); }

const UNSUPPORTED = new Set(['yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb', '.pnpmfile.cjs', '.pnpmfile.mjs', 'uv.lock', 'pdm.lock', 'pylock.toml', 'Pipfile', 'Pipfile.lock', 'setup.py', 'setup.cfg']);
const INSTALL_CONFIG = new Set(['.npmrc', '.yarnrc', '.yarnrc.yml', 'pip.conf', 'pip.ini', 'uv.toml', 'poetry.toml', 'bunfig.toml']);

// Which parser applies to a repository path, or null.
function manifestKind(file) {
  const f = String(file).replace(/\\/g, '/');
  if (/(^|\/)(node_modules|vendor\/bundle|\.venv|venv)\//.test(f)) return null;
  const b = base(f);
  if (b === 'package.json') return 'package.json';
  if (b === 'package-lock.json' || b === 'npm-shrinkwrap.json') return 'package-lock';
  if (/^requirements.*\.txt$/i.test(b) || /\.requirements\.txt$/i.test(b)) return 'requirements';
  if (b === 'pyproject.toml') return 'pyproject';
  if (b === 'poetry.lock') return 'poetry.lock';
  if (b === 'Gemfile' || b === 'gems.rb') return 'gemfile';
  if (b === 'Gemfile.lock' || b === 'gems.locked') return 'gemfile.lock';
  if (b === '.mcp.json' || b === 'claude_desktop_config.json' || (b === 'mcp.json' && /(^|\/)\.(cursor|vscode)\/mcp\.json$/.test(f))) return 'mcp';
  if (/(^|\/)\.claude\/settings(\.local)?\.json$/.test(f)) return 'mcp';
  // Files that change WHAT an installer fetches but that we do not resolve: reported, never ignored.
  if (UNSUPPORTED.has(b)) return 'unsupported';
  if (INSTALL_CONFIG.has(b) || /(^|\/)\.bundle\/config$/.test(f)) return 'install-config';
  return null;
}

const unknown = (spec, reason) => ({ kind: 'skip', unverifiable: true, spec: String(spec), reason });
const local = (spec, reason) => ({ kind: 'skip', unverifiable: false, spec: String(spec), reason });

// ---------------------------------------------------------------------------
// Decoding: read bytes the way the installer does
// ---------------------------------------------------------------------------

function decode(kind, buf) {
  if (typeof buf === 'string') return buf;
  const b = Buffer.from(buf);
  if (kind === 'requirements') {
    // pip auto_decode: BOMs, then a PEP 263 coding line, then UTF-8 (strict)
    if (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(3));
    if ((b[0] === 0xff && b[1] === 0xfe && b[2] === 0 && b[3] === 0) || (b[0] === 0 && b[1] === 0 && b[2] === 0xfe && b[3] === 0xff)) throw new Error('UTF-32 requirements file is not supported');
    if (b[0] === 0xff && b[1] === 0xfe) return new TextDecoder('utf-16le', { fatal: true }).decode(b.subarray(2));
    if (b[0] === 0xfe && b[1] === 0xff) return new TextDecoder('utf-16be', { fatal: true }).decode(b.subarray(2));
    const head = b.subarray(0, 400).toString('latin1').split(/\r\n|\r|\n/).slice(0, 2).join('\n');
    const m = /^#.*coding[:=]\s*([-\w.]+)/m.exec(head);
    if (m) {
      const enc = m[1].toLowerCase().replace(/_/g, '-');
      if (['latin-1', 'latin1', 'iso-8859-1', 'iso8859-1', 'l1'].includes(enc)) return b.toString('latin1');
      if (!['utf-8', 'utf8'].includes(enc)) throw new Error(`requirements file declares encoding "${m[1].slice(0, 20)}", which this check does not decode`);
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(b);
  }
  if (kind === 'pyproject' || kind === 'poetry.lock') return new TextDecoder('utf-8', { fatal: true }).decode(b);
  return b.toString('utf8'); // npm, bundler and MCP clients read UTF-8 leniently
}

// ---------------------------------------------------------------------------
// npm specs (mirrors npm-package-arg: anything that is not a registry range is not a name)
// ---------------------------------------------------------------------------

const NPM_NAME = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const NPM_RANGE_CHARS = /^[A-Za-z0-9.\-+*^~<>=|\s_]*$/;

// depName: the name the dependency is installed under; raw: the spec string.
function npmFromRange(depName, raw, depth = 0) {
  const name = String(depName);
  const r = String(raw).trim();
  if (r.startsWith('npm:')) {
    if (depth > 0) return unknown(`${name}: ${r}`, 'nested npm: alias');
    const m = /^((?:@[^/@\s]+\/)?[^/@\s]+)(?:@(.*))?$/.exec(r.slice(4));
    if (!m) return unknown(`${name}: ${r}`, 'npm: alias that does not name a registry package');
    const p = npmFromRange(m[1], m[2] || '', depth + 1);
    if (p.kind === 'package') p.spec = `${name}: ${r}`;
    return p;
  }
  if (/\.(tgz|tar\.gz|tar)$/i.test(r)) return unknown(`${name}: ${r}`, 'tarball: its contents are not a registry package and were not checked');
  if (/^(file:|link:|workspace:|portal:)/i.test(r) || /^(\.{1,2}(\/|\\|$)|~[/\\]|\/)/.test(r)) {
    if (!/^workspace:/i.test(r) && /^(\/|~|[A-Za-z]:)/.test(r.replace(/^(file|link|portal):/i, ''))) return unknown(`${name}: ${r}`, 'absolute or home-relative path outside the repository');
    return local(`${name}: ${r}`, 'local path or workspace package');
  }
  if (r.includes(':')) return unknown(`${name}: ${r}`, 'git/URL/protocol source: not checkable against a registry deny-list');
  if (r.includes('/') || r.includes('\\')) return unknown(`${name}: ${r}`, 'GitHub shorthand or path: not checkable against a registry deny-list');
  if (!NPM_RANGE_CHARS.test(r)) return unknown(`${name}: ${r}`, 'not a registry version range or tag');
  if (!NPM_NAME.test(name) || name.length > 214) return unknown(name, 'not a valid npm package name');
  const out = { kind: 'package', ecosystem: 'npm', name, version: null, spec: r ? `${name}@${r}` : name };
  if (EXACT_SEMVER.test(r)) out.version = r.replace(/^v?=?/, '');
  else if (r && r !== 'latest' && r !== '*') out.note = `range "${r}": no exact version, so the known-vulnerability check cannot run`;
  return out;
}

// A command-line package argument (npx foo@1, npx @s/x, npx github:a/b).
function parseNpmSpec(spec) {
  const s = String(spec).trim();
  if (!s) return unknown(s, 'empty package argument');
  const m = /^((?:@[^/@\s:]+\/)?[^/@\s:\\]+)(?:@(.*))?$/.exec(s);
  if (!m) return unknown(s, 'not a registry package (git, URL, path or shorthand)');
  return npmFromRange(m[1], m[2] || '');
}

// ---------------------------------------------------------------------------
// pip (mirrors pip's req_file.py: splitlines, join_lines, comments, options, then PEP 508)
// ---------------------------------------------------------------------------

// Python str.splitlines() boundaries, which is what pip uses (not just \n).
function pySplitLines(text) { return String(text).split(/\r\n|[\n\r\u000b\u000c\u001c\u001d\u001e\u0085\u2028\u2029]/); }

const isWs = (c) => c === ' ' || c === '\t' || c === '\f' || c === '\v' || c === '\r' || c === '\n' || /\s/.test(c);
// Linear equivalent of re.sub(r'(^|\s+)#.*$', '', line): the first '#' at the start or after whitespace.
function commentStart(line) {
  for (let k = 0; k < line.length; k++) {
    if (line[k] === '#' && (k === 0 || isWs(line[k - 1]))) { let p = k; while (p > 0 && isWs(line[p - 1])) p--; return p; }
  }
  return -1;
}

function pipLogicalLines(text) {
  const out = [];
  let acc = null, accLine = 0;
  pySplitLines(text).forEach((line, idx) => {
    const n = idx + 1;
    const isComment = commentStart(line) >= 0;
    if (!line.endsWith('\\') || isComment) {
      if (isComment) line = ' ' + line;
      if (acc) { acc.push(line); out.push({ n: accLine, text: acc.join('') }); acc = null; }
      else out.push({ n, text: line });
    } else {
      if (!acc) { acc = []; accLine = n; }
      acc.push(line.replace(/^\\+|\\+$/g, ''));
    }
  });
  if (acc) out.push({ n: accLine, text: acc.join('') });
  return out.map(({ n, text: t }) => { const c = commentStart(t); return { n, text: (c >= 0 ? t.slice(0, c) : t).trim() }; }).filter(x => x.text);
}

function shlexSplit(s) {
  const out = []; let cur = null; let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (/\s/.test(c)) { if (cur !== null) { out.push(cur); cur = null; } i++; continue; }
    cur = cur || '';
    if (c === "'") { const e = s.indexOf("'", i + 1); if (e < 0) throw new Error('unbalanced quote'); cur += s.slice(i + 1, e); i = e + 1; continue; }
    if (c === '"') { let j = i + 1; while (j < s.length && s[j] !== '"') { if (s[j] === '\\' && j + 1 < s.length) j++; cur += s[j]; j++; } if (j >= s.length) throw new Error('unbalanced quote'); i = j + 1; continue; }
    if (c === '\\' && i + 1 < s.length) { cur += s[i + 1]; i += 2; continue; }
    cur += c; i++;
  }
  if (cur !== null) out.push(cur);
  return out;
}

// pip's line options. type: 'include' | 'editable' | 'index' (replaces PyPI) | 'extra' (adds a source) | 'flag' | 'value'
const PIP_LINE_OPTS = {
  '-r': 'include', '--requirement': 'include', '-c': 'include', '--constraint': 'include',
  '-e': 'editable', '--editable': 'editable',
  '-i': 'index', '--index-url': 'index', '--no-index': 'noindex',
  '--extra-index-url': 'extra', '-f': 'extra', '--find-links': 'extra', '--trusted-host': 'extra',
  '--no-binary': 'value', '--only-binary': 'value', '--use-feature': 'value',
  '--prefer-binary': 'flag', '--require-hashes': 'flag', '--pre': 'flag',
};
const PIP_REQ_OPTS = { '--hash': 'value', '--global-option': 'value', '--config-settings': 'value', '-C': 'value' };

// optparse semantics: exact long option, else a unique prefix; short options may glue their value.
function matchOpt(tok, table) {
  if (tok.startsWith('--')) {
    const [nm, ...rest] = tok.split('=');
    const v = rest.length ? rest.join('=') : undefined;
    if (table[nm]) return { name: nm, value: v };
    const c = Object.keys(table).filter(k => k.startsWith('--') && k.startsWith(nm));
    return c.length === 1 ? { name: c[0], value: v } : null;
  }
  const short = tok.slice(0, 2);
  if (table[short]) return { name: short, value: tok.length > 2 ? tok.slice(2) : undefined };
  return null;
}

const PEP508_NAME = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)/;
const PIP_ARCHIVE = /\.(whl|tar\.gz|tgz|tar\.bz2|tbz|tar\.xz|txz|tar|zip)$/i;
const VERSION_CLAUSE = /^\s*(~=|===|==|!=|<=|>=|<|>)\s*([A-Za-z0-9.*+!_-]+)\s*$/;

// One PEP 508 requirement (no pip options). Used for requirements lines and pyproject strings.
function parsePipSpec(spec) {
  let s = String(spec).trim();
  if (!s) return null;
  if (/\$\{[A-Za-z0-9_]+\}/.test(s)) return unknown(s, 'environment-variable expansion: the value is only known at install time');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || /^(git|hg|svn|bzr)\+/i.test(s)) return unknown(s, 'VCS/URL source: not checkable against a registry deny-list');
  if (s.startsWith('.') || s.startsWith('/') || s.startsWith('~') || /^[A-Za-z]:[\\/]/.test(s) || /^[^@;]*[/\\]/.test(s.split(';')[0]) || (PIP_ARCHIVE.test(s.split(';')[0].trim()) && !s.includes('@'))) {
    const p = s.split(';')[0].trim();
    if (PIP_ARCHIVE.test(p)) return unknown(s, 'archive file: its contents are not a registry package and were not checked');
    if (/^(\/|~|[A-Za-z]:)/.test(p) || /(^|[/\\])\.\.([/\\]|$)/.test(p)) return unknown(s, 'path outside the repository');
    return local(s, 'local path');
  }
  const nm = PEP508_NAME.exec(s);
  if (!nm) return unknown(s, 'not a parseable requirement');
  let rest = s.slice(nm[0].length).trimStart();
  if (rest.startsWith('[')) { const e = rest.indexOf(']'); if (e < 0 || !/^\[[\sA-Za-z0-9._,-]*\]$/.test(rest.slice(0, e + 1))) return unknown(s, 'malformed extras'); rest = rest.slice(e + 1).trimStart(); }
  if (rest.startsWith('@')) return unknown(s, 'direct reference (name @ URL): not checkable against a registry deny-list');
  const semi = rest.indexOf(';');
  let constraint = (semi >= 0 ? rest.slice(0, semi) : rest).trim();
  if (constraint.startsWith('(') && constraint.endsWith(')')) constraint = constraint.slice(1, -1).trim();
  const out = { kind: 'package', ecosystem: 'pypi', name: nm[1], version: null, spec: s };
  if (constraint) {
    const clauses = constraint.split(',').map(x => x.trim());
    if (clauses.some(c => !VERSION_CLAUSE.test(c))) return unknown(s, `version specifier "${constraint.slice(0, 60)}" is not parseable`);
    const ex = clauses.length === 1 ? /^\s*(===|==)\s*([0-9][0-9A-Za-z.+!_-]*)\s*$/.exec(clauses[0]) : null;
    if (ex && !ex[2].includes('*')) out.version = ex[2];
    else out.note = `constraint "${constraint}": no exact pin, so the known-vulnerability check cannot run`;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Manifest parsers
// ---------------------------------------------------------------------------

function itemKey(item) {
  if (item.kind === 'package') return pkgKey(item.ecosystem, item.name, item.version);
  if (item.kind === 'mcp') return `mcp:${item.where}`;
  return `skip:${item.spec}`;
}
function put(m, item) { if (item) m.set(itemKey(item), item); }

function duplicatesAsUnknown(m, dups, file) {
  for (const d of dups.slice(0, 20)) put(m, unknown(`duplicate key ${d}`, `${file} defines "${d}" twice; tools that keep the first value and tools that keep the last would install different things`));
}

function npmOverrides(m, obj, label, keyToName) {
  const walk = (o, depth) => {
    if (!o || typeof o !== 'object' || depth > 32) return;
    for (const [k, v] of Object.entries(o)) {
      if (k === '.') { continue; }
      const nm = keyToName(k);
      if (typeof v === 'string') {
        if (v.startsWith('$') || v === '-') continue; // reference to a direct dependency's own spec / pnpm removal
        if (!nm) { put(m, unknown(`${label} ${k}`, 'override key does not name a package')); continue; }
        const p = npmFromRange(nm, v);
        if (p.kind === 'skip') p.spec = `${label} ${k}: ${v}`;
        else p.note = `${label}${p.note ? '; ' + p.note : ''}`;
        put(m, p);
      } else if (v && typeof v === 'object') {
        if (typeof v['.'] === 'string' && nm && !v['.'].startsWith('$')) { const p = npmFromRange(nm, v['.']); if (p.kind === 'skip') p.spec = `${label} ${k}: ${v['.']}`; put(m, p); }
        walk(v, depth + 1);
      } else put(m, unknown(`${label} ${k}`, 'override value is not a string'));
    }
  };
  walk(obj, 0);
}

function fromPackageJson(text) {
  const { value: j, duplicates } = parseJson(text);
  const m = new Map();
  duplicatesAsUnknown(m, duplicates, 'package.json');
  if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('package.json is not an object');
  for (const sec of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const deps = j[sec];
    if (deps == null) continue;
    if (typeof deps !== 'object' || Array.isArray(deps)) { put(m, unknown(sec, `"${sec}" is not an object`)); continue; }
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec !== 'string') { put(m, unknown(`${name}`, `${sec} value is not a string`)); continue; }
      const p = npmFromRange(name, spec);
      if (p.kind === 'skip' && !p.spec.startsWith(`${name}:`) && p.spec !== name) p.spec = `${name}: ${p.spec}`;
      put(m, p);
    }
  }
  // overrides / resolutions rewrite the tree: an override to git or a different package is installed.
  if (j.overrides) npmOverrides(m, j.overrides, 'overrides', (k) => { const x = /^((?:@[^/@]+\/)?[^/@]+)(?:@.*)?$/.exec(k); return x ? x[1] : null; });
  if (j.resolutions) npmOverrides(m, j.resolutions, 'resolutions', (k) => { const parts = k.replace(/@npm:.*$/, '').split('/').filter(x => x && x !== '**'); if (!parts.length) return null; const last = parts[parts.length - 1]; const prev = parts[parts.length - 2]; const nm = prev && prev.startsWith('@') ? `${prev}/${last}` : last; return nm.replace(/(.)@.*$/, '$1'); });
  if (j.pnpm && j.pnpm.overrides) npmOverrides(m, j.pnpm.overrides, 'pnpm.overrides', (k) => { const last = k.split('>').pop(); const x = /^((?:@[^/@]+\/)?[^/@]+)(?:@.*)?$/.exec(last); return x ? x[1] : null; });
  return m;
}

// Identity npm will actually fetch for a resolved URL on the public registry, or null.
function npmRegistryIdentity(resolved) {
  let u;
  try { u = new URL(resolved); } catch { return null; }
  if (u.protocol !== 'https:' || !['registry.npmjs.org', 'registry.yarnpkg.com'].includes(u.hostname) || u.port || u.username || u.password || u.search || u.hash) return null;
  let p;
  try { p = decodeURIComponent(u.pathname); } catch { return null; }
  const x = /^\/((?:@[^/]+\/)?[^/]+)\/-\/([^/]+)\.tgz$/.exec(p);
  if (!x) return null;
  const name = x[1];
  const unscoped = name.includes('/') ? name.split('/')[1] : name;
  if (!x[2].startsWith(unscoped + '-')) return null;
  const version = x[2].slice(unscoped.length + 1);
  if (!NPM_NAME.test(name) || !EXACT_SEMVER.test(version)) return null;
  return { name, version };
}

function lockEntry(m, { name, version, resolved, transitive, where }) {
  if (!name || !NPM_NAME.test(name)) { put(m, unknown(`${where}`, 'lockfile entry does not name a valid package')); return; }
  if (typeof version !== 'string' || !version) { put(m, unknown(`${name} (${where})`, 'lockfile entry has no version: what npm installs here was not determined')); return; }
  let vname = name, ver = version;
  if (version.startsWith('npm:')) { const a = /^npm:((?:@[^/@]+\/)?[^/@]+)@(.+)$/.exec(version); if (!a) { put(m, unknown(`${name}@${version}`, 'unparseable alias')); return; } vname = a[1]; ver = a[2]; }
  if (resolved != null && resolved !== '') {
    if (typeof resolved !== 'string') { put(m, unknown(`${name}@${version}`, 'resolved is not a string')); return; }
    if (/^file:/i.test(resolved) || !/^[a-z][a-z0-9+.-]*:/i.test(resolved)) {
      if (/\.(tgz|tar\.gz|tar)$/i.test(resolved)) { put(m, unknown(`${name}@${version}`, `tarball ${resolved.slice(0, 80)}: contents were not checked`)); return; }
      put(m, local(`${name}@${version}`, 'local path in the lockfile'));
      return;
    }
    const id = npmRegistryIdentity(resolved);
    if (!id) { put(m, unknown(`${name}@${version}`, `resolved from a non-default registry or source (${resolved.slice(0, 80)}): the name was not checked`)); return; }
    if (id.name.toLowerCase() !== vname.toLowerCase() || id.version !== ver) {
      put(m, unknown(`${name}@${version}`, `lockfile says ${vname}@${ver} but its resolved URL fetches ${id.name}@${id.version}; the fetched package is checked separately`));
    }
    put(m, { kind: 'package', ecosystem: 'npm', name: id.name, version: id.version, spec: `${id.name}@${id.version}`, transitive });
    return;
  }
  if (!EXACT_SEMVER.test(ver)) {
    if (/^file:/i.test(ver)) { put(m, /\.(tgz|tar\.gz|tar)$/i.test(ver) ? unknown(`${name}@${version}`, 'tarball: contents were not checked') : local(`${name}@${version}`, 'local path in the lockfile')); return; }
    put(m, unknown(`${name}@${version}`, 'lockfile version is not a registry version (git, URL or tag): not checkable'));
    return;
  }
  put(m, { kind: 'package', ecosystem: 'npm', name: vname, version: ver.replace(/^v?=?/, ''), spec: `${vname}@${ver}`, transitive });
}

function fromPackageLock(text, { transitive = true } = {}) {
  const { value: j, duplicates } = parseJson(text);
  const m = new Map();
  duplicatesAsUnknown(m, duplicates, 'the lockfile');
  if (!j || typeof j !== 'object') throw new Error('lockfile is not an object');
  // v2/v3 "packages" and v1/v2 "dependencies" are BOTH read: different npm majors read different
  // halves, so a lockfile whose halves disagree must not be judged by the benign half only.
  const pk = j.packages && typeof j.packages === 'object' ? j.packages : {};
  for (const [p, info] of Object.entries(pk)) {
    if (!p || !p.includes('node_modules/')) continue;
    if (!info || typeof info !== 'object') { put(m, unknown(p, 'lockfile entry is not an object')); continue; }
    const isDirect = /^node_modules\/(@[^/]+\/)?[^/]+$/.test(p);
    if (!transitive && !isDirect) continue;
    const pathName = p.slice(p.lastIndexOf('node_modules/') + 13);
    if (info.link) {
      if (typeof info.resolved === 'string' && (/^[a-z][a-z0-9+.-]*:/i.test(info.resolved) || info.resolved.startsWith('/') || /(^|\/)\.\.(\/|$)/.test(path.posix.normalize(info.resolved)))) put(m, unknown(pathName, `link to ${String(info.resolved).slice(0, 80)} outside the repository`));
      continue; // workspace link: the target folder is in this repository
    }
    lockEntry(m, { name: typeof info.name === 'string' ? info.name : pathName, version: info.version, resolved: info.resolved, transitive: !isDirect, where: p });
  }
  if (j.dependencies && typeof j.dependencies === 'object') {
    const walk = (deps, depth) => {
      if (depth > 64) return;
      for (const [name, info] of Object.entries(deps || {})) {
        if (!info || typeof info !== 'object') { put(m, unknown(name, 'lockfile entry is not an object')); continue; }
        if (transitive || depth === 0) lockEntry(m, { name, version: info.version, resolved: info.resolved, transitive: depth > 0, where: `dependencies.${name}` });
        if (info.dependencies) walk(info.dependencies, depth + 1);
      }
    };
    walk(j.dependencies, 0);
  }
  return m;
}

// requirements.txt. opts.readInclude(repoRelativePath) -> text|null follows -r/-c inside the repo.
function fromRequirements(text, opts = {}, state = { depth: 0, seen: new Set(), ctx: null }) {
  const m = new Map();
  const ctx = state.ctx || { indexReplaced: null };
  const file = opts.file || 'requirements.txt';
  for (const { n, text: line } of pipLogicalLines(text)) {
    const where = `${file}:${n}`;
    if (line.length > MAX_LINE) { put(m, unknown(where, `line longer than ${MAX_LINE} characters was not parsed`)); continue; }
    if (/\$\{[A-Z0-9_]+\}/.test(line)) { put(m, unknown(`${where}`, 'environment-variable expansion: the value is only known at install time')); continue; }
    // pip's break_args_options: tokens split on single spaces; the first "-" token starts options
    const tokens = line.split(' ');
    let k = 0; const args = [];
    while (k < tokens.length && !tokens[k].startsWith('-')) args.push(tokens[k++]);
    const reqStr = args.join(' ').trim();
    let opt;
    try { opt = shlexSplit(tokens.slice(k).join(' ')); } catch { put(m, unknown(where, 'unparseable options')); continue; }
    if (reqStr) {
      for (let t = 0; t < opt.length; t++) {
        const o = matchOpt(opt[t], PIP_REQ_OPTS);
        if (!o) { put(m, unknown(where, `unrecognized per-requirement option ${opt[t].slice(0, 40)}`)); break; }
        if (o.value === undefined) t++;
      }
      put(m, parsePipSpec(reqStr));
      continue;
    }
    for (let t = 0; t < opt.length; t++) {
      const o = matchOpt(opt[t], PIP_LINE_OPTS);
      if (!o) { put(m, unknown(where, `unrecognized pip option ${opt[t].slice(0, 40)}`)); break; }
      const type = PIP_LINE_OPTS[o.name];
      if (type === 'flag' || type === 'noindex') {
        if (type === 'noindex') { ctx.indexReplaced = ctx.indexReplaced || '--no-index'; put(m, unknown(`${where} --no-index`, 'PyPI disabled: packages come from local links only')); }
        continue;
      }
      let v = o.value;
      if (v === undefined) { v = opt[++t]; if (v === undefined) { put(m, unknown(where, `option ${o.name} without a value`)); break; } }
      if (type === 'value') continue;
      if (type === 'index') { ctx.indexReplaced = ctx.indexReplaced || v; put(m, unknown(`${where} ${o.name}`, `index replaced (${v.slice(0, 80)}): every package in this file is fetched from it, not from PyPI`)); continue; }
      if (type === 'extra') { put(m, unknown(`${where} ${o.name}`, `additional package source (${v.slice(0, 80)}): dependency-confusion surface; same-named packages may come from it`)); continue; }
      if (type === 'editable') {
        const p = parsePipSpec(v);
        if (p && p.kind === 'package') put(m, unknown(`${where} -e ${v}`, 'editable install of a non-path requirement'));
        else if (p) { p.spec = `-e ${p.spec}`; put(m, p); }
        continue;
      }
      if (type === 'include') {
        if (/^[a-z][a-z0-9+.-]*:/i.test(v)) { put(m, unknown(`${where} ${o.name} ${v}`, 'requirements included from a URL were not checked')); continue; }
        const target = path.posix.normalize(path.posix.join(path.posix.dirname(file.replace(/\\/g, '/')), v.replace(/\\/g, '/')));
        if (path.posix.isAbsolute(v) || target.startsWith('../') || target === '..') { put(m, unknown(`${where} ${o.name} ${v}`, 'included file is outside the repository')); continue; }
        if (state.seen.has(target)) continue;
        if (state.depth >= MAX_INCLUDE_DEPTH) { put(m, unknown(`${where} ${o.name} ${v}`, 'include nesting too deep')); continue; }
        const inc = opts.readInclude ? opts.readInclude(target) : null;
        if (inc == null) { put(m, unknown(`${where} ${o.name} ${v}`, 'included file could not be read inside the repository; its requirements were not checked')); continue; }
        state.seen.add(target);
        const sub = fromRequirements(inc, { ...opts, file: target }, { depth: state.depth + 1, seen: state.seen, ctx });
        for (const [kk, vv] of sub) m.set(kk, vv);
      }
    }
  }
  if (state.depth === 0 && ctx.indexReplaced) replacePackages(m, `fetched from ${String(ctx.indexReplaced).slice(0, 80)} instead of PyPI, so the PyPI name was not what gets installed`);
  return m;
}

// Every registry package in m becomes UNKNOWN (its source is not the registry we judge).
function replacePackages(m, why, filter = () => true) {
  for (const [k, v] of [...m]) {
    if (v.kind !== 'package' || !filter(v)) continue;
    m.delete(k);
    put(m, unknown(v.spec, why));
  }
}

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);

function pep508List(m, arr, where) {
  if (arr == null) return;
  if (!Array.isArray(arr)) { put(m, unknown(where, 'expected an array of requirements')); return; }
  for (const x of arr) {
    if (typeof x === 'string') put(m, parsePipSpec(x));
    else if (isObj(x) && typeof x['include-group'] === 'string') continue; // PEP 735 reference to another group
    else put(m, unknown(where, 'non-string requirement'));
  }
}

function poetryDep(m, name, v, where) {
  if (String(name).toLowerCase() === 'python') return;
  if (typeof v === 'string') {
    const ver = v.trim();
    const spec = /^=?=?\s*\d[\w.!+-]*$/.test(ver) ? `${name}==${ver.replace(/^=+\s*/, '')}` : ver === '*' || ver === '' ? name : null;
    if (spec) { put(m, parsePipSpec(spec)); return; }
    if (!/^[\s\d.*^~<>=!,|a-zA-Z+-]+$/.test(ver)) { put(m, unknown(`${name} ${ver}`, `${where}: unparseable Poetry constraint`)); return; }
    const p = { kind: 'package', ecosystem: 'pypi', name, version: null, spec: `${name} ${ver}`, note: `constraint "${ver}": no exact pin, so the known-vulnerability check cannot run` };
    if (!PEP508_NAME.test(name) || PEP508_NAME.exec(name)[0] !== name) { put(m, unknown(name, 'not a valid package name')); return; }
    put(m, p);
    return;
  }
  if (Array.isArray(v)) { for (const x of v) poetryDep(m, name, x, where); return; }
  if (isObj(v)) {
    if (v.git || v.url) { put(m, unknown(name, `${where}: Poetry ${v.git ? 'git' : 'url'} source: not checkable against a registry deny-list`)); return; }
    if (v.path || v.file) { put(m, local(name, `${where}: Poetry path dependency`)); return; }
    if (v.source) { put(m, unknown(name, `${where}: Poetry source "${String(v.source).slice(0, 40)}" (not PyPI): the name was not checked`)); return; }
    poetryDep(m, name, typeof v.version === 'string' ? v.version : '*', where);
    return;
  }
  put(m, unknown(name, `${where}: unrecognized dependency value`));
}

function fromPyproject(text) {
  const t = parseToml(text);
  const m = new Map();
  const project = isObj(t.project) ? t.project : {};
  pep508List(m, isObj(t['build-system']) ? t['build-system'].requires : null, 'build-system.requires');
  pep508List(m, project.dependencies, 'project.dependencies');
  if (isObj(project['optional-dependencies'])) for (const [g, arr] of Object.entries(project['optional-dependencies'])) pep508List(m, arr, `project.optional-dependencies.${g}`);
  if (isObj(t['dependency-groups'])) for (const [g, arr] of Object.entries(t['dependency-groups'])) pep508List(m, arr, `dependency-groups.${g}`);
  const tool = isObj(t.tool) ? t.tool : {};
  const uv = isObj(tool.uv) ? tool.uv : {};
  for (const k of ['dev-dependencies', 'constraint-dependencies', 'override-dependencies']) pep508List(m, uv[k], `tool.uv.${k}`);
  if (isObj(tool.pdm) && isObj(tool.pdm['dev-dependencies'])) for (const [g, arr] of Object.entries(tool.pdm['dev-dependencies'])) pep508List(m, arr, `tool.pdm.dev-dependencies.${g}`);
  const poetry = isObj(tool.poetry) ? tool.poetry : {};
  for (const sec of ['dependencies', 'dev-dependencies']) if (isObj(poetry[sec])) for (const [n, v] of Object.entries(poetry[sec])) poetryDep(m, n, v, `tool.poetry.${sec}`);
  if (isObj(poetry.group)) for (const [g, grp] of Object.entries(poetry.group)) if (isObj(grp) && isObj(grp.dependencies)) for (const [n, v] of Object.entries(grp.dependencies)) poetryDep(m, n, v, `tool.poetry.group.${g}.dependencies`);

  // Sources that change where a NAME is fetched from.
  if (isObj(uv.sources)) {
    const redirected = new Set();
    for (const [n, src] of Object.entries(uv.sources)) {
      const list = Array.isArray(src) ? src : [src];
      for (const s of list) {
        if (!isObj(s)) { put(m, unknown(`tool.uv.sources.${n}`, 'unrecognized source')); redirected.add(pep503(n)); continue; }
        if (s.workspace === true) continue;
        if (s.path && !s.git && !s.url && !s.index) { put(m, local(`tool.uv.sources.${n}`, 'local path source')); redirected.add(pep503(n)); continue; }
        put(m, unknown(`tool.uv.sources.${n}`, `uv source (${s.git ? 'git' : s.url ? 'url' : s.index ? 'index ' + String(s.index).slice(0, 40) : 'unknown'}): not PyPI, so the name was not checked`));
        redirected.add(pep503(n));
      }
    }
    replacePackages(m, 'tool.uv.sources redirects this package away from PyPI', (v) => redirected.has(pep503(v.name)));
  }
  const uvIdx = Array.isArray(uv.index) ? uv.index : [];
  if (uvIdx.some(x => isObj(x) && x.default === true) || typeof uv['index-url'] === 'string' || uv['no-index'] === true) {
    put(m, unknown('tool.uv default index', 'the default index is replaced: packages are not fetched from PyPI'));
    replacePackages(m, 'tool.uv replaces PyPI as the default index');
  } else if (uvIdx.length || uv['extra-index-url'] || uv['find-links']) put(m, unknown('tool.uv extra index', 'additional package index (dependency-confusion surface)'));
  const psrc = Array.isArray(poetry.source) ? poetry.source : [];
  if (psrc.some(x => isObj(x) && (x.default === true || x.priority === undefined || x.priority === 'primary' || x.priority === 'default'))) {
    put(m, unknown('tool.poetry.source', 'a primary/default source replaces PyPI for Poetry dependencies'));
    replacePackages(m, 'a Poetry primary source replaces PyPI, so the PyPI name was not what gets installed');
  } else if (psrc.length) put(m, unknown('tool.poetry.source', 'additional package source (dependency-confusion surface)'));
  return m;
}

function fromPoetryLock(text) {
  const t = parseToml(text);
  const m = new Map();
  const pkgs = Array.isArray(t.package) ? t.package : [];
  for (const p of pkgs) {
    if (!isObj(p) || typeof p.name !== 'string' || typeof p.version !== 'string') { put(m, unknown(`poetry.lock package ${isObj(p) ? String(p.name || '?').slice(0, 60) : '?'}`, 'locked package without a name or version')); continue; }
    const spec = `${p.name}==${p.version}`;
    const src = isObj(p.source) ? p.source : null;
    if (src) {
      const type = String(src.type || '');
      const url = String(src.url || '');
      if (type === 'legacy' && /^https:\/\/pypi\.org\/simple\/?$/.test(url)) { /* explicit PyPI */ }
      else if (type === 'directory') { put(m, local(spec, 'Poetry directory source')); continue; }
      else if (type === 'legacy') { put(m, unknown(spec, `alternate package index ${url.slice(0, 80)} (dependency-confusion surface): the name was judged on public PyPI only, so it was not checked`)); continue; }
      else { put(m, unknown(spec, `Poetry source type "${type.slice(0, 20)}": not from PyPI, the name was not checked`)); continue; }
    }
    const pp = parsePipSpec(spec);
    put(m, pp && pp.kind === 'package' ? pp : unknown(spec, 'unparseable locked package'));
  }
  return m;
}

// ---- Gemfile: Ruby source. Only a small static subset is understood; every other line is
// code bundler would execute, so it is UNKNOWN rather than ignored.

function rubyArgs(s) {
  // -> array of { t: 'str'|'sym'|'kw'|'arr'|'lit', v } or null when not statically parseable
  const out = []; let i = 0;
  const ws = () => { while (s[i] === ' ' || s[i] === '\t') i++; };
  for (;;) {
    ws();
    if (i >= s.length) return out;
    let tok = null;
    const c = s[i];
    if (c === '"' || c === "'") {
      const e = s.indexOf(c, i + 1);
      if (e < 0) return null;
      const v = s.slice(i + 1, e);
      if (v.includes('\\') || (c === '"' && v.includes('#{'))) return null;
      tok = { t: 'str', v }; i = e + 1;
    } else if (c === ':' && /[A-Za-z_]/.test(s[i + 1] || '')) {
      const r = /:([A-Za-z_]\w*[?!]?)/y; r.lastIndex = i; const x = r.exec(s); tok = { t: 'sym', v: x[1] }; i += x[0].length;
      ws(); if (s.startsWith('=>', i)) { i += 2; tok = { t: 'kw', v: tok.v }; }
    } else if (c === '%' && /[iIwW]/.test(s[i + 1] || '') && '[({<'.includes(s[i + 2])) {
      const close = { '[': ']', '(': ')', '{': '}', '<': '>' }[s[i + 2]];
      const e = s.indexOf(close, i + 3); if (e < 0) return null;
      tok = { t: 'arr', v: s.slice(i + 3, e).trim().split(/\s+/).filter(Boolean) }; i = e + 1;
    } else if (c === '[') {
      const e = s.indexOf(']', i); if (e < 0) return null;
      const inner = rubyArgs(s.slice(i + 1, e)); if (!inner || inner.some(x => x.t !== 'sym' && x.t !== 'str')) return null;
      tok = { t: 'arr', v: inner.map(x => x.v) }; i = e + 1;
    } else {
      const r = /([A-Za-z_]\w*):(?!:)/y; r.lastIndex = i; const x = r.exec(s);
      if (x) { tok = { t: 'kw', v: x[1] }; i += x[0].length; }
      else { const l = /(true|false|nil)\b/y; l.lastIndex = i; const y = l.exec(s); if (!y) return null; tok = { t: 'lit', v: y[1] }; i += y[0].length; }
    }
    out.push(tok);
    ws();
    if (i >= s.length) return out;
    if (tok.t === 'kw') continue; // value follows
    if (s[i] === ',') { i++; continue; }
    return null;
  }
}

// Cut a Ruby comment: the first '#' outside a string literal (linear scan, no regex backtracking).
function rubyStripComment(line) {
  let q = null;
  for (let k = 0; k < line.length; k++) {
    const c = line[k];
    if (q) { if (c === '\\') k++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === '#') return line.slice(0, k);
  }
  return line;
}

const RUBYGEMS_SOURCE = /^https:\/\/(rubygems\.org|index\.rubygems\.org)\/?$/;
const GEM_OK_KW = new Set(['require', 'group', 'groups', 'platform', 'platforms', 'env', 'autorequire', 'force_ruby_platform']);
const GEM_SRC_KW = new Set(['git', 'github', 'gist', 'bitbucket', 'path', 'source', 'branch', 'ref', 'tag', 'submodules', 'glob']);

function fromGemfile(text) {
  const m = new Map();
  const raw = String(text).split(/\r?\n/);
  // join continuation lines (trailing comma or backslash)
  const lines = [];
  for (let k = 0; k < raw.length; k++) {
    if (raw[k].length > MAX_RUBY_LINE) { lines.push({ n: k + 1, l: null }); continue; }
    let l = rubyStripComment(raw[k]).trimEnd(); const n = k + 1;
    while ((l.endsWith(',') || l.endsWith('\\')) && k + 1 < raw.length && l.length < MAX_RUBY_LINE) l = l.replace(/\\$/, '') + ' ' + rubyStripComment(raw[++k]).trim();
    lines.push({ n, l });
  }
  const blocks = []; // stack of { kind: 'group'|'source'|'other', ok }
  let globalSource = null;
  const inForeign = () => blocks.some(b => b.kind === 'source' && !b.ok);
  for (const { n, l: rawLine } of lines) {
    if (rawLine == null || rawLine.length > MAX_RUBY_LINE) { put(m, unknown(`Gemfile:${n}`, 'line too long')); continue; }
    const line = rawLine.trim();
    if (!line) continue;
    const where = `Gemfile:${n}`;
    if (line === 'end') { blocks.pop(); continue; }
    let x;
    if ((x = /^source\s*\(?\s*(["'])([^"']+)\1\s*\)?\s*(do)?$/.exec(line))) {
      const ok = RUBYGEMS_SOURCE.test(x[2]);
      if (x[3]) blocks.push({ kind: 'source', ok });
      else { if (!ok) globalSource = x[2]; }
      if (!ok) put(m, unknown(`${where} source`, `gem source ${x[2].slice(0, 80)} is not RubyGems.org (dependency-confusion surface)`));
      continue;
    }
    if (/^(git|path|github|gist|bitbucket)\b.*\bdo(\s*\|[^|]*\|)?$/.test(line)) { blocks.push({ kind: 'source', ok: /^path\b/.test(line) }); if (!/^path\b/.test(line)) put(m, unknown(`${where}`, 'git source block: gems inside it are not from RubyGems.org')); continue; }
    if (/^(group|platforms?)\b[^{}]*\bdo$/.test(line)) { blocks.push({ kind: 'group' }); continue; }
    if (/^git_source\s*\(\s*:\w+\s*\)\s*\{\s*\|\s*\w+\s*\|\s*"[^"`]*"\s*\}$/.test(line)) continue; // URL template; gems using it carry an unknown keyword
    if (/^ruby\s*\(?\s*(["'][^"']*["']|file:\s*["'][^"']*["'])(\s*,.*)?\)?$/.test(line) && !/[`$]|system|exec|eval/.test(line)) continue;
    if (/^gemspec\b/.test(line) && !/[`$(]|system|exec|eval/.test(line)) { put(m, local(where, 'gemspec: its runtime dependencies are checked through Gemfile.lock')); continue; }
    if ((x = /^gem\s*(\(?)\s*(.*?)\s*(\)?)$/.exec(line)) && (x[1] === '(') === (x[3] === ')')) {
      const args = rubyArgs(x[2]);
      if (!args || !args.length || args[0].t !== 'str') { put(m, unknown(where, 'gem line is not a static name and options: bundler evaluates it as code')); continue; }
      const name = args[0].v;
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) { put(m, unknown(where, 'not a valid gem name')); continue; }
      const reqs = []; let bad = null; let srcKw = null;
      for (let a = 1; a < args.length; a++) {
        if (args[a].t === 'str' && !args.slice(1, a).some(z => z.t === 'kw')) reqs.push(args[a].v.trim());
        else if (args[a].t === 'kw') {
          const kw = args[a].v; const val = args[a + 1]; a++;
          if (GEM_SRC_KW.has(kw)) srcKw = srcKw || kw;
          else if (!GEM_OK_KW.has(kw)) bad = `unrecognized gem option ${kw}:`;
          if (!val) bad = 'option without a value';
        } else bad = 'unexpected argument';
      }
      if (bad) { put(m, unknown(`${where} ${name}`, `${bad}: not statically resolvable`)); continue; }
      if (srcKw) { put(m, srcKw === 'path' ? local(name, 'Gemfile path source') : unknown(name, `Gemfile ${srcKw}: source: not checkable against RubyGems.org`)); continue; }
      if (inForeign() || globalSource) { put(m, unknown(name, `fetched from ${globalSource ? globalSource.slice(0, 80) : 'a non-RubyGems source block'}, not RubyGems.org`)); continue; }
      if (reqs.some(r => !/^(=|!=|>=|<=|>|<|~>)?\s*\d[\w.]*$/.test(r))) { put(m, unknown(`${name} ${reqs.join(', ')}`, 'unparseable version requirement')); continue; }
      const exact = reqs.length === 1 ? /^=?\s*(\d[\w.]*)$/.exec(reqs[0]) : null;
      const item = { kind: 'package', ecosystem: 'rubygems', name, version: exact ? exact[1] : null, spec: reqs.length ? `${name} ${reqs.join(', ')}` : name };
      if (!exact && reqs.length) item.note = `requirement "${reqs.join(', ')}": no exact version, so the known-vulnerability check cannot run`;
      put(m, item);
      continue;
    }
    put(m, unknown(where, 'Gemfile line is Ruby code this check does not evaluate (bundler runs it at install time)'));
  }
  return m;
}

function fromGemfileLock(text) {
  const m = new Map();
  let block = '', inSpecs = false, remotes = [];
  for (const line of String(text).split(/\r?\n/)) {
    if (/^[A-Z]/.test(line)) { block = line.trim(); inSpecs = false; remotes = []; continue; }
    if (/^ {2}remote:/.test(line)) { remotes.push(line.split('remote:')[1].trim()); continue; }
    if (/^ {2}specs:/.test(line)) { inSpecs = true; continue; }
    if (!inSpecs || !/^ {4}(?! )/.test(line)) continue; // 6 spaces = requirements of a spec
    if (line.length > MAX_LINE) { put(m, unknown('Gemfile.lock line', 'line too long')); continue; }
    // bundler's NAME_VERSION: version is everything up to the first "-", the rest is the platform
    const s = /^ {4}(?! )(.*?)(?: \(([^-]*)(?:-(.*))?\))?(!)?$/.exec(line);
    const name = s && s[1], version = s && s[2];
    if (!name || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) || !version || !/^\d[\w.]*$/.test(version)) { put(m, unknown(line.trim().slice(0, 80), 'unparseable locked gem')); continue; }
    const spec = `${name} (${version})`;
    if (block === 'PATH') { put(m, local(spec, 'PATH gem from this repository')); continue; }
    if (block !== 'GEM' || !remotes.length || remotes.some(r => !RUBYGEMS_SOURCE.test(r))) {
      put(m, unknown(spec, `from ${block}${remotes.length ? ' ' + remotes.join(' ').slice(0, 80) : ''}: not RubyGems.org, the name was not checked`));
      continue;
    }
    put(m, { kind: 'package', ecosystem: 'rubygems', name, version, spec });
  }
  return m;
}

// ---- MCP configs (JSONC). An MCP server's identity is the package its launcher installs; a
// config KEY is attacker-chosen text and is never sent to Dredd as if it were the server.

function mcpEntries(j) {
  const out = [];
  const collect = (obj, where) => { if (isObj(obj)) for (const [k, v] of Object.entries(obj)) out.push([k, v, `${where}.${k}`]); };
  collect(j && j.mcpServers, 'mcpServers');
  collect(j && j.servers, 'servers');
  collect(j && j.mcp && j.mcp.servers, 'mcp.servers');
  if (j && isObj(j.projects)) for (const [pn, p] of Object.entries(j.projects)) collect(p && p.mcpServers, `projects.${pn}.mcpServers`);
  return out;
}

const NPX_BOOL = new Set(['-y', '--yes', '--no', '-q', '--quiet', '--no-install', '--ignore-existing', '-s', '--silent', '--prefer-offline', '--prefer-online', '--offline', '--bun', '--verbose']);
const NPX_PKG = new Set(['-p', '--package']);
const UVX_BOOL = new Set(['-q', '--quiet', '-v', '--verbose', '--offline', '--no-cache', '-n', '--isolated', '--refresh', '--no-progress', '--native-tls', '--prerelease=allow']);
const UVX_SKIPVAL = new Set(['--python', '-p', '--python-preference', '--color']);
const UVX_PKG = new Set(['--from', '--with', '-w']);
const ENV_REDIRECT = /(^|_)(REGISTRY|INDEX_URL|INDEX|EXTRA_INDEX_URL|FIND_LINKS|DEFAULT_INDEX|MIRROR|REPLACE_REGISTRY_HOST)$|^NODE_OPTIONS$|^NPM_CONFIG_|^PIP_|^UV_(INDEX|EXTRA|FIND|DEFAULT)|^PYTHONPATH$|^LD_PRELOAD$|^DYLD_/i;

// -> { packages: [item], problem: string|null }
function launcherPackages(cmd, args) {
  const res = { packages: [], problem: null };
  const fail = (p) => { res.problem = p; return res; };
  if (['npx', 'bunx'].includes(cmd) || (['pnpm', 'yarn'].includes(cmd) && args[0] === 'dlx') || (cmd === 'npm' && (args[0] === 'exec' || args[0] === 'x'))) {
    const rest = cmd === 'npx' || cmd === 'bunx' ? args : args.slice(1);
    const pk = []; let positional = null;
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === '--') { positional = rest[i + 1]; break; }
      if (NPX_PKG.has(a)) { if (rest[i + 1] === undefined) return fail(`${a} without a value`); pk.push(rest[++i]); continue; }
      if (a.startsWith('--package=')) { pk.push(a.slice(10)); continue; }
      if (a === '-c' || a === '--call' || a === '--shell-mode' || a.startsWith('--call=')) return fail(`${a} runs a shell command`);
      if (NPX_BOOL.has(a)) continue;
      if (a.startsWith('-')) return fail(`launcher option ${a.slice(0, 40)} is not understood (it may change the registry or what runs)`);
      positional = a; break;
    }
    if (!pk.length) { if (!positional) return fail('no package argument'); pk.push(positional); }
    for (const p of pk) res.packages.push(parseNpmSpec(p));
    return res;
  }
  if (cmd === 'uvx' || (cmd === 'uv' && args[0] === 'tool' && args[1] === 'run') || (cmd === 'pipx' && args[0] === 'run')) {
    const rest = cmd === 'uvx' ? args : args.slice(2);
    let from = null, positional = null; const extra = [];
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      const [flag, inl] = a.startsWith('--') && a.includes('=') ? [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)] : [a, undefined];
      const val = () => (inl !== undefined ? inl : rest[++i]);
      if (UVX_PKG.has(flag) || (cmd === 'pipx' && flag === '--spec')) { const v = val(); if (v === undefined) return fail(`${flag} without a value`); if (flag === '--from' || flag === '--spec') from = v; else extra.push(...v.split(',')); continue; }
      if (UVX_SKIPVAL.has(flag)) { if (val() === undefined) return fail(`${flag} without a value`); continue; }
      if (UVX_BOOL.has(a)) continue;
      if (a.startsWith('-')) return fail(`launcher option ${a.slice(0, 40)} is not understood (it may change the index or what runs)`);
      positional = a; break;
    }
    const main = from || positional;
    if (!main) return fail('no package argument');
    for (const p of [main, ...extra]) {
      const t = p.replace(/@latest$/, '').replace(/^([A-Za-z0-9._-]+(?:\[[^\]]*\])?)@(\d[\w.!+-]*)$/, '$1==$2');
      res.packages.push(parsePipSpec(t) || unknown(p, 'empty package argument'));
    }
    return res;
  }
  return fail(`command "${String(cmd).slice(0, 40)}" runs local or arbitrary code; no package identity to judge`);
}

const DOCKER_BOOL = new Set(['-i', '-t', '-it', '-ti', '--rm', '-d', '--detach', '--init', '--interactive', '--tty', '--read-only', '--privileged', '-P', '--publish-all', '--no-healthcheck', '-q', '--quiet']);
const DOCKER_VAL = new Set(['-e', '--env', '--env-file', '-v', '--volume', '--mount', '--name', '-p', '--publish', '--network', '--net', '-w', '--workdir', '-u', '--user', '--entrypoint', '--label', '-l', '--cap-add', '--cap-drop', '--memory', '-m', '--cpus', '--platform', '--pull', '--hostname', '-h', '--add-host', '--security-opt', '--tmpfs', '--ulimit', '--log-driver', '--log-opt', '--restart', '--shm-size', '--device', '--dns', '--ipc', '--pid', '--user-ns', '--userns', '--group-add', '--expose', '--stop-signal', '--health-cmd']);

function dockerImage(args) {
  if (args[0] !== 'run' && args[0] !== 'container') return { problem: `docker ${String(args[0] || '').slice(0, 20)}: not a docker run` };
  let i = args[0] === 'container' ? (args[1] === 'run' ? 2 : -1) : 1;
  if (i < 0) return { problem: 'not a docker run' };
  for (; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { i++; break; }
    if (!a.startsWith('-')) break;
    if (a.startsWith('--') && a.includes('=')) continue;
    if (DOCKER_BOOL.has(a)) continue;
    if (DOCKER_VAL.has(a)) { i++; continue; }
    if (/^-[eupvwlhm]./.test(a)) continue; // glued short option value, e.g. -eFOO=bar
    return { problem: `docker option ${a.slice(0, 40)} is not understood` };
  }
  const img = args[i];
  if (!img || !/^[a-z0-9][a-z0-9._/:@-]*$/i.test(img) || img.length > 255) return { problem: 'no image reference found' };
  const at = img.indexOf('@');
  const ref = at >= 0 ? img.slice(0, at) : img;
  const digest = at >= 0 ? img.slice(at + 1) : null;
  const tm = /^(.*?)(?::([\w][\w.-]{0,127}))?$/.exec(ref);
  let repo = tm[1]; const tag = tm[2] || null;
  repo = repo.replace(/^(docker\.io|index\.docker\.io|registry-1\.docker\.io)\//, '');
  // Docker's official MCP catalog namespace is mcp/<server>; anything else keeps its full path,
  // so "evil/github-mcp-server" is never judged as "github-mcp-server".
  const server = /^mcp\/[^/]+$/.test(repo) ? repo.slice(4) : repo;
  return { server, version: digest ? null : (tag && tag !== 'latest' ? tag : null) };
}

function fromMcpConfig(text) {
  const m = new Map();
  const { value: j, duplicates } = parseJson(text, { jsonc: true });
  duplicatesAsUnknown(m, duplicates, 'the MCP config');
  for (const [key, cfg, where] of mcpEntries(j)) {
    const say = (reason) => put(m, unknown(key, `MCP server "${key}": ${reason}`));
    if (!isObj(cfg)) { say('entry is not an object'); continue; }
    const remote = cfg.url || cfg.serverUrl || cfg.httpUrl;
    if (remote || ['sse', 'http', 'streamable-http'].includes(cfg.type)) {
      let host = '';
      try { host = new URL(String(remote)).host; } catch { host = String(remote || '').slice(0, 60); }
      say(`remote server at ${host || 'an unspecified URL'}: no package identity to judge, and its config key is not an identity`);
      continue;
    }
    if (typeof cfg.command !== 'string' || !cfg.command.trim()) { say('no command'); continue; }
    if (/\s/.test(cfg.command.trim())) { say('command contains spaces (shell-style command line): not statically resolvable'); continue; }
    if (cfg.args != null && !Array.isArray(cfg.args)) { say('args is not an array'); continue; }
    const args = (cfg.args || []).map(a => (typeof a === 'string' ? a : JSON.stringify(a)));
    const env = isObj(cfg.env) ? Object.keys(cfg.env) : [];
    const redirect = env.find(k => ENV_REDIRECT.test(k));
    if (redirect) { say(`env ${redirect} changes where packages are fetched from or what code loads`); continue; }
    const cmd = base(cfg.command).replace(/\.(cmd|exe|bat|ps1)$/i, '');
    if (cmd === 'docker' || cmd === 'podman') {
      const d = dockerImage(args);
      if (d.problem) { say(d.problem); continue; }
      put(m, { kind: 'mcp', key, where, server: d.server, version: d.version, via: cmd });
      continue;
    }
    const lp = launcherPackages(cmd, args);
    if (lp.problem) { say(lp.problem); continue; }
    let first = null;
    for (const p of lp.packages) {
      if (p.kind === 'package') { put(m, { ...p, via: `mcp:${key}` }); if (!first) first = p; }
      else put(m, { ...p, spec: `${key}: ${p.spec}` });
    }
    if (first && lp.packages.every(p => p.kind === 'package')) put(m, { kind: 'mcp', key, where, server: first.name, version: first.version, via: cmd });
    else if (!lp.packages.some(p => p.kind !== 'package')) say('no resolvable package');
  }
  return m;
}

// ---- Files we do not resolve, and installer config that redirects fetches.

function fnv(text) { let h = 0x811c9dc5; for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return h.toString(16); }

function fromUnsupported(text, { file = '' } = {}) {
  const m = new Map();
  const it = unknown(file, 'this manifest/lockfile format is not parsed by this check: the dependencies it installs were not judged');
  it.contentHash = fnv(String(text));
  m.set(`skip:${file}:${it.contentHash}`, it);
  return m;
}

const REDIRECT_KEY = /registry|index|find-links|trusted-host|mirror|npmScopes|unsafeHttpWhitelist|replace-registry-host|BUNDLE_MIRROR|BUNDLE_.*SOURCE|ignore-scripts|script-shell|node-options/i;
function fromInstallConfig(text, { file = '' } = {}) {
  const m = new Map();
  pySplitLines(text).forEach((line, idx) => {
    const l = line.replace(/^\s*[#;].*$/, '').trim();
    if (!l) return;
    const eq = l.indexOf('=');
    const key = (eq >= 0 ? l.slice(0, eq) : l.split(/:\s/)[0]).trim();
    if (REDIRECT_KEY.test(key)) {
      // The key is reported; the value is not (it may be a committed credential).
      const it = unknown(`${file}: ${key.slice(0, 60)}`, `installer configuration changes where packages are fetched from or how they run (line ${idx + 1})`);
      it.contentHash = fnv(l);
      m.set(`skip:${file}:${key}:${it.contentHash}`, it);
    }
  });
  return m;
}

function parse(kind, text, opts = {}) {
  switch (kind) {
    case 'package.json': return fromPackageJson(text);
    case 'package-lock': return fromPackageLock(text, opts);
    case 'requirements': return fromRequirements(text, opts);
    case 'pyproject': return fromPyproject(text);
    case 'poetry.lock': return fromPoetryLock(text);
    case 'gemfile': return fromGemfile(text);
    case 'gemfile.lock': return fromGemfileLock(text);
    case 'mcp': return fromMcpConfig(text);
    case 'unsupported': return fromUnsupported(text, opts);
    case 'install-config': return fromInstallConfig(text, opts);
    default: return new Map();
  }
}

// Items present in `after` that are new or different vs `before`.
// A file that does not parse is an UNKNOWN item, never just a note: an installer may still read it.
function diffItems(kind, beforeText, afterText, opts = {}, beforeOpts = opts) {
  const errors = [];
  let before = new Map(), after;
  if (beforeText != null) { try { before = parse(kind, decode(kind, beforeText), beforeOpts); } catch { /* treat old as empty: everything is new */ } }
  try { after = parse(kind, decode(kind, afterText), opts); } catch (e) {
    const msg = String((e && e.message) || e).replace(/\s+/g, ' ').slice(0, 120);
    errors.push(`does not parse (${msg}); its dependencies were NOT checked`);
    after = new Map();
    const f = opts.file || kind;
    after.set(`skip:parse:${f}`, unknown(f, `file does not parse with this check's ${kind} reader (${msg}); an installer may still read it, so nothing in it was judged`));
  }
  const items = [];
  for (const [k, v] of after) {
    const b = before.get(k);
    if (!b) items.push({ ...v, change: 'added' });
    else if (JSON.stringify(b) !== JSON.stringify(v)) items.push({ ...v, change: 'changed' });
  }
  return { items, errors };
}

module.exports = {
  EXACT_SEMVER, pep503, pkgKey, manifestKind, parseNpmSpec, npmFromRange, parsePipSpec, parse, diffItems, decode,
  pipLogicalLines, npmRegistryIdentity,
  fromPackageJson, fromPackageLock, fromRequirements, fromPyproject, fromPoetryLock, fromGemfile, fromGemfileLock, fromMcpConfig,
};
