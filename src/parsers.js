'use strict';
// Manifest and MCP-config parsers. Zero dependencies on purpose: this code guards installs,
// so it must not need one.
//
// Every parser returns a Map of key -> item. An item is either
//   { kind: 'package', ecosystem: 'npm'|'pypi'|'rubygems', name, version|null, spec, note? }
//   { kind: 'mcp', key, server, version|null, via }
//   { kind: 'skip', spec, reason, unverifiable? }   (reported, never silently dropped)

const path = require('path');

const EXACT_SEMVER = /^v?=?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;

function pep503(name) { return String(name).toLowerCase().replace(/[-_.]+/g, '-'); }

function pkgKey(ecosystem, name, version) {
  const n = ecosystem === 'pypi' ? pep503(name) : String(name).toLowerCase();
  return `${ecosystem}:${n}@${version || ''}`;
}

function base(file) { return path.posix.basename(String(file).replace(/\\/g, '/')); }

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
  return null;
}

// ---------------------------------------------------------------------------
// Spec parsing
// ---------------------------------------------------------------------------

function parseNpmSpec(spec) {
  const s = String(spec).trim();
  if (!s) return null;
  if (/^(git\+|git:|github:|gitlab:|bitbucket:|https?:)/i.test(s)) return { kind: 'skip', unverifiable: true, spec: s, reason: 'git/URL source: not checkable against a registry deny-list' };
  if (/^(\.{0,2}\/|~\/|file:|link:|workspace:)/.test(s) || /\.(tgz|tar\.gz|tar)$/.test(s)) return { kind: 'skip', spec: s, reason: 'local path, workspace or tarball' };
  let name = s, range = null;
  const at = s.startsWith('@') ? s.indexOf('@', 1) : s.indexOf('@');
  if (at > 0) { name = s.slice(0, at); range = s.slice(at + 1); }
  if (range && range.startsWith('npm:')) return parseNpmSpec(range.slice(4)); // alias: the real package
  if (!s.startsWith('@') && name.includes('/')) return { kind: 'skip', unverifiable: true, spec: s, reason: 'GitHub shorthand (user/repo): not checkable against a registry deny-list' };
  if (!/^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i.test(name)) return { kind: 'skip', spec: s, reason: 'not a package name' };
  const out = { kind: 'package', ecosystem: 'npm', name, version: null, spec: s };
  if (range && EXACT_SEMVER.test(range)) out.version = range.replace(/^v?=?/, '');
  else if (range && range !== 'latest' && range !== '*') out.note = `range "${range}": no exact version, so the known-vulnerability check cannot run`;
  return out;
}

function parsePipSpec(spec) {
  let s = String(spec).trim();
  if (!s || s.startsWith('#')) return null;
  s = s.replace(/\s+#.*$/, '').split(';')[0].trim();
  if (!s) return null;
  if (s.startsWith('-')) return { kind: 'skip', spec: s, reason: 'pip option line (-r/-c/-e/--index-url): not followed', unverifiable: /index-url|find-links|^-e\b|--editable/.test(s) };
  if (/^(\.{0,2}\/|~\/|file:)/.test(s) || /\.(whl|tar\.gz|zip)$/.test(s)) return { kind: 'skip', spec: s, reason: 'local path or archive' };
  if (/^(git\+|hg\+|svn\+|bzr\+|https?:|ftp:)/.test(s) || /^[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?\s*@/.test(s)) return { kind: 'skip', unverifiable: true, spec: s, reason: 'VCS/URL source: not checkable against a registry deny-list' };
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/.exec(s);
  if (!m) return { kind: 'skip', spec: s, reason: 'not a requirement' };
  const constraint = (m[3] || '').trim();
  const out = { kind: 'package', ecosystem: 'pypi', name: m[1], version: null, spec: s };
  const exact = /^===?\s*([0-9][0-9A-Za-z.+!-]*)$/.exec(constraint);
  if (exact) out.version = exact[1];
  else if (constraint) out.note = `constraint "${constraint}": no exact pin, so the known-vulnerability check cannot run`;
  return out;
}

// ---------------------------------------------------------------------------
// Manifest parsers
// ---------------------------------------------------------------------------

function put(m, item) {
  if (!item) return;
  const k = item.kind === 'package' ? pkgKey(item.ecosystem, item.name, item.version)
    : item.kind === 'mcp' ? `mcp:${item.key}` : `skip:${item.spec}`;
  m.set(k, item);
}

function fromPackageJson(text) {
  const j = JSON.parse(text);
  const m = new Map();
  for (const sec of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, spec] of Object.entries((j && j[sec]) || {})) {
      const sp = String(spec);
      const p = /^(npm:|git|github:|gitlab:|bitbucket:|https?:|file:|link:|workspace:|\.|\/|~)/.test(sp) || (sp.includes('/') && !sp.startsWith('npm:'))
        ? parseNpmSpec(sp.startsWith('npm:') ? sp.slice(4) : sp)
        : parseNpmSpec(`${name}@${sp}`);
      if (p && p.kind === 'skip') p.spec = `${name}: ${p.spec}`;
      put(m, p);
    }
  }
  return m;
}

function fromPackageLock(text, { transitive = true } = {}) {
  const j = JSON.parse(text);
  const m = new Map();
  const pk = (j && j.packages) || {};
  for (const [p, info] of Object.entries(pk)) {
    if (!p || !p.includes('node_modules/') || !info || info.link || !info.version) continue;
    // direct deps sit at node_modules/<name>; nested ones are transitive
    const isDirect = /^node_modules\/(@[^/]+\/)?[^/]+$/.test(p);
    if (!transitive && !isDirect) continue;
    const name = info.name || p.slice(p.lastIndexOf('node_modules/') + 13);
    if (info.resolved && !/^https:\/\/registry\.(npmjs\.org|yarnpkg\.com)\//.test(info.resolved)) {
      put(m, { kind: 'skip', unverifiable: true, spec: `${name}@${info.version}`, reason: `resolved from a non-default registry or source (${String(info.resolved).slice(0, 80)}): the name was not checked` });
      continue;
    }
    put(m, { kind: 'package', ecosystem: 'npm', name, version: info.version, spec: `${name}@${info.version}`, transitive: !isDirect });
  }
  if (!Object.keys(pk).length && j && j.dependencies) { // lockfile v1
    const walk = (deps, depth) => {
      for (const [name, info] of Object.entries(deps || {})) {
        if (info && info.version && EXACT_SEMVER.test(info.version) && (transitive || depth === 0)) {
          put(m, { kind: 'package', ecosystem: 'npm', name, version: info.version, spec: `${name}@${info.version}`, transitive: depth > 0 });
        }
        walk(info && info.dependencies, depth + 1);
      }
    };
    walk(j.dependencies, 0);
  }
  return m;
}

function fromRequirements(text) {
  const m = new Map();
  // join backslash continuations; drop --hash options that trail a requirement
  const lines = String(text).replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.replace(/\s--hash=\S+/g, '').trim();
    if (!line || line.startsWith('#')) continue;
    put(m, parsePipSpec(line));
  }
  return m;
}

function tomlSections(text) {
  // -> array of { section, line }
  let section = '';
  return String(text).split(/\r?\n/).map(l => {
    const h = /^\s*\[\[?([^\]]+)\]\]?\s*(#.*)?$/.exec(l);
    if (h) section = h[1].trim();
    return { section, line: l, header: !!h };
  });
}

function fromPyproject(text) {
  const m = new Map();
  const t = String(text);
  const rows = tomlSections(t);
  // PEP 621 / PEP 735 arrays: collect multi-line arrays by scanning lines
  let i = 0;
  while (i < rows.length) {
    const { section, line } = rows[i];
    const a = /^\s*([A-Za-z0-9_-]+)\s*=\s*\[(.*)$/.exec(line);
    if (a) {
      const keyName = a[1];
      const isDeps = (section === 'project' && keyName === 'dependencies')
        || section === 'project.optional-dependencies' || section === 'dependency-groups'
        || (section === 'tool.uv' && keyName === 'dev-dependencies');
      let body = a[2];
      while (!/\]\s*(#.*)?$/.test(body) && i + 1 < rows.length) { i++; body += '\n' + rows[i].line; }
      if (isDeps) for (const q of body.matchAll(/["']([^"']+)["']/g)) put(m, parsePipSpec(q[1]));
    }
    i++;
  }
  // Poetry tables
  for (const { section, line, header } of rows) {
    if (header || !/^tool\.poetry\.(dev-)?dependencies$|^tool\.poetry\.group\.[^.]+\.dependencies$/.test(section)) continue;
    const kv = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.+)$/.exec(line);
    if (!kv || kv[1].toLowerCase() === 'python') continue;
    if (/\b(git|path|url)\s*=/.test(kv[2])) { put(m, { kind: 'skip', unverifiable: /git|url/.test(kv[2]), spec: kv[1], reason: 'Poetry git/path/url source: not checkable against a registry deny-list' }); continue; }
    const v = /version\s*=\s*["']([^"']+)["']/.exec(kv[2]) || /^["']([^"']+)["']/.exec(kv[2].trim());
    const ver = v ? v[1] : '';
    const spec = /^\d[\w.!+-]*$/.test(ver) ? `${kv[1]}==${ver}` : (ver && ver !== '*' ? `${kv[1]} ${ver}` : kv[1]);
    put(m, parsePipSpec(spec));
  }
  return m;
}

function fromPoetryLock(text) {
  const m = new Map();
  let cur = null;
  const flush = () => {
    if (cur && cur.name && cur.version) {
      if (cur.sourceType && cur.sourceType !== 'legacy') put(m, { kind: 'skip', unverifiable: true, spec: `${cur.name}==${cur.version}`, reason: `Poetry source type "${cur.sourceType}": not from PyPI, the name was not checked` });
      else if (cur.sourceType === 'legacy') put(m, { kind: 'skip', unverifiable: true, spec: `${cur.name}==${cur.version}`, reason: 'alternate package index (dependency-confusion surface): the name was judged on public PyPI only, so it was not checked' });
      else put(m, { kind: 'package', ecosystem: 'pypi', name: cur.name, version: cur.version, spec: `${cur.name}==${cur.version}` });
    }
    cur = null;
  };
  for (const { section, line, header } of tomlSections(text)) {
    if (header) { if (section === 'package') { flush(); cur = {}; } else if (section !== 'package.source' && !section.startsWith('package.')) flush(); continue; }
    if (!cur) continue;
    const kv = /^\s*(name|version|type)\s*=\s*["']([^"']+)["']/.exec(line);
    if (!kv) continue;
    if (section === 'package') { if (kv[1] !== 'type') cur[kv[1]] = kv[2]; }
    else if (section === 'package.source' && kv[1] === 'type') cur.sourceType = kv[2];
  }
  flush();
  return m;
}

function fromGemfile(text) {
  const m = new Map();
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '');
    const g = /^\s*gem\s+["']([A-Za-z0-9._-]+)["']\s*(.*)$/.exec(line);
    if (!g) continue;
    const name = g[1], rest = g[2];
    if (/\b(git|github|path|gist|bitbucket)\s*:|:(git|github|path)\s*=>/.test(rest)) { put(m, { kind: 'skip', unverifiable: /git|gist|bitbucket/.test(rest), spec: name, reason: 'Gemfile git/path source: not checkable against a registry deny-list' }); continue; }
    if (/\bsource\s*:|:source\s*=>/.test(rest)) { put(m, { kind: 'skip', unverifiable: true, spec: name, reason: 'per-gem source (dependency-confusion surface): not checked against RubyGems.org' }); continue; }
    const reqs = [...rest.matchAll(/["']([^"']+)["']/g)].map(x => x[1].trim());
    const exact = reqs.length === 1 ? /^=?\s*(\d[\w.-]*)$/.exec(reqs[0]) : null;
    const item = { kind: 'package', ecosystem: 'rubygems', name, version: exact ? exact[1] : null, spec: reqs.length ? `${name} ${reqs.join(', ')}` : name };
    if (!exact && reqs.length) item.note = `requirement "${reqs.join(', ')}": no exact version, so the known-vulnerability check cannot run`;
    put(m, item);
  }
  return m;
}

function fromGemfileLock(text) {
  const m = new Map();
  let block = '', inSpecs = false, remote = '';
  for (const line of String(text).split(/\r?\n/)) {
    if (/^[A-Z]/.test(line)) { block = line.trim(); inSpecs = false; remote = ''; continue; }
    if (/^ {2}remote:/.test(line)) { remote = line.split('remote:')[1].trim(); continue; }
    if (/^ {2}specs:/.test(line)) { inSpecs = true; continue; }
    if (!inSpecs) continue;
    const s = /^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)\s*$/.exec(line); // 4 spaces = a resolved gem; 6 = its requirements
    if (!s) continue;
    const version = s[2].replace(/-(x86|x64|arm|aarch|universal|java|mingw|mswin|darwin|linux|musl).*$/i, '');
    if (block !== 'GEM' || (remote && !/^https:\/\/(rubygems\.org|index\.rubygems\.org)\/?$/.test(remote))) {
      put(m, { kind: 'skip', unverifiable: true, spec: `${s[1]} (${s[2]})`, reason: `from ${block}${remote ? ' ' + remote : ''}: not RubyGems.org, the name was not checked` });
      continue;
    }
    put(m, { kind: 'package', ecosystem: 'rubygems', name: s[1], version, spec: `${s[1]} (${version})` });
  }
  return m;
}

// MCP configs: { mcpServers: {...} } (Claude, Cursor), { servers: {...} } (VS Code), Claude projects.
function mcpEntries(j) {
  const out = [];
  const collect = (obj) => { if (obj && typeof obj === 'object') for (const [k, v] of Object.entries(obj)) if (v && typeof v === 'object') out.push([k, v]); };
  collect(j && j.mcpServers);
  collect(j && j.servers);
  collect(j && j.mcp && j.mcp.servers);
  if (j && j.projects && typeof j.projects === 'object') for (const p of Object.values(j.projects)) collect(p && p.mcpServers);
  return out;
}

function fromMcpConfig(text) {
  const m = new Map();
  const j = JSON.parse(text);
  for (const [key, cfg] of mcpEntries(j)) {
    const cmd = base(cfg.command || '');
    const args = Array.isArray(cfg.args) ? cfg.args.map(String) : [];
    let server = key, version = null, via = cmd || (cfg.url ? 'url' : 'unknown');
    if (cfg.url || cfg.serverUrl) {
      via = 'url';
    } else if (['npx', 'bunx'].includes(cmd) || (['pnpm', 'yarn'].includes(cmd) && args[0] === 'dlx')) {
      const rest = cmd === 'npx' || cmd === 'bunx' ? args : args.slice(1);
      let pkgArg = null;
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i];
        if (a === '-p' || a === '--package') { pkgArg = rest[i + 1]; break; }
        if (a.startsWith('--package=')) { pkgArg = a.slice(10); break; }
        if (a.startsWith('-')) continue;
        pkgArg = a; break;
      }
      const p = pkgArg ? parseNpmSpec(pkgArg) : null;
      if (p && p.kind === 'package') { server = p.name; version = p.version; put(m, { ...p, via: `mcp:${key}` }); }
      else if (p) put(m, { ...p, spec: `${key}: ${p.spec}` });
    } else if (cmd === 'uvx' || (cmd === 'uv' && args[0] === 'tool' && args[1] === 'run') || (cmd === 'pipx' && args[0] === 'run')) {
      const rest = cmd === 'uvx' ? args : args.slice(2);
      let pkgArg = null;
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i];
        if (a === '--from') { pkgArg = rest[i + 1]; break; }
        if (/^--(python|with|index-url|extra-index-url)$/.test(a)) { i++; continue; }
        if (a.startsWith('-')) continue;
        pkgArg = a; break;
      }
      const p = pkgArg ? parsePipSpec(pkgArg.replace(/@(\d[\w.!+-]*)$/, '==$1')) : null;
      if (p && p.kind === 'package') { server = p.name; version = p.version; put(m, { ...p, via: `mcp:${key}` }); }
      else if (p) put(m, { ...p, spec: `${key}: ${p.spec}` });
    } else if (cmd === 'docker' || cmd === 'podman') {
      const img = args.find((a, i) => i > 0 && !a.startsWith('-') && /[/:]/.test(a));
      if (img) { const [n, tag] = img.split(/:(?=[^/]+$)/); server = n.split('/').pop(); version = tag && tag !== 'latest' ? tag : null; }
    }
    put(m, { kind: 'mcp', key, server, version, via });
  }
  return m;
}

function parse(kind, text, opts = {}) {
  switch (kind) {
    case 'package.json': return fromPackageJson(text);
    case 'package-lock': return fromPackageLock(text, opts);
    case 'requirements': return fromRequirements(text);
    case 'pyproject': return fromPyproject(text);
    case 'poetry.lock': return fromPoetryLock(text);
    case 'gemfile': return fromGemfile(text);
    case 'gemfile.lock': return fromGemfileLock(text);
    case 'mcp': return fromMcpConfig(text);
    default: return new Map();
  }
}

// Items present in `after` that are new or different vs `before`.
function diffItems(kind, beforeText, afterText, opts = {}) {
  const errors = [];
  let before = new Map(), after;
  if (beforeText) { try { before = parse(kind, beforeText, opts); } catch { /* treat old as empty */ } }
  try { after = parse(kind, afterText, opts); } catch (e) { errors.push(`does not parse (${e.message.slice(0, 120)}); its dependencies were NOT checked`); after = new Map(); }
  const items = [];
  for (const [k, v] of after) {
    const b = before.get(k);
    if (!b) items.push({ ...v, change: 'added' });
    // same key, different content: an MCP entry edited in place, or a package.json range bump
    else if (JSON.stringify(b) !== JSON.stringify(v)) items.push({ ...v, change: 'changed' });
  }
  return { items, errors };
}

module.exports = {
  EXACT_SEMVER, pep503, pkgKey, manifestKind, parseNpmSpec, parsePipSpec, parse, diffItems,
  fromPackageJson, fromPackageLock, fromRequirements, fromPyproject, fromPoetryLock, fromGemfile, fromGemfileLock, fromMcpConfig,
};
