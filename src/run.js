'use strict';
// Orchestration: decide scan mode, collect manifests, diff, check, report, decide job status.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const parsers = require('./parsers');
const { Client, clean } = require('./api');
const { neutralize } = require('./gha');

const FAIL_ON = ['block', 'review', 'none'];
const ORDER = { BLOCK: 0, ADVISORY: 1, REVIEW: 2, UNKNOWN: 3, ALLOW: 4 };

// Git is run with repository-supplied configuration hooks disabled, and never with a pager,
// external diff driver or textconv filter that a repository's attributes could name.
const GIT_SAFE = ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'diff.external=', '-c', 'core.pager=cat', '-c', 'protocol.ext.allow=never'];
function git(cwd, args, { buffer = false } = {}) {
  return execFileSync('git', [...GIT_SAFE, ...args], { cwd, encoding: buffer ? 'buffer' : 'utf8', maxBuffer: 256 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat', GIT_EXTERNAL_DIFF: '' } });
}

// A base revision we pass to git: a hex object id, or (from the workflow's base-ref input) a
// plain ref name. Never anything that starts with "-" and could be read as an option.
function validRev(rev) {
  const r = String(rev || '');
  return /^[0-9a-fA-F]{7,64}$/.test(r) || (/^[A-Za-z0-9_][A-Za-z0-9._/-]{0,250}$/.test(r) && !r.includes('..') && !r.endsWith('.lock') && !r.endsWith('/'));
}

function readEvent() {
  try { return JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')); } catch { return {}; }
}

// -> { mode: 'diff'|'full', base: sha|null, reason }
function resolveMode({ modeInput, eventName, event, baseInput }) {
  if (modeInput === 'full') return { mode: 'full', base: null, reason: 'mode: full' };
  if (baseInput && !validRev(baseInput)) throw new Error('base-ref must be a commit SHA or a plain ref name');
  let base = baseInput || null;
  const sha = (x) => (typeof x === 'string' && /^[0-9a-fA-F]{7,64}$/.test(x) ? x : null);
  if (!base && /^pull_request/.test(eventName || '') && event.pull_request && event.pull_request.base) base = sha(event.pull_request.base.sha);
  if (!base && modeInput === 'diff' && eventName === 'push' && event.before && !/^0+$/.test(event.before)) base = sha(event.before);
  if (modeInput === 'diff' || (modeInput === 'auto' && /^pull_request|^merge_group/.test(eventName || ''))) {
    if (!base && eventName === 'merge_group' && event.merge_group) base = sha(event.merge_group.base_sha);
    if (base) return { mode: 'diff', base, reason: `${eventName || 'run'}: only dependencies added or changed since ${base.slice(0, 12)}` };
    return { mode: 'full', base: null, reason: 'no base commit available for a diff; scanned everything' };
  }
  return { mode: 'full', base: null, reason: `${eventName || 'run'}: full scan of every manifest` };
}

function ensureCommit(cwd, sha) {
  if (!validRev(sha)) return false;
  try { git(cwd, ['cat-file', '-e', `${sha}^{commit}`]); return true; } catch { /* fetch it */ }
  if (!/^[0-9a-fA-F]{40,64}$/.test(sha)) return false;
  try { git(cwd, ['fetch', '--no-tags', '--no-recurse-submodules', '--depth=1', 'origin', sha]); git(cwd, ['cat-file', '-e', `${sha}^{commit}`]); return true; } catch { return false; }
}

const MAX_FILE_BYTES = 32 * 1024 * 1024;

// Read a repository file without ever leaving the repository: the path must be relative with no
// ".." or NUL, every component must resolve inside root, the file itself must be a regular file
// (not a symlink, FIFO, socket or device) and no larger than MAX_FILE_BYTES. Throws on refusal.
// A symlinked package.json pointing at /proc/self/environ or ~/.ssh would otherwise be parsed,
// and its contents would leak into names sent to the API and into the public job log.
function safeRead(root, rel) {
  const r = String(rel);
  if (!r || r.includes('\0') || path.isAbsolute(r) || r.split(/[\\/]/).some(seg => seg === '..')) throw new Error('path is outside the repository');
  const realRoot = fs.realpathSync(root);
  const full = path.resolve(realRoot, r);
  if (full !== realRoot && !full.startsWith(realRoot + path.sep)) throw new Error('path is outside the repository');
  const parent = fs.realpathSync(path.dirname(full));
  if (parent !== realRoot && !parent.startsWith(realRoot + path.sep)) throw new Error('a directory on the path is a symlink out of the repository');
  const st = fs.lstatSync(full);
  if (st.isSymbolicLink()) throw new Error('is a symlink (not followed)');
  if (!st.isFile()) throw new Error('is not a regular file');
  if (st.size > MAX_FILE_BYTES) throw new Error(`is larger than ${MAX_FILE_BYTES} bytes`);
  const fd = fs.openSync(full, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
    const st2 = fs.fstatSync(fd);
    if (!st2.isFile() || st2.ino !== st.ino || st2.dev !== st.dev) throw new Error('changed while being read');
    if (st2.size > MAX_FILE_BYTES) throw new Error(`is larger than ${MAX_FILE_BYTES} bytes`);
    return fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
}

// The committed content of a file at a revision (a git blob: never a symlink target on disk).
function showAt(cwd, rev, rel) {
  if (!validRev(rev)) return null;
  try {
    const spec = `${rev}:./${rel}`;
    const type = git(cwd, ['cat-file', '-t', spec]).trim();
    if (type !== 'blob') return null;
    const mode = git(cwd, ['ls-tree', rev, '--', `./${rel}`]).split(' ')[0];
    if (mode === '120000') return null; // a symlink blob holds a path, not a manifest
    const size = Number(git(cwd, ['cat-file', '-s', spec]).trim());
    if (!(size <= MAX_FILE_BYTES)) return null;
    return git(cwd, ['cat-file', 'blob', spec], { buffer: true });
  } catch { return null; }
}

const MAX_WALK_DEPTH = 64;
// -> array of repository-relative paths; out.truncated lists directories past the depth limit
// (reported as unknown:ambiguous by collect, never silently skipped).
function listFiles(cwd) {
  try { return git(cwd, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0').filter(Boolean); } catch { /* not a git checkout */ }
  const out = [];
  out.truncated = [];
  const walk = (d, rel, depth) => {
    if (depth > MAX_WALK_DEPTH) { out.truncated.push(rel); return; }
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(path.join(d, e.name), r, depth + 1); else if (e.isFile()) out.push(r);
    }
  };
  walk(cwd, '', 0);
  return out;
}

function lineOf(text, needle) {
  if (!text || !needle) return undefined;
  const lines = text.split('\n');
  const q = [`"${needle}"`, `'${needle}'`, `node_modules/${needle}"`, `    ${needle} (`, needle];
  for (const n of q) { const i = lines.findIndex(l => l.includes(n)); if (i >= 0) return i + 1; }
  return undefined;
}

// Collect checkable items from the repo. -> { items: [...], notes: [...] }
function collect({ cwd, mode, base, includeTransitive, checkMcp, pathFilter }) {
  const notes = [];
  let files;
  if (mode === 'diff') {
    if (!validRev(base)) throw new Error('invalid base revision');
    // --relative: paths relative to (and limited to) the working directory, which is what we read
    files = git(cwd, ['diff', '--no-ext-diff', '--no-textconv', '--relative', '--name-only', '-z', '--diff-filter=ACMRT', base, 'HEAD', '--']).split('\0').filter(Boolean);
    // uncommitted working-tree changes count too (local runs, or a prior step that rewrote a lockfile)
    try { for (const f of git(cwd, ['diff', '--no-ext-diff', '--no-textconv', '--relative', '--name-only', '-z', 'HEAD', '--']).split('\0').filter(Boolean)) if (!files.includes(f)) files.push(f); } catch { /* ignore */ }
    // A requirements file can pull in any other file with -r/-c; re-read them all so a change to
    // an included file is seen even when the including file did not change. Unchanged = no items.
    for (const f of listFiles(cwd)) if (parsers.manifestKind(f) === 'requirements' && !files.includes(f)) files.push(f);
  } else {
    files = listFiles(cwd);
  }
  const truncated = files.truncated || [];
  files = files.filter(f => parsers.manifestKind(f) && (!pathFilter || pathFilter(f)));
  if (!checkMcp) files = files.filter(f => parsers.manifestKind(f) !== 'mcp');
  const transitive = includeTransitive === 'auto' ? mode === 'diff' : includeTransitive === 'true';
  const byKey = new Map();
  const texts = {};
  const addItem = (f, it, text) => {
    it.files = [f];
    it.line = lineOf(text, it.kind === 'mcp' ? it.key : it.name);
    const k = it.kind === 'package' ? parsers.pkgKey(it.ecosystem, it.name, it.version) : it.kind === 'mcp' ? `mcp:${it.server}@${it.version || ''}` : `skip:${f}:${it.spec}`;
    const prev = byKey.get(k);
    // an ambiguous finding is never hidden behind an earlier, milder item with the same key
    if (prev && !(it.kind === 'skip' && it.cls === 'ambiguous' && prev.cls !== 'ambiguous')) { if (!prev.files.includes(f)) prev.files.push(f); return; }
    byKey.set(k, it);
  };
  for (const d of truncated) addItem(d, parsers.unknown(d, `directory nesting deeper than ${MAX_WALK_DEPTH} levels was not scanned`), '');
  for (const f of files) {
    const kind = parsers.manifestKind(f);
    let newBuf;
    try { newBuf = safeRead(cwd, f); } catch (e) {
      addItem(f, { kind: 'skip', unverifiable: true, cls: 'ambiguous', spec: f, reason: `file not read: ${e.message}. Installers may still read it, so nothing in it was judged`, change: 'added' }, '');
      continue;
    }
    let newText = '';
    try { newText = parsers.decode(kind, newBuf); } catch { newText = ''; }
    texts[f] = newText;
    const oldBuf = mode === 'diff' ? showAt(cwd, base, f) : null;
    const readNew = (rel) => { try { return parsers.decode('requirements', safeRead(cwd, rel)); } catch { return null; } };
    const readOld = (rel) => { const b = showAt(cwd, base, rel); if (!b) return null; try { return parsers.decode('requirements', b); } catch { return null; } };
    const { items, errors } = parsers.diffItems(kind, oldBuf, newBuf, { transitive, file: f, readInclude: readNew }, { transitive, file: f, readInclude: readOld });
    for (const e of errors) notes.push({ file: f, text: `${f} ${e}`, level: 'warning' });
    for (const it of items) addItem(f, it, newText);
  }
  // npx runs a package of the same name from this repository (a workspace member, or a file:/git/
  // alias dependency installed into node_modules) instead of fetching the registry package we
  // judge. Every package.json in the repository is read for this, changed or not.
  const npx = [...byKey.entries()].filter(([, i]) => i.kind === 'mcp' && i.via === 'npx');
  if (npx.length) {
    const shadow = new Set();
    for (const f of listFiles(cwd)) {
      if (parsers.manifestKind(f) !== 'package.json') continue;
      try { for (const n of parsers.localNpmNames(parsers.decode('package.json', safeRead(cwd, f)))) shadow.add(n); } catch { /* unreadable: reported elsewhere if changed */ }
    }
    for (const [k, i] of npx) {
      if (!shadow.has(String(i.server).toLowerCase())) continue;
      byKey.set(k, { ...parsers.unknown(i.key, `MCP server "${i.key}": npx package "${i.server}" has the same name as a package or non-registry dependency in this repository, so npx may run the local copy instead of the registry package`), files: i.files, line: i.line, change: i.change });
    }
  }
  let items = [...byKey.values()];
  // A range in package.json plus the exact version from the lockfile is one package: keep the exact one.
  const exact = new Set(items.filter(i => i.kind === 'package' && i.version).map(i => `${i.ecosystem}:${i.ecosystem === 'pypi' ? parsers.pep503(i.name) : i.name.toLowerCase()}`));
  items = items.filter(i => !(i.kind === 'package' && !i.version && exact.has(`${i.ecosystem}:${i.ecosystem === 'pypi' ? parsers.pep503(i.name) : i.name.toLowerCase()}`)));
  // Non-checkable local sources (path/workspace) are notes; unverifiable remote sources are UNKNOWN rows.
  for (const i of items.filter(x => x.kind === 'skip' && !x.unverifiable)) notes.push({ file: i.files[0], text: `${i.files[0]}: ${i.spec}: ${i.reason}; not checked`, level: 'notice' });
  items = items.filter(i => !(i.kind === 'skip' && !i.unverifiable));
  return { items, notes, files, texts, transitive };
}

function label(i) {
  if (i.kind === 'mcp') return `${i.key}${i.server !== i.key ? ` → ${i.server}` : ''}`;
  if (i.kind === 'skip') return i.spec;
  return i.name;
}

async function check(items, client, { maxLookups, log }) {
  // Priority under the lookup cap: MCP servers, then direct deps, then transitive ones.
  const prio = (i) => (i.kind === 'mcp' ? 0 : i.kind === 'skip' ? 3 : i.transitive ? 2 : 1);
  const sorted = [...items].sort((a, b) => prio(a) - prio(b));
  let used = 0;
  const results = [];
  const work = sorted.map(async (i) => {
    if (i.kind === 'skip') return { item: i, verdict: 'UNKNOWN', unknown_class: i.cls === 'not_in_corpus' ? 'not_in_corpus' : 'ambiguous', reason: `not checked: ${i.reason}`, evidence: [] };
    // a count limit is attacker-reachable (pad the PR), so what it cuts off fails by default (unchecked)
    if (used >= maxLookups) return { item: i, verdict: 'UNKNOWN', unknown_class: 'unchecked', reason: `not checked: lookup cap (max-lookups=${maxLookups}) reached`, evidence: [] };
    used++;
    const r = i.kind === 'mcp' ? await client.checkMcpServer(i) : await client.checkPackage(i);
    log(`${i.kind === 'mcp' ? 'mcp' : i.ecosystem} ${neutralize(label(i), 200)}${i.version ? '@' + neutralize(i.version, 80) : ''}: ${r.verdict}`);
    // unchecked: the API never answered (unreachable, 5xx, timeout, 429 past the wait budget, bad
    // response). not_in_corpus: it answered and holds no record.
    return { item: i, ...r, ...(r.verdict === 'UNKNOWN' ? { unknown_class: r.unknown_class === 'unchecked' ? 'unchecked' : 'not_in_corpus' } : {}) };
  });
  // The client paces and serializes per lane, so starting them all is safe.
  for (const r of await Promise.all(work)) results.push(r);
  return results;
}

// Three classes of UNKNOWN:
//   ambiguous      evasion-shaped (non-canonical launcher, git/url/file/alias spec, duplicate key,
//                  Gemfile code, a parser limit hit, unparsed manifest...): fails unless fail-on-ambiguous is false.
//   unchecked      a clean identity the API never judged: unreachable, 5xx, timeout, 429 past the wait
//                  budget, lookup cap. A PR can pad itself to cause this, so it fails unless fail-on-unchecked is false.
//   not_in_corpus  the API answered and holds no record (or a remote MCP server): fails only with fail-on-unknown.
// fail-on: none disables verdict failures, not the UNKNOWN gates (they have their own inputs).
// An UNKNOWN with no recognized class is ambiguous (fail closed).
const unknownClass = (r) => (r.verdict === 'UNKNOWN' ? (['not_in_corpus', 'unchecked'].includes(r.unknown_class) ? r.unknown_class : 'ambiguous') : null);
const CLASS_COUNT = { ambiguous: 'UNKNOWN_AMBIGUOUS', unchecked: 'UNKNOWN_UNCHECKED', not_in_corpus: 'UNKNOWN_NOT_IN_CORPUS' };
function decide(results, { failOn, failOnUnknown, failOnAmbiguous = true, failOnUnchecked = true }) {
  const counts = { BLOCK: 0, ADVISORY: 0, REVIEW: 0, UNKNOWN: 0, ALLOW: 0, UNKNOWN_AMBIGUOUS: 0, UNKNOWN_UNCHECKED: 0, UNKNOWN_NOT_IN_CORPUS: 0 };
  for (const r of results) {
    counts[r.verdict] = (counts[r.verdict] || 0) + 1;
    if (r.verdict === 'UNKNOWN') counts[CLASS_COUNT[unknownClass(r)]]++;
  }
  const failing = (r) => {
    const v = typeof r === 'string' ? r : r.verdict;
    if (failOn !== 'none' && v === 'BLOCK') return true;
    if (failOn === 'review' && (v === 'REVIEW' || v === 'ADVISORY')) return true;
    if (v !== 'UNKNOWN') return false;
    const cls = typeof r === 'string' ? 'ambiguous' : unknownClass(r);
    return cls === 'ambiguous' ? !!failOnAmbiguous : cls === 'unchecked' ? !!failOnUnchecked : !!failOnUnknown;
  };
  const failed = results.some(r => failing(r));
  return { counts, failed, failing };
}

// Job-summary cell from untrusted text. Every character markdown or HTML could act on is written
// as a numeric entity, so a package name, file name or API reason renders as text: no links,
// images, code-span breakouts, tables, headings or tags.
function mdCell(s) { return clean(s, 400).replace(/[\\`*_{}\[\]()#!|<>&~:@$]/g, (c) => `&#${c.charCodeAt(0)};`); }

const ICON = { BLOCK: '⛔ BLOCK', ADVISORY: '⚠️ ADVISORY', REVIEW: '⚠️ REVIEW', UNKNOWN: '❔ UNKNOWN', ALLOW: '✅ ALLOW' };
const CLASS_LABEL = { ambiguous: '🚩 UNKNOWN: ambiguous', unchecked: '⏳ UNKNOWN: unchecked', not_in_corpus: '❔ UNKNOWN: not in corpus' };
const icon = (r) => (r.verdict === 'UNKNOWN' ? CLASS_LABEL[unknownClass(r)] : ICON[r.verdict]);

function summaryMarkdown({ results, counts, failed, modeInfo, notes, failOn, failOnUnknown, failOnAmbiguous = true, failOnUnchecked = true, keyed, client, transitive }) {
  const L = [];
  L.push('## DugganUSA Checks');
  L.push('');
  L.push(`**Result: ${failed ? 'FAILED' : 'passed'}** · ${mdCell(modeInfo.reason)}${modeInfo.mode === 'diff' ? (transitive ? ' (lockfile transitives included)' : '') : (transitive ? '' : ' (lockfile transitives skipped; set include-transitive: true)')}`);
  L.push('');
  const amb = counts.UNKNOWN_AMBIGUOUS || 0; const unc = counts.UNKNOWN_UNCHECKED || 0; const nic = counts.UNKNOWN_NOT_IN_CORPUS || 0;
  L.push(`| BLOCK | ADVISORY | REVIEW | UNKNOWN: ambiguous | UNKNOWN: unchecked | UNKNOWN: not in corpus | ALLOW |`);
  L.push(`|---:|---:|---:|---:|---:|---:|---:|`);
  L.push(`| ${counts.BLOCK} | ${counts.ADVISORY} | ${counts.REVIEW} | ${amb} | ${unc} | ${nic} | ${counts.ALLOW} |`);
  L.push('');
  L.push(`Fails on: BLOCK${failOn === 'review' ? ', REVIEW, ADVISORY' : ''}${failOn === 'none' ? ' (disabled: fail-on none)' : ''}${failOnAmbiguous ? ', UNKNOWN: ambiguous' : ''}${failOnUnchecked ? ', UNKNOWN: unchecked' : ''}${failOnUnknown ? ', UNKNOWN: not in corpus' : ''}. ${counts.UNKNOWN && (!failOnUnknown || !failOnAmbiguous || !failOnUnchecked) ? `**${counts.UNKNOWN} UNKNOWN: these were not judged and are not a pass.**` : ''}`);
  L.push('');
  L.push('**UNKNOWN: ambiguous** means the entry is evasion-shaped: this check could not prove what would be installed or run (a non-canonical MCP launcher, a git/URL/file/alias spec, a duplicate key, Gemfile code, a parser limit hit, an unparsed manifest). It fails by default (`fail-on-ambiguous`). **UNKNOWN: unchecked** means the identity is clean but the API never judged it (unreachable, 5xx, timeout, rate limit past the wait budget, lookup cap); a pull request can pad itself to cause this, so it fails by default (`fail-on-unchecked`). **UNKNOWN: not in corpus** means the API answered and holds no record (or a remote MCP server); it fails only with `fail-on-unknown`.');
  L.push('');
  if (results.length) {
    L.push('| Verdict | Type | Name | Version | File | Reason | Evidence |');
    L.push('|---|---|---|---|---|---|---|');
    const sorted = [...results].sort((a, b) => ORDER[a.verdict] - ORDER[b.verdict] || label(a.item).localeCompare(label(b.item)));
    for (const r of sorted) {
      const i = r.item;
      const type = i.kind === 'mcp' ? 'MCP server' : i.kind === 'skip' ? 'source' : `${i.ecosystem}${i.transitive ? ' (transitive)' : ''}`;
      L.push(`| ${icon(r)} | ${type} | <code>${mdCell(label(i))}</code> | ${mdCell(i.version || '—')} | ${mdCell(i.files.join(', '))} | ${mdCell(r.reason)} | ${mdCell((r.evidence || []).join(', ') || '—')} |`);
    }
  } else {
    L.push('No dependency manifests or MCP configs with new or changed entries.');
  }
  if (notes.length) {
    L.push('');
    L.push('<details><summary>Notes</summary>');
    L.push('');
    for (const n of notes) L.push(`- ${mdCell(n.text)}`);
    L.push('');
    L.push('</details>');
  }
  L.push('');
  L.push(`<sub>${client.calls} API call(s)${client.rateLimited ? `, ${client.rateLimited} rate-limited` : ''}, ${keyed ? 'keyed' : 'keyless (anonymous free rate; add an api-key secret for more)'}. ALLOW means no known evidence against it, not proof of safety. UNKNOWN means nothing was judged. Verdicts come from the public DugganUSA check-package and Dredd preflight APIs; treat them as one input, not a guarantee.</sub>`);
  return L.join('\n');
}

module.exports = { unknownClass, listFiles, resolveMode, ensureCommit, collect, check, decide, summaryMarkdown, readEvent, label, safeRead, showAt, validRev, mdCell, FAIL_ON, Client };
