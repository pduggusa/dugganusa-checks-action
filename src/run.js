'use strict';
// Orchestration: decide scan mode, collect manifests, diff, check, report, decide job status.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const parsers = require('./parsers');
const { Client, clean } = require('./api');

const FAIL_ON = ['block', 'review', 'none'];
const ORDER = { BLOCK: 0, ADVISORY: 1, REVIEW: 2, UNKNOWN: 3, ALLOW: 4 };

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
}

function readEvent() {
  try { return JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')); } catch { return {}; }
}

// -> { mode: 'diff'|'full', base: sha|null, reason }
function resolveMode({ modeInput, eventName, event, baseInput }) {
  if (modeInput === 'full') return { mode: 'full', base: null, reason: 'mode: full' };
  let base = baseInput || null;
  if (!base && /^pull_request/.test(eventName || '') && event.pull_request && event.pull_request.base) base = event.pull_request.base.sha;
  if (!base && modeInput === 'diff' && eventName === 'push' && event.before && !/^0+$/.test(event.before)) base = event.before;
  if (modeInput === 'diff' || (modeInput === 'auto' && /^pull_request|^merge_group/.test(eventName || ''))) {
    if (!base && eventName === 'merge_group' && event.merge_group) base = event.merge_group.base_sha;
    if (base) return { mode: 'diff', base, reason: `${eventName || 'run'}: only dependencies added or changed since ${base.slice(0, 12)}` };
    return { mode: 'full', base: null, reason: 'no base commit available for a diff; scanned everything' };
  }
  return { mode: 'full', base: null, reason: `${eventName || 'run'}: full scan of every manifest` };
}

function ensureCommit(cwd, sha) {
  try { git(cwd, ['cat-file', '-e', `${sha}^{commit}`]); return true; } catch { /* fetch it */ }
  try { git(cwd, ['fetch', '--no-tags', '--depth=1', 'origin', sha]); git(cwd, ['cat-file', '-e', `${sha}^{commit}`]); return true; } catch { return false; }
}

function listFiles(cwd) {
  try { return git(cwd, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0').filter(Boolean); } catch { /* not a git checkout */ }
  const out = [];
  const walk = (d, rel) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(path.join(d, e.name), r); else if (e.isFile()) out.push(r);
    }
  };
  walk(cwd, '');
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
    files = git(cwd, ['diff', '--name-only', '-z', '--diff-filter=AMR', base, 'HEAD']).split('\0').filter(Boolean);
    // uncommitted working-tree changes count too (local runs, or a prior step that rewrote a lockfile)
    try { for (const f of git(cwd, ['diff', '--name-only', '-z', 'HEAD']).split('\0').filter(Boolean)) if (!files.includes(f)) files.push(f); } catch { /* ignore */ }
  } else {
    files = listFiles(cwd);
  }
  files = files.filter(f => parsers.manifestKind(f) && (!pathFilter || pathFilter(f)));
  if (!checkMcp) files = files.filter(f => parsers.manifestKind(f) !== 'mcp');
  const transitive = includeTransitive === 'auto' ? mode === 'diff' : includeTransitive === 'true';
  const byKey = new Map();
  const texts = {};
  for (const f of files) {
    const kind = parsers.manifestKind(f);
    let newText;
    try { newText = fs.readFileSync(path.join(cwd, f), 'utf8'); } catch { continue; }
    texts[f] = newText;
    let oldText = null;
    if (mode === 'diff') { try { oldText = git(cwd, ['show', `${base}:${f}`]); } catch { oldText = null; } }
    const { items, errors } = parsers.diffItems(kind, oldText, newText, { transitive });
    for (const e of errors) notes.push({ file: f, text: `${f} ${e}`, level: 'warning' });
    for (const it of items) {
      it.files = [f];
      it.line = lineOf(newText, it.kind === 'mcp' ? it.key : it.name);
      const k = it.kind === 'package' ? parsers.pkgKey(it.ecosystem, it.name, it.version) : it.kind === 'mcp' ? `mcp:${it.server}@${it.version || ''}` : `skip:${f}:${it.spec}`;
      const prev = byKey.get(k);
      if (prev) { if (!prev.files.includes(f)) prev.files.push(f); continue; }
      byKey.set(k, it);
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
    if (i.kind === 'skip') return { item: i, verdict: 'UNKNOWN', reason: `not checked: ${i.reason}`, evidence: [] };
    if (used >= maxLookups) return { item: i, verdict: 'UNKNOWN', reason: `not checked: lookup cap (max-lookups=${maxLookups}) reached`, evidence: [] };
    used++;
    const r = i.kind === 'mcp' ? await client.checkMcpServer(i) : await client.checkPackage(i);
    log(`${i.kind === 'mcp' ? 'mcp' : i.ecosystem} ${label(i)}${i.version ? '@' + i.version : ''}: ${r.verdict}`);
    return { item: i, ...r };
  });
  // The client paces and serializes per lane, so starting them all is safe.
  for (const r of await Promise.all(work)) results.push(r);
  return results;
}

function decide(results, { failOn, failOnUnknown }) {
  const counts = { BLOCK: 0, ADVISORY: 0, REVIEW: 0, UNKNOWN: 0, ALLOW: 0 };
  for (const r of results) counts[r.verdict] = (counts[r.verdict] || 0) + 1;
  const failing = (v) => (failOn !== 'none' && v === 'BLOCK')
    || (failOn === 'review' && (v === 'REVIEW' || v === 'ADVISORY'))
    || (failOnUnknown && v === 'UNKNOWN');
  const failed = results.some(r => failing(r.verdict));
  return { counts, failed, failing };
}

function mdCell(s) { return clean(s, 400).replace(/\|/g, '\\|').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

const ICON = { BLOCK: '⛔ BLOCK', ADVISORY: '⚠️ ADVISORY', REVIEW: '⚠️ REVIEW', UNKNOWN: '❔ UNKNOWN', ALLOW: '✅ ALLOW' };

function summaryMarkdown({ results, counts, failed, modeInfo, notes, failOn, failOnUnknown, keyed, client, transitive }) {
  const L = [];
  L.push('## DugganUSA Checks');
  L.push('');
  L.push(`**Result: ${failed ? 'FAILED' : 'passed'}** · ${modeInfo.reason}${modeInfo.mode === 'diff' ? (transitive ? ' (lockfile transitives included)' : '') : (transitive ? '' : ' (lockfile transitives skipped; set include-transitive: true)')}`);
  L.push('');
  L.push(`| BLOCK | ADVISORY | REVIEW | UNKNOWN | ALLOW |`);
  L.push(`|---:|---:|---:|---:|---:|`);
  L.push(`| ${counts.BLOCK} | ${counts.ADVISORY} | ${counts.REVIEW} | ${counts.UNKNOWN} | ${counts.ALLOW} |`);
  L.push('');
  L.push(`Fails on: BLOCK${failOn === 'review' ? ', REVIEW, ADVISORY' : ''}${failOn === 'none' ? ' (disabled: fail-on none)' : ''}${failOnUnknown ? ', UNKNOWN' : ''}. ${counts.UNKNOWN && !failOnUnknown ? `**${counts.UNKNOWN} UNKNOWN: these were not judged and are not a pass.**` : ''}`);
  L.push('');
  if (results.length) {
    L.push('| Verdict | Type | Name | Version | File | Reason | Evidence |');
    L.push('|---|---|---|---|---|---|---|');
    const sorted = [...results].sort((a, b) => ORDER[a.verdict] - ORDER[b.verdict] || label(a.item).localeCompare(label(b.item)));
    for (const r of sorted) {
      const i = r.item;
      const type = i.kind === 'mcp' ? 'MCP server' : i.kind === 'skip' ? 'source' : `${i.ecosystem}${i.transitive ? ' (transitive)' : ''}`;
      L.push(`| ${ICON[r.verdict]} | ${type} | \`${mdCell(label(i))}\` | ${mdCell(i.version || '—')} | ${mdCell(i.files.join(', '))} | ${mdCell(r.reason)} | ${mdCell((r.evidence || []).join(', ') || '—')} |`);
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

module.exports = { resolveMode, ensureCommit, collect, check, decide, summaryMarkdown, readEvent, label, FAIL_ON, Client };
