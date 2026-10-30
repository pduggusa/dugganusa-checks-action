'use strict';
// PORTED from DugganUSA microservices/analytics-dashboard/lib/untrusted-repo-scan.js (the canonical copy, also served
// by the Jeevesus MCP tool check-repo and the scan-untrusted-repo command line). Keep the analyzer below
// byte-identical to it; only fromRepoLures at the bottom is specific to this action.
/**
 * untrusted-repo-scan: should you open or run this repository? (2026-10-30)
 *
 * WHY: the recurring way a developer laptop is lost is a stranger's repository: a recruiter's "coding test",
 * a zip from a job board, a PoC from a forum. Binance's first account of its 2026-10-29 loss is an engineer's
 * laptop; the FBI describes TraderTraitor reaching staff with fake recruitment tests. A dependency check never
 * reads the places those lures live: install hooks, an editor task that runs on folder open, an agent hook
 * file, a devcontainer command, a yarn binary committed to the repo.
 *
 * Pure function over { path: text }. No network, no filesystem, no dependencies, bounded and linear:
 * every pattern runs on a clipped string and none has nested quantifiers. A finding is a reason to read the
 * file by hand, not proof of malice. "No findings" means none of these patterns were seen; it does not
 * mean the repository is safe.
 *
 * Rules:
 *   RLS-001  npm install hook (preinstall/install/postinstall/dependencies/prepare...) or binding.gyp that fetches or evaluates code
 *   RLS-002  VS Code task set to run when the folder opens
 *   RLS-003  agent or editor hook/server config that runs a command (.claude, .cursor, .mcp.json)
 *   RLS-004  devcontainer lifecycle command (initializeCommand runs on the HOST)
 *   RLS-005  package manager config that executes repo code or redirects installs (.yarnrc, .npmrc, .pnpmfile)
 *   RLS-006  dependency fetched from a git or URL source (runs its install scripts)
 *   RLS-007  source file that decodes and evaluates a payload
 *   RLS-008  python setup.py that fetches or evaluates code at install
 */

const crypto = require('crypto');
const MAX_FILES = 3000;
const MAX_BYTES_PER_FILE = 200 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
const CLIP = 4000;          // characters of any one script or command examined
const MAX_FINDINGS = 100;

const clip = (s, n = 120) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, ' ').trim().slice(0, n);
const norm = (p) => String(p).replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, '?').replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');   // never truncated: matching runs on the full path, only display is clipped
const base = (p) => p.slice(p.lastIndexOf('/') + 1);

// Strong: executes what it fetched or decoded. BLOCK.
const STRONG = [
  [/\b(?:curl|wget)\b[^\n]{0,300}?\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i, 'pipes a download into a shell'],
  [/\b(?:node|python3?|ruby|perl|php)\s+-[ec]\b/i, 'runs an inline program'],
  [/\b(?:powershell|pwsh)\b[^\n]{0,200}?(?:-enc\w*|-e\s|iex|invoke-expression|downloadstring|downloadfile)/i, 'runs PowerShell with encoded or downloaded content'],
  [/\b(?:iex|invoke-expression)\b/i, 'evaluates a string as PowerShell'],
  [/\bbase64\s+(?:-d|--decode)\b/i, 'decodes base64 in a shell'],
  [/\batob\s*\(|Buffer\.from\([^)]{0,200}['"]base64['"]/i, 'decodes base64 in script'],
  [/\b(?:certutil|bitsadmin|mshta|regsvr32)\b/i, 'uses a Windows download or proxy-execution tool'],
  [/\b(?:ba|z|da)?sh\s+-c\s+["']?(?:\$\(|`)\s*(?:curl|wget)\b/i, 'runs a downloaded script through sh -c'],
  [/\b(?:ba|z|da)?sh\s+<\(\s*(?:curl|wget)\b/i, 'runs a downloaded script through process substitution'],
];
// Weak: reaches the network. REVIEW.
const WEAK = [
  [/\b(?:curl|wget)\b/i, 'downloads with curl or wget'],
  [/\bhttps?:\/\/[^\s"'`]{1,200}/i, 'contains a URL'],
  [/\b(?:nc|ncat|netcat)\b\s+-?\w*\s*[\w.]+\s+\d{2,5}/i, 'opens a raw network connection'],
];
const NPM_HOOKS = ['preinstall', 'install', 'postinstall', 'dependencies', 'prepublish', 'preprepare', 'prepare', 'postprepare'];
// Scripts that are ordinary and local. Not evidence of anything; they still get resolved one level.
const BENIGN_HOOK = /^(?:husky(?:\s+install)?|tsc(?:\s[\w .\-/=]*)?|node-gyp\s+rebuild|patch-package|prisma\s+generate|npx\s+(?:--no-install\s+)?(?:husky|patch-package)(?:\s+install)?|simple-git-hooks|lefthook\s+install|echo(?:\s+[\w .,:'"-]*)?)$/;
const SHELL_META = /[$`()<>|;&\n\r\\]/;

// ONE command or string value at a time, clipped, so padding in front of a payload cannot hide it.
function classifyOne(s) {
  for (const [re, why] of STRONG) if (re.test(s)) return { level: 'strong', why };
  for (const [re, why] of WEAK) if (re.test(s)) return { level: 'weak', why };
  return null;
}
// A string longer than the clip is read in overlapping windows, so padding in front of a payload cannot hide it
// (review of 2026-10-30). Linear: at most about 55 windows for a 200 KB file.
function classify(cmd) {
  const t = String(cmd);
  if (t.length <= CLIP) return classifyOne(t);
  let best = null;
  for (let i = 0; i < t.length && i < MAX_BYTES_PER_FILE; i += CLIP - 300) {
    best = worse(best, classifyOne(t.slice(i, i + CLIP)));
    if (best && best.level === 'strong') break;
  }
  return best;
}
const worse = (a, b) => (!a ? b : !b ? a : (a.level === 'strong' || b.level !== 'strong') ? a : b);
const classifyText = classify;   // same windows, for raw text
function classifyAll(strings) { let best = null; for (const s of strings) { best = worse(best, classify(s)); if (best && best.level === 'strong') break; } return best; }

// "npm run build" is only as safe as scripts.build. Resolve up to three hops, bounded; flags and run-script are read.
function expand(cmd, scripts, depth = 0) {
  const out = [String(cmd)];
  if (depth >= 3) return out;
  const m = /^\s*(?:npm|pnpm|yarn)\s+(?:(?:run-script|run)\s+)?(?:(?:-s|-q|--silent|--quiet|--if-present)\s+)*([\w:.\-]{1,60})(?:\s+-{1,2}\S.{0,100})?\s*$/.exec(String(cmd).slice(0, 300));
  if (m && scripts && typeof scripts[m[1]] === 'string') out.push(...expand(scripts[m[1]], scripts, depth + 1));
  return out;
}

function lineOf(text, needle) {
  const i = text.indexOf(needle);
  if (i < 0) return 0;
  let n = 1; for (let k = 0; k < i; k++) if (text.charCodeAt(k) === 10) n++;
  return n;
}

// JSON as editors read it: comments and trailing commas allowed (VS Code, devcontainer). Linear. Returns null if it
// does not parse, and the caller falls back to raw-text rules (never a pass). Parsing also decodes \uXXXX escapes, so
// "runOn" cannot hide a key from us that the editor will read.
function parseJsonc(text) {
  try { return JSON.parse(text); } catch (_) { /* try the lenient form */ }
  let out = ''; let i = 0; const n = text.length; let inStr = false;
  while (i < n) {
    const c = text[i];
    if (inStr) { out += c; if (c === '\\' && i + 1 < n) { out += text[i + 1]; i += 2; continue; } if (c === '"') inStr = false; i++; continue; }
    if (c === '"') { inStr = true; out += c; i++; continue; }
    if (c === '/' && text[i + 1] === '/') { while (i < n && text[i] !== '\n') i++; continue; }
    if (c === '/' && text[i + 1] === '*') { i += 2; while (i < n && !(text[i] === '*' && text[i + 1] === '/')) i++; i += 2; continue; }
    out += c; i++;
  }
  try { return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1')); } catch (_) { return null; }
}
// Strings under a node, bounded in count, depth and size.
// Where a bound is hit the result carries truncated = true and the caller reports it: a walk that gave up is not a pass.
function collectStrings(node, limit = 400) {
  const out = []; const stack = [[node, 0]]; let seen = 0;
  out.truncated = false;
  while (stack.length) {
    if (out.length >= limit || seen++ >= 5000) { out.truncated = true; break; }
    const [v, d] = stack.pop();
    if (typeof v === 'string') out.push(v.slice(0, MAX_BYTES_PER_FILE));
    else if (Array.isArray(v) || (v && typeof v === 'object')) {
      if (d >= 20) { out.truncated = true; continue; }
      const kids = Array.isArray(v) ? v : Object.values(v);
      if (kids.length > 200) out.truncated = true;
      for (const x of kids.slice(0, 200)) stack.push([x, d + 1]);
    }
  }
  return out;
}
// Short digest of the text a finding rests on, so a pull request that CHANGES a command re-triggers the finding even when
// its description is the same words (the Action diffs findings by identity).
const digest = (strings) => crypto.createHash('sha256').update(strings.join('\n')).digest('hex').slice(0, 12);
// Every object in the tree that sets runOn to folderOpen (anywhere, not only under tasks), with the strings around it.
function findRunOnOpen(doc) {
  const out = []; const stack = [[doc, null, 0]]; let seen = 0;
  out.truncated = false;
  while (stack.length) {
    if (seen++ >= 5000) { out.truncated = true; break; }
    const [v, parent, d] = stack.pop();
    if (!v || typeof v !== 'object') continue;
    if (d > 20) { out.truncated = true; continue; }
    if (isObj(v) && ((isObj(v.runOptions) && v.runOptions.runOn === 'folderOpen') || v.runOn === 'folderOpen')) { const cs = collectStrings(isObj(v.runOptions) ? v : (parent || v), 50); if (cs.truncated) out.truncated = true; out.push(cs); }
    const kids = Array.isArray(v) ? v : Object.values(v);
    if (kids.length > 200) out.truncated = true;
    for (const x of kids.slice(0, 200)) stack.push([x, v, d + 1]);
  }
  return out;
}
// Raw text with JSON \\uXXXX escapes decoded, for the fallback rules on a file that would not parse.
const rawDecoded = (t) => String(t).replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);

function scanRepo(files, opts = {}) {
  const result = { analyzed: false, verdict: 'UNKNOWN', files_checked: 0, findings: [], coverage: ['RLS-001 npm install hooks and binding.gyp', 'RLS-002 VS Code run-on-open tasks', 'RLS-003 agent/editor hooks, helper commands and MCP servers', 'RLS-004 devcontainer lifecycle commands', 'RLS-005 package manager config and .pnpmfile', 'RLS-006 git/URL dependencies', 'RLS-007 decode-and-eval in source', 'RLS-008 setup.py network or eval'], note: 'No findings means none of these patterns were seen. It does not mean the repository is safe: read the code before you run it, on a machine that holds nothing.' };
  if (!files || typeof files !== 'object' || Array.isArray(files)) { result.error = 'files must be an object of path -> text'; return result; }
  const entries = Object.entries(files);
  if (entries.length > MAX_FILES) { result.error = `more than ${MAX_FILES} files, not analyzed`; return result; }
  let total = 0;
  const unread = [];
  let capped = false;
  let findingsTruncated = false;
  const skipped = Array.isArray(opts.skipped) ? opts.skipped.slice(0, 50).map((x) => clip(x, 100)) : [];
  // Every field that reaches a terminal, a log or a summary is stripped of control, C1, bidi and line-break characters
  // here, once, whatever the rule interpolated into it (a dependency name, a hook name, a path).
  const add = (f) => { if (result.findings.length >= MAX_FINDINGS && f.verdict !== 'BLOCK' && f.rule !== 'RLS-000') { findingsTruncated = true; return; } result.findings.push({ ...f, digest: f.digest ? String(f.digest).slice(0, 16) : undefined, file: clip(f.file, 300), message: clip(f.message, 600), evidence: clip(f.evidence, 160), fix: clip(f.fix, 300) }); };

  for (const [rawPath, rawText] of entries) {
    const path = norm(rawPath);
    const pathL = path.toLowerCase();
    const name = base(pathL);
    if (typeof rawText !== 'string') continue;
    if (/(^|\/)node_modules\//.test(pathL) || /(^|\/)\.git\//.test(pathL)) continue;
    if (rawText.length > MAX_BYTES_PER_FILE) { unread.push(path); continue; }
    total += rawText.length;
    if (total > MAX_TOTAL_BYTES) { result.error = 'input larger than 8 MB, not fully analyzed'; capped = true; break; }
    const text = rawText.replace(/^﻿/, '');
    result.files_checked++;

    // RLS-001 and RLS-006: package.json
    if (name === 'package.json') {
      let pkg = null;
      try { pkg = JSON.parse(text); } catch (e) { add({ rule: 'RLS-001', severity: 'medium', verdict: 'REVIEW', file: path, line: 0, evidence: '', message: 'package.json does not parse as JSON, so its install hooks could not be checked.', fix: 'Open it and read the scripts section.' }); }
      if (isObj(pkg)) {
        const scripts = isObj(pkg.scripts) ? pkg.scripts : {};
        for (const hook of NPM_HOOKS) {
          if (typeof scripts[hook] !== 'string') continue;
          const cmd = scripts[hook];
          const k = classifyAll(expand(cmd, scripts));
          const line = result.findings.length < 25 ? lineOf(text, `"${hook}"`) : 0;
          if (k && k.level === 'strong') add({ rule: 'RLS-001', severity: 'critical', verdict: 'BLOCK', file: path, line, evidence: cmd, message: `The ${hook} script runs automatically on npm install and ${k.why}.`, fix: 'Do not install. Read what it fetches or evaluates first, on a machine with no credentials, and install with --ignore-scripts.' });
          else if (k) add({ rule: 'RLS-001', severity: 'high', verdict: 'REVIEW', file: path, line, evidence: cmd, message: `The ${hook} script runs automatically on npm install and ${k.why}.`, fix: 'Read it before installing. Use npm install --ignore-scripts to inspect first.' });
          else if (SHELL_META.test(cmd) || !BENIGN_HOOK.test(cmd.trim())) add({ rule: 'RLS-001', severity: 'medium', verdict: 'REVIEW', file: path, line, evidence: cmd, message: `The ${hook} script runs automatically on npm install. It does not match a known-ordinary command.`, fix: 'Read the script it runs before installing.' });
        }
        // Dependencies fetched from git or a URL: every field npm or pnpm resolves, bounded.
        const groups = [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies, pkg.peerDependencies, pkg.overrides, pkg.resolutions, isObj(pkg.pnpm) ? pkg.pnpm.overrides : null];
        let budget = 3000; let gitDeps = 0; const sample = [];
        outer: for (const deps of groups) {
          if (!isObj(deps)) continue;
          for (const [dn, dv0] of Object.entries(deps)) {
            if (--budget < 0) { findingsTruncated = true; break outer; }
            const vals = typeof dv0 === 'string' ? [dv0] : isObj(dv0) ? Object.values(dv0).filter((x) => typeof x === 'string').slice(0, 20) : [];
            for (const dv of vals) {
              if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/|file:|link:)/i.test(dv) || /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(dv)) { gitDeps++; if (sample.length < 3) sample.push(`${dn}: ${dv}`); break; }
            }
          }
        }
        // One finding per file, not one per dependency: 600 git dependencies are one thing to read, and a flood of them
        // must never push a BLOCK out of the list.
        if (gitDeps) add({ rule: 'RLS-006', severity: 'medium', verdict: 'REVIEW', file: path, line: lineOf(text, JSON.stringify(sample[0].split(': ')[0])), evidence: sample.join('; '), digest: digest(sample), message: `${gitDeps} dependenc${gitDeps === 1 ? 'y is' : 'ies are'} fetched from a git or URL source, not the registry, and run their own install scripts (first: ${sample[0].split(': ')[0]}).`, fix: 'Open each source and read it, or replace it with a registry release.' });
      }
      continue;
    }
    // binding.gyp: npm runs node-gyp rebuild by itself when this file exists, and <!( runs a command while it does.
    if (name === 'binding.gyp') {
      if (/<!@?\(/.test(text)) { const k = classifyText(text); add({ rule: 'RLS-001', severity: k && k.level === 'strong' ? 'critical' : 'high', verdict: k && k.level === 'strong' ? 'BLOCK' : 'REVIEW', file: path, line: lineOf(text, '<!'), evidence: k ? k.why : 'command expansion', message: `binding.gyp runs a shell command during the native build that npm starts automatically on install${k ? ' and ' + k.why : ''}.`, fix: 'Read the command inside <!( ) before you install.' }); }
      continue;
    }

    // RLS-002: VS Code tasks (and tasks inside a .code-workspace file) that run when the folder opens
    if (/(^|\/)\.vscode\/tasks\.json$/.test(pathL) || /\.code-workspace$/.test(pathL)) {
      const doc = parseJsonc(text);
      let hits = null;   // strings of every run-on-open task, or null when there is none
      if (doc) {
        const found = findRunOnOpen(doc);
        if (found.length) hits = found.flat();
        if (found.truncated) add({ rule: 'RLS-002', severity: 'high', verdict: 'REVIEW', file: path, line: 1, evidence: 'file too large to check fully', message: `${path} is too large or deeply nested to check fully for tasks that run when the folder opens.`, fix: 'Read it by hand before you open this folder in VS Code.' });
        // The walk found nothing but the file says folderOpen somewhere (odd structure): never a pass.
        else if (!hits && /folderopen/i.test(rawDecoded(text))) hits = [text];
      } else {
        // Will not parse. Whatever VS Code makes of it, we cannot, so it is never clean.
        add({ rule: 'RLS-002', severity: 'high', verdict: 'REVIEW', file: path, line: 1, evidence: 'unparsed tasks file', message: `${path} could not be parsed, so it could not be checked for tasks that run when the folder opens.`, fix: 'Read it by hand before you open this folder in VS Code.' });
        if (/folderopen/i.test(rawDecoded(text))) hits = [text]; else continue;
      }
      if (hits) {
        const k = classifyAll(hits);
        add({ digest: digest(hits), rule: 'RLS-002', severity: k && k.level === 'strong' ? 'critical' : 'high', verdict: k && k.level === 'strong' ? 'BLOCK' : 'REVIEW', file: path, line: lineOf(text, 'folderOpen'), evidence: k ? k.why : 'task runs on folder open', message: `A VS Code task is set to run as soon as the folder is opened${k ? ' and ' + k.why : ''}. Opening the folder is enough; nothing needs to be run by hand.`, fix: 'Do not open this folder in VS Code. Read tasks.json first, or open it in a container or a viewer that does not run tasks.' });
      }
      continue;
    }

    // RLS-003: agent / editor hooks, helper commands and MCP servers
    if (/(^|\/)\.claude\/settings(?:\.local)?\.json$/.test(pathL) || /(^|\/)\.cursor\/(?:mcp|hooks)\.json$/.test(pathL) || /(^|\/)\.mcp\.json$/.test(pathL) || /(^|\/)\.vscode\/mcp\.json$/.test(pathL)) {
      const doc = parseJsonc(text);
      let hookStrings = [], serverStrings = [], autoApprove = false, trunc = false;
      const cs = (n, lim) => { const r = collectStrings(n, lim); if (r.truncated) trunc = true; return r; };
      if (isObj(doc)) {
        if (doc.hooks !== undefined) hookStrings.push(...cs(doc.hooks));
        // Commands the agent runs outside the hooks key: status line, credential and telemetry helpers.
        if (isObj(doc.statusLine)) hookStrings.push(...cs(doc.statusLine, 20));
        for (const k of ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper']) if (typeof doc[k] === 'string') hookStrings.push(doc[k].slice(0, MAX_BYTES_PER_FILE));
        for (const k of ['mcpServers', 'servers']) if (doc[k] !== undefined) serverStrings.push(...cs(doc[k]));
        autoApprove = doc.enableAllProjectMcpServers === true || doc.enabledMcpjsonServers !== undefined;
      } else {
        // Would not parse: raw-text rules on the escape-decoded text, and the file is REVIEW whatever they find.
        const dec = rawDecoded(text);
        add({ rule: 'RLS-003', severity: 'high', verdict: 'REVIEW', file: path, line: 1, evidence: 'unparsed config file', message: `${path} could not be parsed, so a hook or server command in it could not be told apart from text.`, fix: 'Read it by hand before you open the folder with an agent or editor.' });
        if (/"hooks"\s*:|"statusLine"\s*:|"apiKeyHelper"\s*:|"awsAuthRefresh"\s*:|"awsCredentialExport"\s*:|"otelHeadersHelper"\s*:/.test(dec)) hookStrings.push(dec);
        else if (/"(?:mcpServers|servers)"\s*:/.test(dec)) serverStrings.push(dec);
        autoApprove = /"enableAllProjectMcpServers"\s*:\s*true|"enabledMcpjsonServers"\s*:/.test(dec);
      }
      if (trunc) add({ rule: 'RLS-003', severity: 'high', verdict: 'REVIEW', file: path, line: 1, evidence: 'file too large to check fully', message: `${path} is too large or deeply nested to check fully for hooks and servers.`, fix: 'Read it by hand before you open the folder with an agent or editor.' });
      const hasHooks = hookStrings.length > 0, hasServers = serverStrings.length > 0;
      if (hasHooks || hasServers || autoApprove) {
        const k = classifyAll([...hookStrings, ...serverStrings]);
        const kind = hasHooks ? 'a hook that runs a command when the agent starts or acts' : 'an MCP server that is started as a command';
        add({ digest: digest([...hookStrings, ...serverStrings, String(autoApprove)]), rule: 'RLS-003', severity: k && k.level === 'strong' ? 'critical' : 'high', verdict: k && k.level === 'strong' ? 'BLOCK' : 'REVIEW', file: path, line: lineOf(text, hasHooks ? 'hooks' : 'mcpServers') || 1, evidence: k ? k.why : (hasHooks ? 'hooks present' : 'servers present'), message: `${path} defines ${kind}${k ? ' and ' + k.why : ''}${autoApprove ? '; it also pre-approves project servers' : ''}. An agent opened in this folder may run it with your permissions.`, fix: 'Read it before you open the folder with an agent or editor. Delete it, or open the repo with project hooks and servers disabled.' });
      }
      continue;
    }

    // RLS-004: devcontainer lifecycle commands (.devcontainer/devcontainer.json, .devcontainer/<name>/devcontainer.json, .devcontainer.json)
    if (/(^|\/)\.devcontainer\/(?:[^/]+\/)?devcontainer\.json$/.test(pathL) || /(^|\/)\.devcontainer\.json$/.test(pathL)) {
      const doc = parseJsonc(text);
      const KEYS = ['initializeCommand', 'onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand'];
      let present = [], strings = [], trunc = false;
      if (isObj(doc)) { for (const key of KEYS) if (doc[key] !== undefined) { present.push(key); const r = collectStrings(doc[key], 50); if (r.truncated) trunc = true; strings.push(...r); } }
      else {
        const dec = rawDecoded(text);
        add({ rule: 'RLS-004', severity: 'high', verdict: 'REVIEW', file: path, line: 1, evidence: 'unparsed config file', message: `${path} could not be parsed, so its lifecycle commands could not be checked.`, fix: 'Read it by hand before you open this folder in a dev container.' });
        for (const key of KEYS) if (new RegExp('"' + key + '"\\s*:').test(dec)) present.push(key);
        if (present.length) strings = null;
      }
      if (trunc) add({ rule: 'RLS-004', severity: 'high', verdict: 'REVIEW', file: path, line: 1, evidence: 'file too large to check fully', message: `${path} is too large or deeply nested to check its lifecycle commands fully.`, fix: 'Read it by hand before you open this folder in a dev container.' });
      if (present.length) {
        const k = strings === null ? classifyText(rawDecoded(text)) : classifyAll(strings);
        const host = present.includes('initializeCommand');
        add({ digest: digest(strings === null ? [text] : [...present, ...strings]), rule: 'RLS-004', severity: (k && k.level === 'strong') || host ? 'critical' : 'high', verdict: (k && k.level === 'strong') ? 'BLOCK' : 'REVIEW', file: path, line: lineOf(text, present[0]), evidence: k ? k.why : present[0], message: `${present[0]} runs when the dev container is created or opened${host ? ' (initializeCommand runs on your host machine, outside the container)' : ''}${k ? ' and ' + k.why : ''}.`, fix: 'Read the command before opening this folder in a dev container.' });
      }
      continue;
    }

    // RLS-005: package manager config. Character classes use [ \t], never \s, so a pattern cannot span newlines.
    if (name === '.yarnrc.yml' || name === '.yarnrc') {
      if (/^[ \t]*["']?yarnPath["']?[ \t]*:/m.test(text) || /^[ \t]*yarn-path[ \t]+/m.test(text)) add({ digest: digest([text]), rule: 'RLS-005', severity: 'critical', verdict: 'BLOCK', file: path, line: lineOf(text, 'arn'), evidence: 'yarnPath', message: 'yarnPath makes yarn run a JavaScript file from this repository as the package manager itself. It is a known way to run repo code on first install.', fix: 'Do not run yarn here. Read the file yarnPath points to.' });
      else if (/^[ \t]*plugins[ \t]*:/m.test(text) && /^[ \t]*-?[ \t]*["']?path["']?[ \t]*:/m.test(text)) add({ rule: 'RLS-005', severity: 'high', verdict: 'REVIEW', file: path, line: lineOf(text, 'plugins'), evidence: 'plugins with a path', message: 'This yarn config loads plugins from a path in the repository. A plugin is JavaScript that runs inside yarn.', fix: 'Read the plugin file before you run yarn.' });
      continue;
    }
    if (name === '.pnpmfile.cjs' || name === '.pnpmfile.mjs') {
      const k = classifyText(text);
      add({ digest: digest([text]), rule: 'RLS-005', severity: k && k.level === 'strong' ? 'critical' : 'high', verdict: k && k.level === 'strong' ? 'BLOCK' : 'REVIEW', file: path, line: 1, evidence: k ? k.why : name, message: `${name} is JavaScript that pnpm runs while it resolves dependencies${k ? ' and ' + k.why : ''}. It executes on install.`, fix: 'Read it before you run pnpm here.' });
      continue;
    }
    if (name === '.npmrc') {
      for (const m of text.matchAll(/^[ \t]*(?:@[\w.-]+:)?registry[ \t]*=[ \t]*(\S+)/gmi)) {
        if (!/^https?:\/\/registry\.npmjs\.org\/?$/i.test(m[1])) { add({ rule: 'RLS-005', severity: 'high', verdict: 'REVIEW', file: path, line: lineOf(text, m[0]), evidence: m[0], message: 'This repository points npm at a registry other than npmjs.org, so installs fetch packages from a server the repository chose.', fix: 'Confirm you recognize that registry, or remove the line.' }); break; }
      }
      const ex = /^[ \t]*(script-shell|node-options|onload-script|git|shell|node-gyp|init-module|editor|browser|viewer|python)[ \t]*=/im.exec(text);
      if (ex) add({ rule: 'RLS-005', severity: 'high', verdict: 'REVIEW', file: path, line: lineOf(text, ex[0]), evidence: ex[0], message: `.npmrc sets ${ex[1]}, which changes which program npm runs for scripts or git. A repository-supplied value can point at a file inside the repository.`, fix: 'Remove it, or read the program it names.' });
      continue;
    }

    // RLS-008: setup.py
    if (name === 'setup.py') {
      const k = classifyText(text);
      const runs = /\b(?:exec|eval)\s*\(|\bos\.system\s*\(|\bsubprocess\.\w+\s*\(|\burlopen\s*\(|\burlretrieve\s*\(/.test(text);
      const net = /\b(?:requests|urllib|socket|http\.client)\b|\b(?:curl|wget)\b|https?:\/\//.test(text);
      if (k && k.level === 'strong') add({ rule: 'RLS-008', severity: 'critical', verdict: 'BLOCK', file: path, line: 0, evidence: k.why, message: `setup.py executes at install and ${k.why}.`, fix: 'Do not pip install. Read it first, in a disposable environment.' });
      else if (runs && net) add({ rule: 'RLS-008', severity: 'high', verdict: 'REVIEW', file: path, line: 0, evidence: 'setup.py', message: 'setup.py both reaches the network and runs a command or evaluates code. It executes when the package is installed.', fix: 'Read it before pip install; install with --no-build-isolation only in a disposable environment.' });
      continue;
    }

    // RLS-007: decode and evaluate in a source file
    if (/\.(?:js|cjs|mjs|ts)$/.test(pathL)) {
      const s = text.slice(0, MAX_BYTES_PER_FILE);
      // Decode feeding an evaluator directly, not "this file contains both words" (polyfills and bundlers do).
      let evalDecoded = /\b(?:eval|Function|vm\.runIn\w+)\s*\(\s*[^)]{0,150}?(?:atob\s*\(|Buffer\.from\s*\(|fromCharCode)/.test(s);
      if (!evalDecoded) {
        // A long run of \xHH escapes followed by an evaluator. Runs are found with a bounded repeat and at most 200 are
        // examined, then only the 80 characters after each run are searched: linear, never a rescan of the file.
        let seen = 0;
        for (const mm of s.matchAll(/(?:\\x[0-9a-f]{2}){12,64}/gi)) {
          if (++seen > 200) break;
          if (/(?:eval|Function)\s*\(/.test(s.slice(mm.index + mm[0].length, mm.index + mm[0].length + 80))) { evalDecoded = true; break; }
        }
      }
      const exec = /\bchild_process\b/.test(s);
      const decode = /\batob\s*\(|Buffer\.from\([^)]{0,200}['"]base64['"]/.test(s);
      const net = /\bhttps?\.(?:get|request)\s*\(|\bfetch\s*\(|\baxios\b|\bXMLHttpRequest\b/.test(s);
      if (evalDecoded) add({ rule: 'RLS-007', severity: 'high', verdict: 'REVIEW', file: path, line: 0, evidence: 'eval of decoded data', message: 'This file passes decoded data straight to an evaluator. Loaders for hidden payloads look like this; so do a few legitimate tools.', fix: 'Read what it decodes before you run it.' });
      else if (exec && decode && net) add({ rule: 'RLS-007', severity: 'medium', verdict: 'REVIEW', file: path, line: 0, evidence: 'child_process with decoding and network', message: 'This file decodes data, uses the network and can start processes.', fix: 'Read it before you run it.' });
    }
  }

  if (findingsTruncated) add({ rule: 'RLS-000', severity: 'medium', verdict: 'REVIEW', file: '(findings)', line: 0, evidence: '', message: `More than ${MAX_FINDINGS} findings were produced and the lower-severity ones were not listed. Every BLOCK is kept.`, fix: 'Treat the repository as untrusted and read it by hand.' });
  if (unread.length) add({ rule: 'RLS-000', severity: 'low', verdict: 'REVIEW', file: unread[0], line: 0, evidence: clip(unread.slice(0, 3).join(', '), 160), message: `${unread.length} file${unread.length === 1 ? ' is' : 's are'} larger than 200 KB and ${unread.length === 1 ? 'was' : 'were'} not read (minified bundles hide payloads as easily as they hide whitespace).`, fix: 'Check that you recognize each one, or read it by hand.' });
  // Anything the caller could not or would not read (symlinks, depth or count limits) is never a clean result.
  if (skipped.length) add({ rule: 'RLS-000', severity: 'medium', verdict: 'REVIEW', file: skipped[0], line: 0, evidence: clip(skipped.slice(0, 3).join('; '), 160), message: `${skipped.length} path${skipped.length === 1 ? ' was' : 's were'} skipped and not checked (symlinks, depth or file-count limits). A lure can sit behind any of them.`, fix: 'Look at the skipped paths yourself before you open the repository.' });
  if (capped) add({ rule: 'RLS-000', severity: 'medium', verdict: 'REVIEW', file: '(input)', line: 0, evidence: '', message: 'The input was larger than 8 MB and was only partly read. The rest was not checked.', fix: 'Scan the directories that hold configuration separately, or read them by hand.' });
  result.analyzed = result.files_checked > 0 || unread.length > 0 || skipped.length > 0;
  if (!result.analyzed && !result.error) result.error = 'no readable files were provided';
  const order = { BLOCK: 0, REVIEW: 1 };
  result.findings.sort((a, b) => order[a.verdict] - order[b.verdict] || a.file.localeCompare(b.file));
  result.verdict = !result.analyzed ? 'UNKNOWN' : result.findings.some((f) => f.verdict === 'BLOCK') ? 'BLOCK' : result.findings.length ? 'REVIEW' : 'NO_FINDINGS';
  return result;
}


// Parser shape for the action: a Map of items, one per finding. Only the rules that are decidable from ONE file
// and low-noise in a pull request: install hooks, run-on-open tasks, agent hooks, devcontainer commands, package
// manager config. Source heuristics (RLS-007), git dependencies (the dependency parser already reports those),
// setup.py and size notes are left to the command line scanner.
const ACTION_RULES = new Set(['RLS-001', 'RLS-002', 'RLS-003', 'RLS-004', 'RLS-005']);   // RLS-008 and RLS-006/007 stay with the command line scanner
function fromRepoLures(file, text) {
  const m = new Map();
  const r = scanRepo({ [file]: String(text) });
  if (!r.analyzed) return m;
  const seen = new Map();
  for (const f of r.findings) {
    if (!ACTION_RULES.has(f.rule)) continue;
    // The MCP parser already sends every server through Dredd; a bare 'servers present' REVIEW would only duplicate it.
    if (f.rule === 'RLS-003' && f.verdict === 'REVIEW' && !/a hook that runs/.test(f.message)) continue;
    // The digest covers the command text, so a pull request that changes what a hook or task runs is a NEW finding.
    const baseKey = `finding:rls:${f.rule}:${f.file}:${f.evidence}:${f.digest || ''}`;
    const n = (seen.get(baseKey) || 0) + 1; seen.set(baseKey, n);
    m.set(`${baseKey}#${n}`, { kind: 'finding', ftype: 'repo lure', verdict: f.verdict, severity: f.severity, spec: `${f.rule} ${f.file}${f.line ? ':' + f.line : ''}`, where: f.line ? `line ${f.line}` : f.file, reason: `${f.message} Fix: ${f.fix}` });
  }
  return m;
}

module.exports = { fromRepoLures, scanRepo, MAX_FILES, MAX_BYTES_PER_FILE, MAX_TOTAL_BYTES };
