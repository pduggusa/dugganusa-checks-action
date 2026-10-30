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
 *   RLS-001  npm install hook (preinstall/install/postinstall/prepare...) that fetches or evaluates code
 *   RLS-002  VS Code task set to run when the folder opens
 *   RLS-003  agent or editor hook/server config that runs a command (.claude, .cursor, .mcp.json)
 *   RLS-004  devcontainer lifecycle command (initializeCommand runs on the HOST)
 *   RLS-005  package manager config that executes repo code or redirects installs (.yarnrc.yml, .npmrc)
 *   RLS-006  dependency fetched from a git or URL source (runs its install scripts)
 *   RLS-007  source file that decodes and evaluates a payload
 *   RLS-008  python setup.py that fetches or evaluates code at install
 */

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
];
// Weak: reaches the network. REVIEW.
const WEAK = [
  [/\b(?:curl|wget)\b/i, 'downloads with curl or wget'],
  [/\bhttps?:\/\/[^\s"'`]{1,200}/i, 'contains a URL'],
  [/\b(?:nc|ncat|netcat)\b\s+-?\w*\s*[\w.]+\s+\d{2,5}/i, 'opens a raw network connection'],
];
const NPM_HOOKS = ['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare'];
// Scripts that are ordinary and local. Not evidence of anything; they still get resolved one level.
const BENIGN_HOOK = /^(?:husky(?:\s+install)?|tsc(?:\s[\w .\-/=]*)?|node-gyp\s+rebuild|patch-package|prisma\s+generate|npx\s+(?:--no-install\s+)?(?:husky|patch-package)(?:\s+install)?|simple-git-hooks|lefthook\s+install|echo(?:\s+[\w .,:'"-]*)?)$/;
const SHELL_META = /[$`()<>|;&\n\r\\]/;

function classify(cmd) {
  const s = String(cmd).slice(0, CLIP);
  for (const [re, why] of STRONG) if (re.test(s)) return { level: 'strong', why };
  for (const [re, why] of WEAK) if (re.test(s)) return { level: 'weak', why };
  return null;
}

// "npm run build" is only as safe as scripts.build. Resolve up to three hops, bounded.
function expand(cmd, scripts, depth = 0) {
  const out = [String(cmd)];
  if (depth >= 3) return out;
  const m = /^\s*(?:npm|pnpm|yarn)\s+(?:run\s+)?([\w:.\-]{1,60})\s*$/.exec(String(cmd).slice(0, 200));
  if (m && scripts && typeof scripts[m[1]] === 'string') out.push(...expand(scripts[m[1]], scripts, depth + 1));
  return out;
}

function lineOf(text, needle) {
  const i = text.indexOf(needle);
  if (i < 0) return 0;
  let n = 1; for (let k = 0; k < i; k++) if (text.charCodeAt(k) === 10) n++;
  return n;
}

function scanRepo(files, opts = {}) {
  const result = { analyzed: false, verdict: 'UNKNOWN', files_checked: 0, findings: [], coverage: ['RLS-001 npm install hooks', 'RLS-002 VS Code run-on-open tasks', 'RLS-003 agent/editor hooks and MCP servers', 'RLS-004 devcontainer lifecycle commands', 'RLS-005 package manager config', 'RLS-006 git/URL dependencies', 'RLS-007 decode-and-eval in source', 'RLS-008 setup.py network or eval'], note: 'No findings means none of these patterns were seen. It does not mean the repository is safe: read the code before you run it, on a machine that holds nothing.' };
  if (!files || typeof files !== 'object' || Array.isArray(files)) { result.error = 'files must be an object of path -> text'; return result; }
  const entries = Object.entries(files);
  if (entries.length > MAX_FILES) { result.error = `more than ${MAX_FILES} files, not analyzed`; return result; }
  let total = 0;
  const unread = [];
  let capped = false;
  const skipped = Array.isArray(opts.skipped) ? opts.skipped.slice(0, 50).map((x) => clip(x, 100)) : [];
  const add = (f) => { if (result.findings.length < MAX_FINDINGS) result.findings.push({ ...f, file: clip(f.file, 300) }); };

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
      if (pkg && typeof pkg === 'object') {
        const scripts = pkg.scripts && typeof pkg.scripts === 'object' ? pkg.scripts : {};
        for (const hook of NPM_HOOKS) {
          if (typeof scripts[hook] !== 'string') continue;
          const cmd = scripts[hook];
          const chain = expand(cmd, scripts);
          let worst = null, why = '';
          for (const c of chain) { const k = classify(c); if (k && (!worst || k.level === 'strong')) { worst = k.level; why = k.why; } }
          const line = lineOf(text, `"${hook}"`);
          if (worst === 'strong') add({ rule: 'RLS-001', severity: 'critical', verdict: 'BLOCK', file: path, line, evidence: clip(cmd), message: `The ${hook} script runs automatically on npm install and ${why}.`, fix: 'Do not install. Read what it fetches or evaluates first, on a machine with no credentials, and install with --ignore-scripts.' });
          else if (worst === 'weak') add({ rule: 'RLS-001', severity: 'high', verdict: 'REVIEW', file: path, line, evidence: clip(cmd), message: `The ${hook} script runs automatically on npm install and ${why}.`, fix: 'Read it before installing. Use npm install --ignore-scripts to inspect first.' });
          else if (SHELL_META.test(cmd) || !BENIGN_HOOK.test(cmd.trim())) add({ rule: 'RLS-001', severity: 'medium', verdict: 'REVIEW', file: path, line, evidence: clip(cmd), message: `The ${hook} script runs automatically on npm install. It does not match a known-ordinary command.`, fix: 'Read the script it runs before installing.' });
        }
        for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
          const deps = pkg[field] && typeof pkg[field] === 'object' ? pkg[field] : {};
          for (const [dn, dv] of Object.entries(deps).slice(0, 2000)) {
            if (typeof dv !== 'string') continue;
            if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/|file:|link:)/i.test(dv) || /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(dv)) add({ rule: 'RLS-006', severity: 'medium', verdict: 'REVIEW', file: path, line: lineOf(text, `"${dn}"`), evidence: clip(`${dn}: ${dv}`), message: `${dn} is fetched from a git or URL source, not the registry, and runs its own install scripts.`, fix: 'Open that source and read it, or replace it with a registry release.' });
          }
        }
      }
      continue;
    }

    // RLS-002: VS Code tasks that run when the folder opens
    if (/(^|\/)\.vscode\/tasks\.json$/.test(pathL)) {
      if (/"runOn"\s*:\s*"folderOpen"/.test(text)) {
        const k = classify(text);
        add({ rule: 'RLS-002', severity: k && k.level === 'strong' ? 'critical' : 'high', verdict: k && k.level === 'strong' ? 'BLOCK' : 'REVIEW', file: path, line: lineOf(text, 'folderOpen'), evidence: k ? k.why : 'task runs on folder open', message: `A VS Code task is set to run as soon as the folder is opened${k ? ' and ' + k.why : ''}. Opening the folder is enough; nothing needs to be run by hand.`, fix: 'Do not open this folder in VS Code. Read tasks.json first, or open it in a container or a viewer that does not run tasks.' });
      }
      continue;
    }

    // RLS-003: agent / editor hooks and MCP servers
    if (/(^|\/)\.claude\/settings(?:\.local)?\.json$/.test(pathL) || /(^|\/)\.cursor\/(?:mcp|hooks)\.json$/.test(pathL) || /(^|\/)\.mcp\.json$/.test(pathL) || /(^|\/)\.vscode\/mcp\.json$/.test(pathL)) {
      const hasHooks = /"hooks"\s*:/.test(text);
      const hasServers = /"(?:mcpServers|servers)"\s*:/.test(text);
      const autoApprove = /"enableAllProjectMcpServers"\s*:\s*true|"enabledMcpjsonServers"\s*:/.test(text);
      if (hasHooks || hasServers || autoApprove) {
        const k = classify(text);
        const kind = hasHooks ? 'a hook that runs a command when the agent starts or acts' : 'an MCP server that is started as a command';
        add({ rule: 'RLS-003', severity: k && k.level === 'strong' ? 'critical' : 'high', verdict: k && k.level === 'strong' ? 'BLOCK' : 'REVIEW', file: path, line: lineOf(text, hasHooks ? '"hooks"' : '"mcpServers"') || 1, evidence: k ? k.why : (hasHooks ? 'hooks present' : 'servers present'), message: `${path} defines ${kind}${k ? ' and ' + k.why : ''}${autoApprove ? '; it also pre-approves project servers' : ''}. An agent opened in this folder may run it with your permissions.`, fix: 'Read it before you open the folder with an agent or editor. Delete it, or open the repo with project hooks and servers disabled.' });
      }
      continue;
    }

    // RLS-004: devcontainer lifecycle commands
    if (/(^|\/)\.devcontainer\/devcontainer\.json$/.test(pathL) || /(^|\/)\.devcontainer\.json$/.test(pathL)) {
      const m = /"(initializeCommand|onCreateCommand|updateContentCommand|postCreateCommand|postStartCommand|postAttachCommand)"\s*:/.exec(text);
      if (m) {
        const k = classify(text);
        const host = /"initializeCommand"\s*:/.test(text);
        add({ rule: 'RLS-004', severity: (k && k.level === 'strong') || host ? 'critical' : 'high', verdict: (k && k.level === 'strong') ? 'BLOCK' : 'REVIEW', file: path, line: lineOf(text, m[1]), evidence: k ? k.why : m[1], message: `${m[1]} runs when the dev container is created or opened${host ? ' (initializeCommand runs on your host machine, outside the container)' : ''}${k ? ' and ' + k.why : ''}.`, fix: 'Read the command before opening this folder in a dev container.' });
      }
      continue;
    }

    // RLS-005: package manager config
    if (name === '.yarnrc.yml' || name === '.yarnrc') {
      if (/^\s*yarnPath\s*:/m.test(text)) add({ rule: 'RLS-005', severity: 'critical', verdict: 'BLOCK', file: path, line: lineOf(text, 'yarnPath'), evidence: 'yarnPath', message: 'yarnPath makes yarn run a JavaScript file from this repository as the package manager itself. It is a known way to run repo code on first install.', fix: 'Do not run yarn here. Read the file yarnPath points to.' });
      continue;
    }
    if (name === '.npmrc') {
      for (const m of text.matchAll(/^[ \t]*(?:@[\w.-]+:)?registry[ \t]*=[ \t]*(\S+)/gmi)) {
        if (!/^https?:\/\/registry\.npmjs\.org\/?$/i.test(m[1])) { add({ rule: 'RLS-005', severity: 'high', verdict: 'REVIEW', file: path, line: lineOf(text, m[0]), evidence: clip(m[0]), message: 'This repository points npm at a registry other than npmjs.org, so installs fetch packages from a server the repository chose.', fix: 'Confirm you recognize that registry, or remove the line.' }); break; }
      }
      const ex = /^[ \t]*(script-shell|node-options|onload-script|git|shell|node-gyp|init-module|editor|browser|viewer|python)[ \t]*=/im.exec(text);
      if (ex) add({ rule: 'RLS-005', severity: 'high', verdict: 'REVIEW', file: path, line: lineOf(text, ex[0]), evidence: clip(ex[0]), message: `.npmrc sets ${ex[1]}, which changes which program npm runs for scripts or git. A repository-supplied value can point at a file inside the repository.`, fix: 'Remove it, or read the program it names.' });
      continue;
    }

    // RLS-008: setup.py
    if (name === 'setup.py') {
      const strong = /\b(?:exec|eval)\s*\(|\bos\.system\s*\(|\bsubprocess\.\w+\s*\(|\burlopen\s*\(|\burlretrieve\s*\(/.test(text.slice(0, MAX_BYTES_PER_FILE));
      const net = /\b(?:requests|urllib)\b/.test(text);
      if (strong && net) add({ rule: 'RLS-008', severity: 'high', verdict: 'REVIEW', file: path, line: 0, evidence: 'setup.py', message: 'setup.py both reaches the network and runs a command or evaluates code. It executes when the package is installed.', fix: 'Read it before pip install; install with --no-build-isolation only in a disposable environment.' });
      continue;
    }

    // RLS-007: decode and evaluate in a source file
    if (/\.(?:js|cjs|mjs|ts)$/.test(pathL)) {
      const s = text.slice(0, MAX_BYTES_PER_FILE);
      // Decode feeding an evaluator directly, not "this file contains both words" (polyfills and bundlers do).
      const evalDecoded = /\b(?:eval|Function|vm\.runIn\w+)\s*\(\s*[^)]{0,150}?(?:atob\s*\(|Buffer\.from\s*\(|fromCharCode)/.test(s) || /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){11,}[^;]{0,60}(?:eval|Function)\s*\(/i.test(s);
      const exec = /\bchild_process\b/.test(s);
      const decode = /\batob\s*\(|Buffer\.from\([^)]{0,200}['"]base64['"]/.test(s);
      const net = /\bhttps?\.(?:get|request)\s*\(|\bfetch\s*\(|\baxios\b|\bXMLHttpRequest\b/.test(s);
      if (evalDecoded) add({ rule: 'RLS-007', severity: 'high', verdict: 'REVIEW', file: path, line: 0, evidence: 'eval of decoded data', message: 'This file passes decoded data straight to an evaluator. Loaders for hidden payloads look like this; so do a few legitimate tools.', fix: 'Read what it decodes before you run it.' });
      else if (exec && decode && net) add({ rule: 'RLS-007', severity: 'medium', verdict: 'REVIEW', file: path, line: 0, evidence: 'child_process with decoding and network', message: 'This file decodes data, uses the network and can start processes.', fix: 'Read it before you run it.' });
    }
  }

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
const ACTION_RULES = new Set(['RLS-001', 'RLS-002', 'RLS-003', 'RLS-004', 'RLS-005']);
function fromRepoLures(file, text) {
  const m = new Map();
  const r = scanRepo({ [file]: String(text) });
  if (!r.analyzed) return m;
  const seen = new Map();
  for (const f of r.findings) {
    if (!ACTION_RULES.has(f.rule)) continue;
    // The MCP parser already sends every server through Dredd; a bare 'servers present' REVIEW would only duplicate it.
    if (f.rule === 'RLS-003' && f.verdict === 'REVIEW' && !/a hook that runs/.test(f.message)) continue;
    const baseKey = `finding:rls:${f.rule}:${f.file}:${f.evidence}`;
    const n = (seen.get(baseKey) || 0) + 1; seen.set(baseKey, n);
    m.set(`${baseKey}#${n}`, { kind: 'finding', ftype: 'repo lure', verdict: f.verdict, severity: f.severity, spec: `${f.rule} ${f.file}${f.line ? ':' + f.line : ''}`, where: f.line ? `line ${f.line}` : f.file, reason: `${f.message} Fix: ${f.fix}` });
  }
  return m;
}

module.exports = { fromRepoLures, scanRepo, MAX_FILES, MAX_BYTES_PER_FILE, MAX_TOTAL_BYTES };
