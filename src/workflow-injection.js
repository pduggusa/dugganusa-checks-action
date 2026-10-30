'use strict';
// PORTED from DugganUSA microservices/analytics-dashboard/lib/workflow-injection.js (the canonical copy,
// also served by the Jeevesus MCP tool check-workflow). Keep the analyzer below byte-identical to it; only
// fromWorkflowInjection at the bottom is specific to this action.
/**
 * workflow-injection.js — static check for script injection in GitHub Actions workflows.
 *
 * WHY (2026-10-30): Radware (Babo, Nakibly, 2026-10-29) documented 83 malicious issues, pull requests
 * and comments across 61 public repositories on 2026-09-01. Each hid a shell command in text a
 * workflow later pasted into a script; in PX4-Autopilot and Snouzy/workout-cool the build logs prove
 * the shell executed it. GitHub replaces `${{ ... }}` with its value BEFORE the shell sees the script,
 * so a title containing command substitution becomes code, even inside double quotes.
 *
 * WHAT IT DOES: reads one workflow file as text and reports where attacker-controllable event text
 * reaches a shell script, a github-script body, or a privileged checkout. Pure, synchronous,
 * dependency-free and deliberately NOT a YAML parser: it reads indentation, so a hostile document
 * (anchors, deep nesting, huge scalars) cannot blow it up. Bounded: 200 KB, 5,000 lines.
 *
 * WHAT IT CANNOT DO: prove a workflow safe. No findings means none of THESE patterns were seen; it
 * says nothing about reusable workflows, composite actions in other repos, or logic it cannot read.
 * Callers must never present an empty result as "safe".
 *
 * Findings never echo workflow text beyond the expression name, and every string is length-clipped.
 * Verdicts use the DugganUSA vocabulary: BLOCK, REVIEW, ADVISORY.
 */

const MAX_BYTES = 200 * 1024;
const MAX_LINES = 5000;

// Event fields an outside user controls. Source: GitHub's own "script injection" guidance plus the
// Radware cases. Matched against the expression text between `${{` and `}}`.
const UNTRUSTED = [
  /\bgithub\.event\.(issue|pull_request|discussion)\.(title|body)\b/,
  /\bgithub\.event\.(comment|review|review_comment)\.body\b/,
  /\bgithub\.event\.pull_request\.head\.(ref|label)\b/,
  /\bgithub\.event\.pull_request\.head\.repo\.default_branch\b/,
  /\bgithub\.head_ref\b/,
  /\bgithub\.event\.(head_commit|commits(\[[^\]]*\]|\.\*))\.(message|author\.(name|email))\b/,
  /\bgithub\.event\.workflow_run\.(head_branch|display_title|head_commit\.(message|author\.(name|email)))\b/,
  /\bgithub\.event\.pages(\[[^\]]*\]|\.\*)\.page_name\b/,
  /\bgithub\.event\.(issue|pull_request|discussion)\.labels\b/,
  /\btojson\(\s*github(\.event(\.[a-z_]+)*)?\s*\)/,                      // serializes everything below it
  /\bgithub\.event(\.[a-z_]+)*\.\*/,                                       // object filter over event fields
  /\bgithub\.event\.(issue|pull_request|discussion|comment|review|review_comment|head_commit|workflow_run)(?![\w.[])/,   // the bare object stringifies to JSON including title and body
];
// GitHub expressions are case-insensitive and accept github.event['issue']["title"] for github.event.issue.title,
// so normalize both before matching (review of 2026-10-30: either spelling slipped past the patterns).
const normalizeExpr = (expr) => String(expr).toLowerCase().replace(/\[\s*(['"])([a-z0-9_*-]{1,40})\1\s*\]/g, '.$2').replace(/\s*([.\[\]])\s*/g, '$1').replace(/\s+/g, ' ');
const isUntrusted = (expr) => { const n = normalizeExpr(expr); return UNTRUSTED.some((re) => re.test(n)); };

// Triggers whose events any GitHub user can cause, and that run with the repository's secrets or a
// write token. (pull_request from a fork has neither, which lowers the blast radius, not the bug.)
const PRIVILEGED_TRIGGERS = new Set(['issues', 'issue_comment', 'pull_request_target', 'discussion', 'discussion_comment',
  'pull_request_review', 'pull_request_review_comment', 'workflow_run', 'fork', 'watch']);
const EXTERNAL_TRIGGERS = new Set([...PRIVILEGED_TRIGGERS, 'pull_request']);
const LINE_CAP = 2000;        // characters of one script line examined for WFI-003
const MAX_ENV_CHECKED = 50;   // untrusted env variables examined per step
const SINK = /\b(?:eval|source)\b|\b(?:sh|bash)\s+-c\b/;   // no global flag: exec() finds the FIRST sink
const VAR_REF = /\$\{?([A-Za-z_][A-Za-z0-9_]*)/g;               // linear scan for $NAME and ${NAME}
const AGENT_ACTION = /(claude|copilot|gemini|openai|codex|llm|ai-review|ai-agent|chatgpt|anthropic)/i;

const clip = (s, n = 120) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);
const indentOf = (raw) => { let i = 0; while (i < raw.length && raw[i] === ' ') i++; return i; };
const isBlank = (raw) => raw.trim() === '' || raw.trim().startsWith('#');

// Lines belonging to a block under a key at `keyIndent`: strictly deeper than the key, blanks included.
function blockEnd(recs, from, keyIndent) {
  let j = from;
  while (j < recs.length && (isBlank(recs[j].raw) || recs[j].indent > keyIndent)) j++;
  return j;
}

function parseTriggers(recs) {
  const names = new Set();
  for (let i = 0; i < recs.length; i++) {
    const r = recs[i];
    const m = r.indent === 0 && /^(?:on|"on"|'on')\s*:\s*(.*)$/.exec(r.raw);
    if (!m) continue;
    const inline = m[1].replace(/\s+#.*$/, '').trim();
    if (inline.startsWith('[')) inline.replace(/[\[\]]/g, '').split(',').map((s) => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean).forEach((n) => names.add(n));
    else if (inline) names.add(inline.replace(/^["']|["']$/g, ''));
    else {
      const end = blockEnd(recs, i + 1, 0);
      let childIndent = null;
      for (let j = i + 1; j < end; j++) {
        if (isBlank(recs[j].raw)) continue;
        if (childIndent === null) childIndent = recs[j].indent;
        if (recs[j].indent !== childIndent) continue;
        const km = /^(?:-\s+)?["']?([A-Za-z_][\w-]*)["']?\s*:?/.exec(recs[j].raw.trim());
        if (km) names.add(km[1]);
      }
    }
    break;
  }
  return names;
}

function topLevelPermissions(recs) {
  for (let i = 0; i < recs.length; i++) {
    const m = recs[i].indent === 0 && /^permissions\s*:\s*(.*)$/.exec(recs[i].raw);
    if (!m) continue;
    const inline = m[1].replace(/\s+#.*$/, '').trim();
    if (inline) return { declared: true, writeAll: /^write-all$/.test(inline), writes: /write/.test(inline) };
    const end = blockEnd(recs, i + 1, 0);
    const body = recs.slice(i + 1, end).map((r) => r.raw).join('\n');
    return { declared: true, writeAll: false, writes: /:\s*write\b/.test(body) };
  }
  return { declared: false, writeAll: false, writes: false };
}

// A key/value or block scalar inside a step span. Returns {lines:[{n,text}], inline}.
function readValue(recs, i, keyIndent, spanEnd) {
  const after = recs[i].raw.slice(recs[i].raw.indexOf(':') + 1).replace(/\s+#.*$/, '').trim();
  if (/^(?:(?:![^\s]*|&[^\s]+)\s+)*[|>](?:\d[+-]?|[+-]\d?)?$/.test(after)) {
    const end = Math.min(blockEnd(recs, i + 1, keyIndent), spanEnd);
    return { block: true, lines: recs.slice(i + 1, end).filter((r) => !r.raw.trim().startsWith('#') || true).map((r) => ({ n: r.n, text: r.raw })), next: end };
  }
  if (after === '') {
    const end = Math.min(blockEnd(recs, i + 1, keyIndent), spanEnd);
    return { block: true, map: true, lines: recs.slice(i + 1, end).map((r) => ({ n: r.n, text: r.raw })), next: end };
  }
  return { block: false, lines: [{ n: recs[i].n, text: after }], next: i + 1 };
}

function parseSteps(recs) {
  const steps = [];
  for (let i = 0; i < recs.length; i++) {
    if (!/^\s*["']?steps["']?\s*:\s*(#.*)?$/.test(recs[i].raw)) continue;
    const stepsIndent = recs[i].indent;
    // The list may be indented under the key or aligned with it (both are valid YAML).
    let end = i + 1;
    while (end < recs.length && (isBlank(recs[end].raw) || recs[end].indent > stepsIndent || (recs[end].indent === stepsIndent && /^\s*-(\s|$)/.test(recs[end].raw)))) end++;
    let itemIndent = null;
    const starts = [];
    for (let j = i + 1; j < end; j++) {
      if (isBlank(recs[j].raw)) continue;
      if (itemIndent === null) itemIndent = recs[j].indent;
      if (recs[j].indent === itemIndent && /^\s*-(\s|$)/.test(recs[j].raw)) starts.push(j);
    }
    // a step at indent == stepsIndent (a "- " list aligned with the key) is also valid YAML
    if (!starts.length) continue;
    for (let s = 0; s < starts.length; s++) {
      const a = starts[s], b = s + 1 < starts.length ? starts[s + 1] : end;
      const span = recs.slice(a, b).map((r, k) => (k === 0 ? { ...r, raw: r.raw.replace(/^(\s*)-(\s)/, '$1 $2'), indent: r.indent + 2 } : r));
      const keyIndent = span[0].indent;
      const step = { index: s + 1, line: recs[a].n, name: '', uses: '', run: [], script: [], env: [], withRef: [] };
      for (let k = 0; k < span.length; k++) {
        const r = span[k];
        if (isBlank(r.raw) || r.indent !== keyIndent) continue;
        const km = /^\s*["']?([A-Za-z_][\w-]*)["']?\s*:/.exec(r.raw);
        if (!km) continue;
        const key = km[1];
        if (key === 'name') step.name = clip(r.raw.slice(r.raw.indexOf(':') + 1).replace(/^["']|["']$/g, ''), 60);
        else if (key === 'uses') step.uses = clip(r.raw.slice(r.raw.indexOf(':') + 1).replace(/\s+#.*$/, '').replace(/^["']|["']$/g, ''), 100);
        else if (key === 'run') { const v = readValue(span, k, keyIndent, span.length); step.run = v.lines; k = v.next - 1; }
        else if (key === 'env' || key === 'with') {
          const v = readValue(span, k, keyIndent, span.length);
          let childIndent = null;
          for (let q = 0; q < v.lines.length; q++) {
            const ln = v.lines[q];
            if (!ln.text.trim() || ln.text.trim().startsWith('#')) continue;
            const ind = indentOf(ln.text);
            if (childIndent === null) childIndent = ind;
            if (ind !== childIndent) continue;
            const cm = /^\s*([A-Za-z_][\w-]*)\s*:(.*)$/.exec(ln.text);
            if (!cm) continue;
            if (key === 'env') step.env.push({ name: cm[1], value: cm[2].trim(), n: ln.n });
            else if (cm[1] === 'script') {
              // github-script body: inline or block scalar
              const rest = cm[2].replace(/\s+#.*$/, '').trim();
              if (/^(?:(?:![^\s]*|&[^\s]+)\s+)*[|>](?:\d[+-]?|[+-]\d?)?$/.test(rest)) {
                let z = q + 1; while (z < v.lines.length && (!v.lines[z].text.trim() || indentOf(v.lines[z].text) > childIndent)) z++;
                step.script = v.lines.slice(q + 1, z); q = z - 1;
              } else step.script = [{ n: ln.n, text: rest }];
            } else if (cm[1] === 'ref' || cm[1] === 'repository') step.withRef.push({ key: cm[1], value: cm[2].trim(), n: ln.n });
          }
          k = v.next - 1;
        }
      }
      steps.push(step);
    }
  }
  return steps;
}

function exprs(text) {
  const out = []; const re = /\$\{\{\s*([^}]{0,300}?)\s*\}\}/g; let m;
  while ((m = re.exec(text)) !== null) out.push(m[1]);
  return out;
}

function analyzeWorkflow(text) {
  const result = { analyzed: false, triggers: [], findings: [], coverage: ['WFI-001 event text in run or script', 'WFI-002 privileged trigger checks out the pull request head', 'WFI-003 event text reaches eval or sh -c through env', 'WFI-004 external trigger with open token permissions', 'WFI-005 AI agent action on an external trigger', 'WFI-006 event text in a workflow whose steps could not be parsed'], note: 'No findings means none of these patterns were seen. It does not mean the workflow is safe.' };
  if (typeof text !== 'string') { result.error = 'workflow must be text'; return result; }
  if (Buffer.byteLength(text, 'utf8') > MAX_BYTES) { result.error = 'workflow is larger than 200 KB, not analyzed'; return result; }
  const lines = text.replace(/^﻿/, '').split(/\r\n|\r|\n/);
  if (lines.length > MAX_LINES) { result.error = 'workflow has more than 5,000 lines, not analyzed'; return result; }
  const recs = lines.map((raw, i) => ({ n: i + 1, raw: raw.replace(/\t/g, '  '), indent: indentOf(raw.replace(/\t/g, '  ')) }));
  // Drop full-line comments from analysis (they are not workflow text).
  const live = recs.map((r) => (r.raw.trim().startsWith('#') ? { ...r, raw: '' } : r));
  const triggers = parseTriggers(live);
  // Not every text is a workflow. Prose, an empty file or a JSON blob must be "not analyzed", never a
  // quiet "no findings". Composite actions (runs: ... steps:) are in scope; they have no on: or jobs:.
  const looksLikeWorkflow = triggers.size > 0 || live.some((r) => r.indent === 0 && /^(jobs|runs)\s*:/.test(r.raw));
  if (!looksLikeWorkflow) { result.error = 'The text does not look like a GitHub Actions workflow or composite action (no on:, jobs: or runs: key)'; return result; }
  result.analyzed = true;

  result.triggers = [...triggers];
  const priv = [...triggers].filter((t) => PRIVILEGED_TRIGGERS.has(t));
  const external = [...triggers].filter((t) => EXTERNAL_TRIGGERS.has(t));
  let perms = topLevelPermissions(live);
  if (!perms.declared) {
    // No top-level block: it is still declared if EVERY job declares its own.
    const jobsAt = live.findIndex((r) => r.indent === 0 && /^jobs\s*:\s*$/.test(r.raw));
    if (jobsAt >= 0) {
      let jobIndent = null; const jobStarts = [];
      for (let j = jobsAt + 1; j < live.length; j++) {
        if (isBlank(live[j].raw)) continue;
        if (live[j].indent === 0) break;
        if (jobIndent === null) jobIndent = live[j].indent;
        if (live[j].indent === jobIndent && /^\s*[A-Za-z_][\w-]*\s*:/.test(live[j].raw)) jobStarts.push(j);
      }
      let withPerms = 0;
      jobStarts.forEach((a2, k) => {
        const b2 = k + 1 < jobStarts.length ? jobStarts[k + 1] : live.length;
        if (live.slice(a2 + 1, b2).some((r) => r.indent === jobIndent + 2 && /^\s*permissions\s*:/.test(r.raw))) withPerms++;
      });
      if (jobStarts.length && withPerms === jobStarts.length) perms = { declared: true, writeAll: false, writes: true };
    }
  }
  const steps = parseSteps(live);

  const add = (f) => { if (result.findings.length < 100) result.findings.push({ ...f, line: f.line, trigger: external.slice(0, 5) }); };

  for (const st of steps) {
    const where = { step: st.index, stepName: st.name };
    // WFI-001: untrusted expression inside a shell script or a github-script body
    const scriptSources = [['run', st.run], ['github-script', /github-script/.test(st.uses) ? st.script : []]];
    for (const [kind, ls] of scriptSources) {
      for (const ln of ls) {
        for (const e of exprs(ln.text)) {
          if (!isUntrusted(e)) continue;
          add({ rule: 'WFI-001', severity: priv.length ? 'critical' : 'high', verdict: 'BLOCK', line: ln.n, ...where,
            expression: clip(e, 80),
            message: `Event text (${clip(e, 80)}) is pasted into ${kind === 'run' ? 'a shell script' : 'a github-script body'}. GitHub substitutes it before ${kind === 'run' ? 'the shell' : 'the script'} runs, so a title or body containing command syntax becomes code, even inside quotes.${priv.length ? ' This workflow is triggered by an event anyone can cause.' : ''}`,
            fix: 'Pass the value through an environment variable (env: NAME: ${{ ... }}) and read it as "$NAME" in the script. Never build it into the script text, and never pass it to eval.' });
        }
      }
    }
    // WFI-003: untrusted env value used with eval or an inline shell. ONE linear pass per line (review of
    // 2026-10-30: a regex built per variable with [^\n]* between sink and variable was quadratic on a long
    // line of repeated sinks, on an unauthenticated endpoint). Lines are capped at LINE_CAP characters and
    // the variables checked per step at MAX_ENV_CHECKED.
    const untrustedEnv = st.env.filter((e) => exprs(e.value).some(isUntrusted)).slice(0, MAX_ENV_CHECKED);
    if (untrustedEnv.length) {
      const names = new Map(untrustedEnv.map((e) => [e.name, e]));
      const flagged = new Set();
      for (const ln of st.run) {
        const line = ln.text.slice(0, LINE_CAP);
        const sink = SINK.exec(line);              // first eval / source / sh -c / bash -c on the line
        if (!sink) continue;
        VAR_REF.lastIndex = sink.index;
        let m;
        while ((m = VAR_REF.exec(line)) !== null) {
          const ev = names.get(m[1]);
          if (ev && !flagged.has(ev.name)) {
            flagged.add(ev.name);
            add({ rule: 'WFI-003', severity: 'high', verdict: 'REVIEW', line: ev.n, ...where, expression: ev.name,
              message: `${ev.name} carries event text and is then evaluated by the shell (eval, sh -c or source). Passing it through the environment is the right start, but evaluating it again reintroduces the injection.`,
              fix: 'Treat the variable as data: print it, compare it, or pass it as a quoted argument. Do not evaluate it.' });
          }
        }
      }
    }
    // WFI-002: pull_request_target / workflow_run checking out the pull request head
    if ((triggers.has('pull_request_target') || triggers.has('workflow_run')) && /actions\/checkout/.test(st.uses)) {
      for (const w of st.withRef) {
        if (exprs(w.value).some((e) => /\bgithub\.event\.(pull_request|workflow_run)\.head\b|\bgithub\.head_ref\b|\bgithub\.event\.pull_request\.head\.sha\b/.test(e))) {
          add({ rule: 'WFI-002', severity: 'critical', verdict: 'BLOCK', line: w.n, ...where, expression: clip(w.value, 80),
            message: 'A workflow that runs with repository secrets checks out code from the pull request head. Anything that then builds or runs that code is executing the contributor\'s code with your secrets.',
            fix: 'Split it: run untrusted code in a pull_request workflow with no secrets and a read-only token, and have a separate privileged workflow consume only its inert output.' });
        }
      }
    }
    // WFI-005: an AI agent action on an externally triggerable workflow
    if (priv.length && st.uses && AGENT_ACTION.test(st.uses) && !/^actions\//.test(st.uses)) {
      add({ rule: 'WFI-005', severity: 'medium', verdict: 'ADVISORY', line: st.line, ...where, expression: clip(st.uses, 60),
        message: `${clip(st.uses, 60)} looks like an AI agent action on a workflow anyone can trigger. An agent that reads issue or comment text and holds credentials is the same boundary as a shell script, with a model in the middle.`,
        fix: 'Give the job the least token permission it needs, keep secrets out of its environment, and separate what reads outside text from what holds keys.' });
    }
  }
  // WFI-006: decide per line. The parser is line-based, so a step it could not read (flow style, odd quoting)
  // would otherwise pass silently, even in a file where other steps parsed. Any line with event text that the
  // parser did not consume is reported, unless it is a plain `key: ${{ ... }}` assignment (job-level env, with:
  // inputs, if: conditions), which is data and not code. run: and script: values are never plain data.
  if (live.some((r) => r.indent === 0 && /^[\"']?(jobs|runs)[\"']?\s*:/.test(r.raw))) {
    const consumed = new Set();
    for (const st of steps) for (const l of [...st.run, ...st.script, ...st.env, ...st.withRef]) consumed.add(l.n);
    // Positive rule (review round 4): a line is data only if it is a direct child of an env: or with: key, or an
    // if: condition, and is a plain single-line assignment. Anything else with event text is reported, whatever
    // its shape. Parent keys are tracked with an indent stack, so this is one linear pass.
    const PLAIN = /^\s*[\"']?[A-Za-z_][\w-]*[\"']?\s*:\s*[\"']?\$\{\{[^}{\[]*\}\}[\"']?\s*$/;
    const IFLINE = /^\s*(?:-\s+)?if\s*:/;
    const KEYLINE = /^\s*(?:-\s+)?[\"']?([A-Za-z_][\w-]*)[\"']?\s*:/;
    const stack = [];   // [{ indent, key }]
    const dataLine = new Set();
    for (const r of live) {
      if (isBlank(r.raw)) continue;
      while (stack.length && stack[stack.length - 1].indent >= r.indent) stack.pop();
      const parent = stack.length ? stack[stack.length - 1].key : '';
      if ((PLAIN.test(r.raw) && (parent === 'env' || parent === 'with')) || (IFLINE.test(r.raw) && !/[|>]\s*$/.test(r.raw))) dataLine.add(r.n);
      const km = KEYLINE.exec(r.raw);
      if (km) stack.push({ indent: r.indent, key: km[1] });
    }
    for (const r of live) {
      if (consumed.has(r.n) || dataLine.has(r.n)) continue;
      const hit = exprs(r.raw).find(isUntrusted);
      if (hit) add({ rule: 'WFI-006', severity: 'medium', verdict: 'REVIEW', line: r.n, step: 0, stepName: '', expression: clip(hit, 80),
        message: `Event text (${clip(hit, 80)}) appears on a line this check could not place inside a step it understands, so it could not tell whether it reaches a shell script.`,
        fix: 'Read the step by hand. If the value reaches a run: script or a github-script body, pass it through env: and use "$NAME" instead.' });
    }
  }
  // WFI-004: external trigger with open permissions
  if (priv.length && (perms.writeAll || (!perms.declared))) {
    add({ rule: 'WFI-004', severity: 'medium', verdict: 'REVIEW', line: 1, step: 0, stepName: '', expression: perms.writeAll ? 'permissions: write-all' : 'no permissions block',
      message: perms.writeAll ? 'The workflow grants write-all to a job that outside users can trigger.' : 'No permissions block on a workflow that outside users can trigger. Depending on the repository default, the token may be able to write.',
      fix: 'Declare permissions: contents: read at the top, and grant a job write access only if it needs it.' });
  }
  const order = { BLOCK: 0, REVIEW: 1, ADVISORY: 2 };
  result.findings.sort((a, b) => order[a.verdict] - order[b.verdict] || a.line - b.line);
  result.verdict = result.findings.some((f) => f.verdict === 'BLOCK') ? 'BLOCK' : result.findings.some((f) => f.verdict === 'REVIEW') ? 'REVIEW' : result.findings.length ? 'ADVISORY' : 'NO_FINDINGS';
  return result;
}


// Parser shape for the action: a Map of items, one per finding, verdict decided locally. Keys exclude the
// line number so an unchanged finding keeps its identity when unrelated lines move (the action diffs old
// against new and reports only what a pull request adds or changes).
function fromWorkflowInjection(text) {
  const m = new Map();
  const r = analyzeWorkflow(text);
  if (!r.analyzed) {
    // A workflow too large to analyze is reported, never skipped silently. Text that is simply not a
    // workflow (a composite action without steps, a stray YAML file) yields nothing.
    if (/larger than|more than/.test(r.error || '')) m.set('skip:wfi:unanalyzed', { kind: 'skip', unverifiable: true, cls: 'ambiguous', spec: 'workflow script-injection check', reason: `${r.error}; the workflow was not checked for script injection`, where: 'line 1' });
    return m;
  }
  const seen = new Map();
  for (const f of r.findings) {
    // An occurrence number keeps a second identical finding (same step name, same expression) from collapsing
    // into the first and hiding an added copy in a pull request diff.
    const base = `finding:wfi:${f.rule}:${f.stepName || f.step}:${f.expression}`;
    const n = (seen.get(base) || 0) + 1; seen.set(base, n);
    m.set(`${base}#${n}`, {
      kind: 'finding', ftype: 'workflow injection', verdict: f.verdict, severity: f.severity,
      spec: `${f.rule} line ${f.line}: ${f.expression}`, where: `line ${f.line}`, reason: `${f.message} Fix: ${f.fix}`,
    });
  }
  return m;
}

module.exports = { fromWorkflowInjection, analyzeWorkflow, isUntrusted, UNTRUSTED, MAX_BYTES, MAX_LINES, PRIVILEGED_TRIGGERS };
