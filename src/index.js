#!/usr/bin/env node
'use strict';
// DugganUSA Checks: pre-install membrane checks for pull requests.

const fs = require('fs');
const path = require('path');
const gha = require('./gha');
const run = require('./run');
const { publicRepository } = require('./api');

async function main() {
  const apiKey = gha.getInput('api-key');
  gha.mask(apiKey);
  const failOn = gha.getInput('fail-on', 'block').toLowerCase();
  if (!run.FAIL_ON.includes(failOn)) throw new Error(`fail-on must be one of ${run.FAIL_ON.join(', ')}`);
  const failOnUnknown = gha.getBool('fail-on-unknown', false);
  const failOnAmbiguous = gha.getBool('fail-on-ambiguous', true);
  const failOnUnchecked = gha.getBool('fail-on-unchecked', true);
  const { allowed: allowAmbiguous, rejected: allowRejected } = run.parseAllowAmbiguous(gha.getInput('allow-ambiguous', ''));
  for (const l of allowRejected) gha.annotate('warning', `allow-ambiguous line has no sha256 fingerprint and honors nothing: ${l}`, { title: 'DugganUSA Checks' });
  const modeInput = gha.getInput('mode', 'auto').toLowerCase();
  if (!['auto', 'diff', 'full'].includes(modeInput)) throw new Error('mode must be auto, diff or full');
  const includeTransitive = gha.getInput('include-transitive', 'auto').toLowerCase();
  if (!['auto', 'true', 'false'].includes(includeTransitive)) throw new Error('include-transitive must be auto, true or false');
  const maxLookups = Math.max(0, parseInt(gha.getInput('max-lookups', '200'), 10) || 0);
  const ratePerMin = parseInt(gha.getInput('rate-per-minute', '0'), 10) || undefined;
  const maxWaitMs = Math.max(0, parseInt(gha.getInput('max-wait-seconds', '300'), 10) || 0) * 1000;
  const checkMcp = gha.getBool('check-mcp', true);
  const workspace = fs.realpathSync(process.env.GITHUB_WORKSPACE || process.cwd());
  const wdInput = gha.getInput('working-directory', '.');
  const workdir = fs.realpathSync(path.resolve(workspace, wdInput));
  if (workdir !== workspace && !workdir.startsWith(workspace + path.sep)) throw new Error('working-directory must be inside the workspace');
  const annFile = (f) => path.posix.join(wdInput.replace(/\\/g, '/'), String(f)).replace(/^\.\//, '');
  const baseInput = gha.getInput('base-ref');
  const apiBase = gha.getInput('api-base', 'https://analytics.dugganusa.com');

  const event = run.readEvent();
  let modeInfo = run.resolveMode({ modeInput, eventName: process.env.GITHUB_EVENT_NAME, event, baseInput });
  if (modeInfo.mode === 'diff' && !run.ensureCommit(workdir, modeInfo.base)) {
    gha.annotate('warning', `Base commit ${modeInfo.base.slice(0, 12)} is not available (use actions/checkout with fetch-depth: 0 or 2); falling back to a full scan.`, { title: 'DugganUSA Checks' });
    modeInfo = { mode: 'full', base: null, reason: 'base commit unavailable; scanned everything' };
  }
  gha.log(`DugganUSA Checks: ${modeInfo.reason}`);

  const { items, notes, files, texts, transitive } = run.collect({ cwd: workdir, mode: modeInfo.mode, base: modeInfo.base, includeTransitive, checkMcp, allowAmbiguous });
  gha.log(`DugganUSA Checks: ${files.length} manifest/config file(s), ${items.length} item(s) to check`);

  const client = new run.Client({ apiBase, apiKey, repository: publicRepository(event, process.env.GITHUB_REPOSITORY), packageRatePerMin: ratePerMin, maxWaitMs, log: (m) => gha.log(`  ${m}`) });
  gha.group('Lookups');
  const results = await run.check(items, client, { maxLookups, log: (m) => gha.log(`  ${m}`) });
  gha.endGroup();

  const { counts, failed, failing } = run.decide(results, { failOn, failOnUnknown, failOnAmbiguous, failOnUnchecked });

  for (const r of results) {
    if (r.verdict === 'ALLOW') continue;
    if (r.owner_allowed) { gha.annotate('notice', `ALLOWED BY OWNER (ambiguous): ${run.label(r.item)}. ${String(r.reason).replace(/[.\s]+$/, '')}. Fingerprint ${r.owner_allowed}.`, { file: annFile(r.item.files[0]), line: r.item.line, title: 'DugganUSA Checks: ALLOWED BY OWNER' }); continue; }
    const i = r.item;
    const name = `${run.label(i)}${i.version ? '@' + i.version : ''}`;
    const ev = (r.evidence || []).length ? ` Evidence: ${r.evidence.join(', ')}.` : '';
    const level = failing(r) ? 'error' : 'warning';
    const cls = run.unknownClass(r);
    const lead = r.verdict === 'UNKNOWN' ? `UNKNOWN: ${cls.replace(/_/g, ' ')} (not judged, NOT a pass)` : r.verdict;
    gha.annotate(level, `${lead}: ${name}. ${String(r.reason).replace(/[.\s]+$/, "")}.${ev}`, { file: annFile(i.files[0]), line: i.line, title: `DugganUSA Checks: ${r.verdict}${cls ? ' ' + cls : ''}` });
  }
  for (const n of notes) if (n.level === 'warning') gha.annotate('warning', n.text, { file: annFile(n.file), title: 'DugganUSA Checks' });

  const md = run.summaryMarkdown({ results, counts, failed, modeInfo, notes, failOn, failOnUnknown, failOnAmbiguous, failOnUnchecked, keyed: !!apiKey, client, transitive });
  if (!gha.appendSummary(md)) for (const l of md.split('\n')) gha.log(l);

  const report = { mode: modeInfo.mode, base: modeInfo.base, failed, counts, api_calls: client.calls, rate_limited: client.rateLimited,
    results: results.map(r => ({ verdict: r.verdict, unknown_class: run.unknownClass(r), owner_allowed: r.owner_allowed || null, fingerprint: r.item.fingerprint || null, api_verdict: r.api_verdict || null, type: r.item.kind === 'mcp' ? 'mcp' : r.item.kind === 'skip' ? 'source' : r.item.ecosystem, name: run.label(r.item), version: r.item.version || null, files: r.item.files, transitive: !!r.item.transitive, reason: r.reason, evidence: r.evidence || [], signature: r.signature || null })) };
  const reportPath = path.join(process.env.RUNNER_TEMP || require('os').tmpdir(), 'dugganusa-checks-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  gha.setOutput('result', failed ? 'fail' : 'pass');
  gha.setOutput('block-count', String(counts.BLOCK));
  gha.setOutput('review-count', String(counts.REVIEW + counts.ADVISORY));
  gha.setOutput('unknown-count', String(counts.UNKNOWN));
  gha.setOutput('ambiguous-count', String(counts.UNKNOWN_AMBIGUOUS));
  gha.setOutput('unchecked-count', String(counts.UNKNOWN_UNCHECKED));
  gha.setOutput('owner-allowed-count', String(counts.OWNER_ALLOWED));
  gha.setOutput('allow-count', String(counts.ALLOW));
  gha.setOutput('report-path', reportPath);

  gha.log(`DugganUSA Checks: ${counts.BLOCK} block, ${counts.ADVISORY} advisory, ${counts.REVIEW} review, ${counts.UNKNOWN} unknown (${counts.UNKNOWN_AMBIGUOUS} ambiguous, ${counts.UNKNOWN_UNCHECKED} unchecked), ${counts.ALLOW} allow -> ${failed ? 'FAIL' : 'pass'}`);
  if (failed) process.exitCode = 1;
}

main().catch((e) => {
  // Our own crash is not a pass: fail loudly rather than report green on a check that never ran.
  gha.annotate('error', `DugganUSA Checks internal error, nothing was judged: ${e && e.message ? e.message : e}`, { title: 'DugganUSA Checks' });
  process.exitCode = 1;
});
