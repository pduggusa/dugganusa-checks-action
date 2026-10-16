'use strict';
// End to end: a throwaway git repo, a local stub API, and the real entry point.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFileSync, spawn } = require('child_process');

const ENTRY = path.join(__dirname, '..', 'src', 'index.js');

function startStub() {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      seen.push({ url: req.url, auth: req.headers.authorization || null, repo: req.headers['x-dugganusa-repo'] || null, ua: req.headers['user-agent'] || null, body });
      res.setHeader('Content-Type', 'application/json');
      if (req.url.startsWith('/api/v1/mcp')) {
        const a = JSON.parse(body).params.arguments;
        const table = {
          'cxp-jquery': { verdict: 'block', malicious: true, osv_id: 'MAL-2021-1', reason: 'On the DugganUSA malicious-package deny-list' },
          lodash: { verdict: 'review', reason: 'Not malicious, but version 4.17.15 has 6 published vulnerabilities (OSV).', known_vulnerabilities: { checked: true, count: 6, vulnerabilities: [{ id: 'GHSA-p6mc-m468-83gw', severity: 'high' }] } },
        };
        const out = table[a.name] || { verdict: 'allow', reason: 'Not on the deny-list', known_vulnerabilities: { checked: !!a.version, count: 0, vulnerabilities: [] } };
        res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: JSON.stringify({ ecosystem: a.ecosystem, package: a.name, ...out }) }] } }));
        return;
      }
      const server = new URL(req.url, 'http://x').searchParams.get('server');
      if (server === 'mcp-grafana') {
        res.end(JSON.stringify({ verdict: 'ADVISORY', severity: 'critical', known_to_us: true, findings: [{ cve: 'CVE-2026-19516', cvss_score: 9.1, severity: 'critical', summary: 'header-controlled SSRF' }], dep_graph: { scanned: true, total_deps: 0 } }));
      } else {
        res.end(JSON.stringify({ verdict: 'REVIEW', severity: 'unknown', known_to_us: false, findings: [], vuln_check: { checked: false, reason: 'server_not_resolved' }, dep_graph: { scanned: false } }));
      }
    });
  });
  return new Promise(r => server.listen(0, '127.0.0.1', () => r({ server, seen, base: `http://127.0.0.1:${server.address().port}` })));
}

function repo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dusa-checks-'));
  const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe' }).toString().trim();
  g('init', '-q', '-b', 'main');
  g('config', 'user.email', 't@example.com'); g('config', 'user.name', 't');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { 'left-pad': '1.3.0' } }, null, 2));
  fs.writeFileSync(path.join(dir, 'requirements.txt'), 'requests==2.31.0\n');
  g('add', '.'); g('commit', '-qm', 'base');
  const base = g('rev-parse', 'HEAD');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { 'left-pad': '1.3.0', lodash: '4.17.15', 'cxp-jquery': '1.0.0' } }, null, 2));
  fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: { grafana: { command: 'docker', args: ['run', '-i', 'mcp/mcp-grafana:1.0.0'] }, mystery: { url: 'https://mystery.example/mcp' } } }, null, 2));
  g('add', '.'); g('commit', '-qm', 'head');
  return { dir, base };
}

function runAction(dir, base, apiBase, inputs = {}, eventName = 'pull_request', extraEnv = {}, eventExtra = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dusa-gh-'));
  const eventPath = path.join(tmp, 'event.json');
  fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { base: { sha: base } }, ...eventExtra }));
  const summary = path.join(tmp, 'summary.md'); const output = path.join(tmp, 'output.txt');
  const env = { PATH: process.env.PATH, HOME: process.env.HOME, GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: eventName, GITHUB_EVENT_PATH: eventPath,
    GITHUB_WORKSPACE: dir, GITHUB_STEP_SUMMARY: summary, GITHUB_OUTPUT: output, RUNNER_TEMP: tmp,
    'INPUT_API-BASE': apiBase, 'INPUT_RATE-PER-MINUTE': '60000' };
  for (const [k, v] of Object.entries(inputs)) env[`INPUT_${k.toUpperCase()}`] = v;
  Object.assign(env, extraEnv);
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [ENTRY], { cwd: dir, env });
    let out = ''; p.stdout.on('data', d => { out += d; }); p.stderr.on('data', d => { out += d; });
    p.on('close', (code) => resolve({ code, out, summary: fs.existsSync(summary) ? fs.readFileSync(summary, 'utf8') : '', output: fs.existsSync(output) ? fs.readFileSync(output, 'utf8') : '', report: JSON.parse(fs.readFileSync(path.join(tmp, 'dugganusa-checks-report.json'), 'utf8')) }));
  });
}

test('pull request diff: BLOCK fails the job, REVIEW/ADVISORY warn, UNKNOWN is loud, unchanged deps are skipped', async () => {
  const stub = await startStub();
  try {
    const { dir, base } = repo();
    const r = await runAction(dir, base, stub.base, { 'api-key': 'sk_e2e_secret' });
    assert.equal(r.code, 1, r.out);
    const names = r.report.results.map(x => `${x.name}:${x.verdict}`).sort();
    assert.deepEqual(names, ['cxp-jquery:BLOCK', 'grafana → mcp-grafana:ADVISORY', 'lodash:REVIEW', 'mystery:UNKNOWN']);
    assert.ok(!names.some(n => n.startsWith('left-pad')), 'unchanged dependency was not re-checked');
    assert.ok(!r.report.results.some(x => x.name === 'requests'), 'unchanged requirements file not scanned');
    assert.match(r.out, /::error file=package\.json,line=\d+,title=DugganUSA Checks%3A BLOCK::BLOCK: cxp-jquery@1\.0\.0/);
    assert.match(r.out, /::warning file=package\.json,line=\d+,title=DugganUSA Checks%3A REVIEW::REVIEW: lodash@4\.17\.15/);
    assert.match(r.out, /::warning .*UNKNOWN: not in corpus \(not judged, NOT a pass\): mystery/);
    assert.match(r.summary, /Result: FAILED/);
    assert.match(r.summary, /GHSA-p6mc-m468-83gw/);
    assert.match(r.summary, /CVE-2026-19516/);
    assert.match(r.output, /block-count<<.*\n1\n/);
    assert.ok(!r.out.includes('sk_e2e_secret') || r.out.includes('::add-mask::sk_e2e_secret'), 'key only appears in the mask command');
    assert.equal(r.out.split('sk_e2e_secret').length - 1, 1);
    assert.ok(stub.seen.every(s => s.auth === 'Bearer sk_e2e_secret' && !/api_key|sk_e2e/.test(s.url)));
  } finally { stub.server.close(); }
});

test('fail-on none passes; fail-on review fails on REVIEW alone; fail-on-unknown fails on UNKNOWN', async () => {
  const stub = await startStub();
  try {
    const { dir, base } = repo();
    assert.equal((await runAction(dir, base, stub.base, { 'fail-on': 'none' })).code, 0);
    // only lodash (REVIEW) added
    const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe' });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { 'left-pad': '1.3.0', lodash: '4.17.15' } }));
    fs.rmSync(path.join(dir, '.mcp.json'));
    g('add', '-A'); g('commit', '-qm', 'review only');
    assert.equal((await runAction(dir, base, stub.base, {})).code, 0, 'REVIEW alone passes at fail-on block');
    assert.equal((await runAction(dir, base, stub.base, { 'fail-on': 'review' })).code, 1);
    fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: { mystery: { url: 'https://m.example' } } }));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { 'left-pad': '1.3.0' } }));
    g('add', '-A'); g('commit', '-qm', 'unknown only');
    const unk = await runAction(dir, base, stub.base, {});
    assert.equal(unk.code, 0); assert.match(unk.summary, /1 UNKNOWN: these were not judged and are not a pass/);
    assert.equal((await runAction(dir, base, stub.base, { 'fail-on-unknown': 'true' })).code, 1);
  } finally { stub.server.close(); }
});

test('push event runs a full scan of every manifest', async () => {
  const stub = await startStub();
  try {
    const { dir, base } = repo();
    const r = await runAction(dir, base, stub.base, { 'fail-on': 'none' }, 'push');
    assert.equal(r.report.mode, 'full');
    const names = r.report.results.map(x => x.name);
    for (const n of ['left-pad', 'requests', 'lodash', 'cxp-jquery']) assert.ok(names.includes(n), n);
  } finally { stub.server.close(); }
});

test('API down: everything UNKNOWN; unchecked fails by default, passes only with fail-on-unchecked false', async () => {
  const { dir, base } = repo();
  const r = await runAction(dir, base, 'http://127.0.0.1:9', { 'max-wait-seconds': '0' });
  assert.equal(r.code, 1);
  assert.ok(r.report.results.every(x => x.verdict === 'UNKNOWN'));
  assert.ok(r.report.results.some(x => x.unknown_class === 'unchecked'));
  assert.match(r.summary, /UNKNOWN: unchecked/);
  const off = await runAction(dir, base, 'http://127.0.0.1:9', { 'max-wait-seconds': '0', 'fail-on-unchecked': 'false' });
  assert.equal(off.code, 0);
  assert.match(off.summary, /not judged and are not a pass/);
});

test('e2e: x-dugganusa-repo is sent only for a PUBLIC repository; private, internal and missing payload send none; raw name never sent', async () => {
  const { repoMarker, USER_AGENT } = require('../src/api');
  const stub = await startStub();
  try {
    const { dir, base } = repo();
    const env = { GITHUB_REPOSITORY: 'Octo-Org/Secret-Repo' };
    const run1 = async (repository) => { stub.seen.length = 0; await runAction(dir, base, stub.base, {}, 'pull_request', env, repository === undefined ? {} : { repository }); return stub.seen.slice(); };
    const pub = await run1({ full_name: 'Octo-Org/Secret-Repo', private: false, visibility: 'public' });
    assert.ok(pub.some(s => s.url.startsWith('/api/v1/mcp')) && pub.some(s => s.url.startsWith('/api/v1/dredd/preflight')));
    for (const s of pub) {
      assert.equal(s.repo, repoMarker('octo-org/secret-repo'));
      assert.equal(s.ua, USER_AGENT);
      assert.ok(!/octo-org|secret-repo/i.test(s.url + s.body), 'raw repository name never on the wire');
    }
    for (const repository of [
      { full_name: 'Octo-Org/Secret-Repo', private: true, visibility: 'private' },
      { full_name: 'Octo-Org/Secret-Repo', private: true, visibility: 'internal' },
      undefined, // payload has no repository object
    ]) {
      const seen = await run1(repository);
      assert.ok(seen.length >= 2);
      assert.ok(seen.every(s => s.repo === null), `no marker for ${JSON.stringify(repository)}`);
      assert.ok(seen.every(s => !/octo-org|secret-repo/i.test(s.url + s.body)));
    }
    // unreadable event payload path
    stub.seen.length = 0;
    await runAction(dir, base, stub.base, { mode: 'full' }, 'push', { ...env, GITHUB_EVENT_PATH: '/nonexistent/event.json' });
    assert.ok(stub.seen.length >= 1, 'full scan made API calls');
    assert.ok(stub.seen.every(s => s.repo === null));
  } finally { stub.server.close(); }
});
