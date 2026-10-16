'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { Client, normalizeDredd, normalizePackage, clean, repoMarker, USER_AGENT } = require('../src/api');
const crypto = require('crypto');

// Fake fetch: routes check-package and Dredd preflight to canned responses; records calls.
function stub({ packages = {}, servers = {}, script = [] } = {}) {
  const calls = [];
  const queue = [...script];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (queue.length) { const s = queue.shift(); if (s) return s(); }
    if (url.includes('/api/v1/mcp')) {
      const a = JSON.parse(init.body).params.arguments;
      const out = packages[`${a.ecosystem}:${a.name}`] || { verdict: 'allow', reason: 'not on the deny-list' };
      return resp(200, { jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: JSON.stringify(out) }] } });
    }
    const server = new URL(url).searchParams.get('server');
    return resp(200, servers[server] || { verdict: 'REVIEW', severity: 'unknown', known_to_us: false, findings: [], vuln_check: { checked: false, reason: 'server_not_resolved' }, dep_graph: { scanned: false } });
  };
  return { fetchImpl, calls };
}
function resp(status, body, headers = {}) {
  return { status, ok: status >= 200 && status < 300, json: async () => body, headers: { get: (k) => headers[k.toLowerCase()] ?? null } };
}
const fast = { sleepImpl: async () => {}, now: () => 0 };

test('key goes ONLY in the Authorization header, never the URL', async () => {
  const s = stub();
  const c = new Client({ apiKey: 'sk_test_secret', fetchImpl: s.fetchImpl, ...fast });
  await c.checkPackage({ ecosystem: 'npm', name: 'x', version: '1.0.0' });
  await c.checkMcpServer({ server: 'y' });
  for (const call of s.calls) {
    assert.ok(!call.url.includes('sk_test_secret'));
    assert.ok(!/api_key/i.test(call.url));
    assert.equal(call.init.headers.Authorization, 'Bearer sk_test_secret');
  }
});

test('keyless sends no Authorization header', async () => {
  const s = stub();
  const c = new Client({ fetchImpl: s.fetchImpl, ...fast });
  await c.checkPackage({ ecosystem: 'npm', name: 'x' });
  assert.equal(s.calls[0].init.headers.Authorization, undefined);
});

test('check-package verdicts map to BLOCK / REVIEW / ALLOW / UNKNOWN', async () => {
  const s = stub({ packages: {
    'npm:cxp-jquery': { verdict: 'block', malicious: true, osv_id: 'MAL-2021-1', reason: 'On the deny-list' },
    'npm:lodash': { verdict: 'review', reason: '6 vulns', known_vulnerabilities: { checked: true, count: 6, vulnerabilities: [{ id: 'GHSA-p6mc-m468-83gw', severity: 'high' }] } },
    'npm:left-pad': { verdict: 'allow', reason: 'Not on the deny-list', known_vulnerabilities: { checked: true, count: 0, vulnerabilities: [] } },
    'npm:weird': { verdict: 'unknown', reason: 'Unsupported' },
  } });
  const c = new Client({ fetchImpl: s.fetchImpl, ...fast });
  const b = await c.checkPackage({ ecosystem: 'npm', name: 'cxp-jquery' });
  assert.equal(b.verdict, 'BLOCK'); assert.deepEqual(b.evidence, ['MAL-2021-1']);
  const r = await c.checkPackage({ ecosystem: 'npm', name: 'lodash', version: '4.17.15' });
  assert.equal(r.verdict, 'REVIEW'); assert.ok(r.evidence[0].startsWith('GHSA-p6mc'));
  assert.equal((await c.checkPackage({ ecosystem: 'npm', name: 'left-pad', version: '1.3.0' })).verdict, 'ALLOW');
  assert.equal((await c.checkPackage({ ecosystem: 'npm', name: 'weird' })).verdict, 'UNKNOWN');
});

test('ALLOW without a version says the vuln check did not run', () => {
  const r = normalizePackage({ verdict: 'allow', reason: 'Not on the deny-list' }, { version: null });
  assert.equal(r.verdict, 'ALLOW');
  assert.match(r.reason, /known-vulnerability check not run/);
});

test('Dredd: BLOCK, ADVISORY with CVE, unknown server is UNKNOWN, ALLOW without dep scan is REVIEW', () => {
  assert.equal(normalizeDredd({ verdict: 'BLOCK', known_to_us: true, severity: 'critical', findings: [{ finding_type: 'malicious' }] }).verdict, 'BLOCK');
  const adv = normalizeDredd({ verdict: 'ADVISORY', known_to_us: true, severity: 'critical', findings: [{ cve: 'CVE-2026-19516', cvss_score: 9.1, severity: 'critical', summary: 'SSRF' }], dep_graph: { scanned: true } });
  assert.equal(adv.verdict, 'ADVISORY'); assert.match(adv.evidence[0], /CVE-2026-19516 CVSS 9.1/);
  const unk = normalizeDredd({ verdict: 'REVIEW', severity: 'unknown', known_to_us: false, findings: [], vuln_check: { reason: 'server_not_resolved' } });
  assert.equal(unk.verdict, 'UNKNOWN'); assert.match(unk.reason, /not a pass/);
  assert.equal(normalizeDredd({ verdict: 'ALLOW', known_to_us: true, severity: 'none', dep_graph: { scanned: false } }).verdict, 'REVIEW');
  assert.equal(normalizeDredd({ verdict: 'ALLOW', known_to_us: true, severity: 'none', dep_graph: { scanned: true, total_deps: 12 } }).verdict, 'ALLOW');
});

test('minute 429 waits and retries; daily 429 stops further package calls', async () => {
  const waits = [];
  const s = stub({ script: [
    () => resp(429, { jsonrpc: '2.0', error: { code: -32029, message: 'rate_limited: minute cap 10' } }, { 'x-ratelimit-window': 'minute' }),
  ] });
  const c = new Client({ fetchImpl: s.fetchImpl, sleepImpl: async (ms) => { waits.push(ms); }, now: () => 30000 });
  const r = await c.checkPackage({ ecosystem: 'npm', name: 'x', version: '1.0.0' });
  assert.equal(r.verdict, 'ALLOW');
  assert.ok(waits.some(w => w >= 30000), 'waited for the next minute window');
  assert.equal(c.rateLimited, 1);

  const s2 = stub({ script: [() => resp(429, { error: { message: 'rate_limited: day cap 50' } }, { 'x-ratelimit-window': 'day' })] });
  const c2 = new Client({ fetchImpl: s2.fetchImpl, ...fast });
  const d1 = await c2.checkPackage({ ecosystem: 'npm', name: 'a' });
  const d2 = await c2.checkPackage({ ecosystem: 'npm', name: 'b' });
  assert.equal(d1.verdict, 'UNKNOWN'); assert.match(d1.reason, /daily cap/);
  assert.equal(d2.verdict, 'UNKNOWN');
  assert.equal(s2.calls.length, 1, 'no call after the daily cap');
  // Dredd lane is independent
  assert.equal((await c2.checkMcpServer({ server: 'z' })).verdict, 'UNKNOWN');
  assert.equal(s2.calls.length, 2);
});

test('429 past the wait budget becomes UNKNOWN, never ALLOW', async () => {
  const always429 = () => resp(429, { error: { message: 'rate_limited: minute cap 10' } });
  const s = stub({ script: [always429, always429, always429, always429, always429, always429] });
  const c = new Client({ fetchImpl: s.fetchImpl, maxWaitMs: 0, ...fast });
  const r = await c.checkPackage({ ecosystem: 'npm', name: 'x' });
  assert.equal(r.verdict, 'UNKNOWN');
});

test('network failure and 5xx become UNKNOWN after retries', async () => {
  const boom = () => { throw new Error('ECONNRESET'); };
  const s = stub({ script: [boom, boom, boom] });
  const c = new Client({ fetchImpl: s.fetchImpl, ...fast });
  assert.equal((await c.checkPackage({ ecosystem: 'npm', name: 'x' })).verdict, 'UNKNOWN');
  const s5 = stub({ script: [() => resp(503, {}), () => resp(503, {}), () => resp(503, {})] });
  const c5 = new Client({ fetchImpl: s5.fetchImpl, ...fast });
  assert.equal((await c5.checkMcpServer({ server: 'x' })).verdict, 'UNKNOWN');
});

test('keyless pacing spaces package calls at the anonymous rate', async () => {
  let t = 0; const waits = [];
  const s = stub();
  const c = new Client({ fetchImpl: s.fetchImpl, now: () => t, sleepImpl: async (ms) => { waits.push(ms); t += ms; } });
  for (let i = 0; i < 3; i++) await c.checkPackage({ ecosystem: 'npm', name: `p${i}` });
  assert.deepEqual(waits, [6000, 6000]);
});

test('clean strips control, bidi and zero-width characters (no workflow-command smuggling)', () => {
  assert.equal(clean('a\n::set-output name=x::y‮​ b'), 'a ::set-output name=x::y b');
});

test('rejects a non-https api-base', () => {
  assert.throws(() => new Client({ apiBase: 'http://evil.example' }));
});

test('repo marker: sha256 of the lowercase repository, first 16 hex chars', () => {
  const want = crypto.createHash('sha256').update('octo-org/my-repo').digest('hex').slice(0, 16);
  assert.equal(repoMarker('Octo-Org/My-Repo'), want);
  assert.equal(repoMarker('octo-org/my-repo'), want);
  assert.match(want, /^[0-9a-f]{16}$/);
  assert.equal(repoMarker(''), null);
  assert.equal(repoMarker(undefined), null);
  assert.equal(repoMarker('   '), null);
});

test('x-dugganusa-repo is sent on BOTH check-package and Dredd preflight, never the raw name', async () => {
  const s = stub();
  const c = new Client({ repository: 'Octo-Org/My-Repo', fetchImpl: s.fetchImpl, ...fast });
  await c.checkPackage({ ecosystem: 'npm', name: 'x', version: '1.0.0' });
  await c.checkMcpServer({ server: 'y' });
  assert.equal(s.calls.length, 2);
  for (const call of s.calls) {
    assert.equal(call.init.headers['x-dugganusa-repo'], repoMarker('octo-org/my-repo'));
    assert.equal(call.init.headers['User-Agent'], USER_AGENT);
    const wire = JSON.stringify({ url: call.url, headers: call.init.headers, body: call.init.body || '' }).toLowerCase();
    assert.ok(!wire.includes('octo-org'), 'raw owner must never be sent');
    assert.ok(!wire.includes('my-repo'), 'raw repo name must never be sent');
  }
});

test('no repository -> no x-dugganusa-repo header', async () => {
  const s = stub();
  const c = new Client({ fetchImpl: s.fetchImpl, ...fast });
  await c.checkPackage({ ecosystem: 'npm', name: 'x' });
  await c.checkMcpServer({ server: 'y' });
  for (const call of s.calls) assert.ok(!('x-dugganusa-repo' in call.init.headers));
});

test('User-Agent carries the package.json version', () => {
  assert.equal(USER_AGENT, `dugganusa-checks-action/${require('../package.json').version}`);
});
