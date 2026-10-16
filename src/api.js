'use strict';
// Client for the two public DugganUSA membrane checks.
//
//   check-package : POST {base}/api/v1/mcp   JSON-RPC 2.0 tools/call "check-package"
//                   (there is no REST route and no batch: one package per request)
//   Dredd         : GET  {base}/api/v1/dredd/preflight?server=&version=
//
// Auth: optional key, sent ONLY as "Authorization: Bearer". Never as a query string.
// Any failure (429 past the wait budget, 5xx, timeout, bad JSON) becomes UNKNOWN, never ALLOW.

const VERSION = '1.0.0';
const USER_AGENT = `dugganusa-checks-action/${VERSION}`;

// Strip control, zero-width, bidi and tag characters from API text before it reaches a log,
// an annotation or the job summary; collapse whitespace; cap length.
function clean(s, max = 300) {
  return String(s == null ? '' : s)
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]|[\u{e0000}-\u{e007f}]/gu, ' ')
    .replace(/\s+/g, ' ').trim().slice(0, max);
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

class Client {
  constructor({ apiBase = 'https://analytics.dugganusa.com', apiKey = '', fetchImpl = globalThis.fetch, packageRatePerMin, mcpRatePerMin = 30, maxWaitMs = 300000, timeoutMs = 20000, sleepImpl = sleep, now = () => Date.now(), log = () => {} } = {}) {
    this.base = String(apiBase).replace(/\/+$/, '');
    if (!/^https:\/\//.test(this.base) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(this.base)) throw new Error('api-base must be an https:// URL');
    this.apiKey = apiKey || '';
    this.fetch = fetchImpl;
    this.sleep = sleepImpl;
    this.now = now;
    this.log = log;
    this.timeoutMs = timeoutMs;
    this.waitBudgetMs = maxWaitMs; // total time this run may spend waiting out 429s
    this.dayExhausted = { pkg: false, mcp: false };
    this.calls = 0;
    this.rateLimited = 0;
    // Client-side pacing so a keyless run stays under the anonymous per-minute cap instead of
    // hammering into 429s. Anonymous check-package: 10/min, 50/day per IP (shared runner IPs!).
    const pkgRate = packageRatePerMin || (this.apiKey ? 60 : 10);
    this.pacers = { pkg: { interval: Math.ceil(60000 / pkgRate), next: 0 }, mcp: { interval: Math.ceil(60000 / mcpRatePerMin), next: 0 } };
  }

  headers(extra = {}) {
    const h = { 'User-Agent': USER_AGENT, Accept: 'application/json', ...extra };
    if (this.apiKey) h.Authorization = `Bearer ${this.apiKey}`;
    return h;
  }

  async pace(lane) {
    const p = this.pacers[lane];
    const t = this.now();
    const at = Math.max(t, p.next);
    p.next = at + p.interval;
    if (at > t) await this.sleep(at - t);
  }

  // One HTTP exchange with 429 / transient retry. -> { ok, status, json, error }
  async request(lane, url, init) {
    let attempt = 0;
    for (;;) {
      if (this.dayExhausted[lane]) return { ok: false, error: 'daily rate-limit cap reached earlier in this run; not called' };
      await this.pace(lane);
      attempt++;
      this.calls++;
      let r;
      try {
        r = await this.fetch(url, { ...init, signal: AbortSignal.timeout(this.timeoutMs) });
      } catch (e) {
        if (attempt < 3) { await this.sleep(2000 * attempt); continue; }
        return { ok: false, error: e && e.name === 'TimeoutError' ? `timed out after ${this.timeoutMs}ms` : `unreachable (${clean(e && e.message, 120)})` };
      }
      let json = null;
      try { json = await r.json(); } catch { /* non-JSON */ }
      if (r.status === 429) {
        this.rateLimited++;
        const msg = String((json && json.error && json.error.message) || (json && json.error) || '');
        const isDay = /day/i.test(msg) || /^day$/i.test(r.headers && r.headers.get ? (r.headers.get('x-ratelimit-window') || '') : '');
        if (isDay) {
          this.dayExhausted[lane] = true;
          return { ok: false, status: 429, error: `rate limited: daily cap reached (${clean(msg, 80) || 'HTTP 429'}). Add an api-key to raise it` };
        }
        const ra = Number(r.headers && r.headers.get ? r.headers.get('retry-after') : NaN);
        const toNextMinute = 60000 - (this.now() % 60000) + 1500;
        const wait = Number.isFinite(ra) && ra > 0 ? ra * 1000 : toNextMinute;
        if (attempt <= 4 && wait <= this.waitBudgetMs) {
          this.waitBudgetMs -= wait;
          this.log(`rate limited (${clean(msg, 80) || 'HTTP 429'}); waiting ${Math.round(wait / 1000)}s`);
          await this.sleep(wait);
          continue;
        }
        return { ok: false, status: 429, error: `rate limited (${clean(msg, 80) || 'HTTP 429'}) and the wait budget is spent` };
      }
      if (r.status >= 500 && attempt < 3) { await this.sleep(2000 * attempt); continue; }
      if (!r.ok) return { ok: false, status: r.status, error: `HTTP ${r.status}${json && json.error ? ': ' + clean(json.error.message || json.error, 120) : ''}` };
      return { ok: true, status: r.status, json };
    }
  }

  async checkPackage({ ecosystem, name, version }) {
    const args = { ecosystem, name };
    if (version) args.version = version;
    const res = await this.request('pkg', `${this.base}/api/v1/mcp`, {
      method: 'POST',
      headers: this.headers({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'check-package', arguments: args } }),
    });
    if (!res.ok) return { verdict: 'UNKNOWN', api_verdict: null, reason: `check-package not completed: ${res.error}`, evidence: [] };
    const d = res.json || {};
    if (d.error) return { verdict: 'UNKNOWN', api_verdict: null, reason: `check-package error: ${clean(d.error.message, 160)}`, evidence: [] };
    let out;
    try { out = JSON.parse(d.result.content[0].text); } catch { return { verdict: 'UNKNOWN', api_verdict: null, reason: 'check-package returned an unreadable result', evidence: [] }; }
    return normalizePackage(out, { version });
  }

  async checkMcpServer({ server, version }) {
    const qs = new URLSearchParams({ server });
    if (version) qs.set('version', version);
    const res = await this.request('mcp', `${this.base}/api/v1/dredd/preflight?${qs}`, { method: 'GET', headers: this.headers() });
    if (!res.ok) return { verdict: 'UNKNOWN', api_verdict: null, reason: `Dredd preflight not completed: ${res.error}`, evidence: [] };
    return normalizeDredd(res.json || {});
  }
}

function normalizePackage(out, { version } = {}) {
  const v = String(out.verdict || '').toLowerCase();
  const verdict = v === 'block' ? 'BLOCK' : v === 'review' ? 'REVIEW' : v === 'allow' ? 'ALLOW' : 'UNKNOWN';
  const evidence = [];
  if (out.osv_id) evidence.push(clean(out.osv_id, 60));
  const kv = out.known_vulnerabilities;
  if (kv && kv.checked && Array.isArray(kv.vulnerabilities)) for (const x of kv.vulnerabilities) evidence.push(clean(x.id, 60) + (x.severity ? ` (${clean(x.severity, 20)})` : ''));
  if (out.reputation && Array.isArray(out.reputation.signals)) for (const s of out.reputation.signals.slice(0, 3)) evidence.push(clean(s, 80));
  const notes = [];
  if (kv && kv.checked === false && version) notes.push(`known-vulnerability check did not run (${clean(kv.reason, 40)})`);
  if (!version && verdict === 'ALLOW') notes.push('no exact version: known-vulnerability check not run');
  if (kv && kv.count > (kv.vulnerabilities || []).length) notes.push(`${kv.count} vulnerabilities total, first ${(kv.vulnerabilities || []).length} listed`);
  return {
    verdict, api_verdict: v || null,
    reason: clean(out.reason, 300) + (notes.length ? ` [${notes.join('; ')}]` : ''),
    evidence,
    source: clean(out.source, 120),
  };
}

function normalizeDredd(d) {
  const V = String(d.verdict || '').toUpperCase();
  const known = d.known_to_us === true;
  const scanned = !!(d.dep_graph && d.dep_graph.scanned);
  const evidence = [];
  for (const f of (d.findings || []).slice(0, 5)) {
    const id = f.cve || f.ghsa || f.osv_id || f.finding_type || f.type || 'finding';
    evidence.push(clean(`${id}${f.cvss_score ? ' CVSS ' + f.cvss_score : ''}${f.severity ? ' (' + f.severity + ')' : ''}`, 80));
  }
  if (d.dep_graph && d.dep_graph.compromised_count) evidence.push(`${Number(d.dep_graph.compromised_count)} compromised dependencies`);
  let verdict, reason;
  const findingText = (d.findings || []).slice(0, 2).map(f => clean(f.summary || f.title || f.reason || '', 140)).filter(Boolean).join('; ');
  if (V === 'BLOCK') { verdict = 'BLOCK'; reason = findingText || 'Dredd BLOCK'; }
  else if (V === 'ADVISORY') { verdict = 'ADVISORY'; reason = findingText || 'Dredd ADVISORY'; }
  else if (!known || d.severity === 'unknown') {
    verdict = 'UNKNOWN';
    reason = `Dredd holds no record of this server (severity unknown${d.vuln_check && d.vuln_check.reason ? ', ' + clean(d.vuln_check.reason, 40) : ''}): nothing was resolved or scanned. This is not a pass`;
  } else if (V === 'ALLOW' && scanned) {
    verdict = 'ALLOW';
    reason = 'Known server, no findings' + (d.dep_graph.total_deps ? `; ${Number(d.dep_graph.total_deps)} dependencies scanned` : '; no dependencies indexed for it, so the transitive check found nothing to scan');
  } else if (V === 'ALLOW') {
    verdict = 'REVIEW'; reason = 'Dredd ALLOW, but the dependency graph was not scanned, so transitive risk is unchecked';
  } else if (V === 'REVIEW') {
    verdict = 'REVIEW'; reason = findingText || 'Dredd REVIEW';
  } else {
    verdict = 'UNKNOWN'; reason = `Dredd returned no usable verdict (${clean(V || 'none', 20)})`;
  }
  return { verdict, api_verdict: V || null, reason, evidence, signature: d.signature ? clean(d.signature, 80) : null, known_to_us: known, dep_graph_scanned: scanned };
}

module.exports = { Client, normalizePackage, normalizeDredd, clean, USER_AGENT, VERSION };
