'use strict';
const test = require('node:test');
const assert = require('node:assert');
const p = require('../src/parsers');

const pkgs = (m) => [...m.values()].filter(i => i.kind === 'package').map(i => `${i.ecosystem}:${i.name}@${i.version || ''}`).sort();
const skips = (m) => [...m.values()].filter(i => i.kind === 'skip');

test('manifestKind recognizes every supported file and ignores vendored trees', () => {
  assert.equal(p.manifestKind('package.json'), 'package.json');
  assert.equal(p.manifestKind('web/package-lock.json'), 'package-lock');
  assert.equal(p.manifestKind('requirements-dev.txt'), 'requirements');
  assert.equal(p.manifestKind('pyproject.toml'), 'pyproject');
  assert.equal(p.manifestKind('poetry.lock'), 'poetry.lock');
  assert.equal(p.manifestKind('Gemfile'), 'gemfile');
  assert.equal(p.manifestKind('Gemfile.lock'), 'gemfile.lock');
  assert.equal(p.manifestKind('.mcp.json'), 'mcp');
  assert.equal(p.manifestKind('.cursor/mcp.json'), 'mcp');
  assert.equal(p.manifestKind('.vscode/mcp.json'), 'mcp');
  assert.equal(p.manifestKind('claude_desktop_config.json'), 'mcp');
  assert.equal(p.manifestKind('mcp.json'), 'mcp'); // any mcp.json is an MCP config (invariant F)
  assert.equal(p.manifestKind('node_modules/x/package.json'), null);
  assert.equal(p.manifestKind('README.md'), null);
});

test('package.json: exact versions kept, ranges noted, git/local sources flagged', () => {
  const m = p.fromPackageJson(JSON.stringify({
    dependencies: { lodash: '4.17.15', express: '^4.18.0', evil: 'github:attacker/evil', local: 'file:../local' },
    devDependencies: { aliased: 'npm:real-pkg@1.0.0' },
  }));
  assert.deepEqual(pkgs(m), ['npm:express@', 'npm:lodash@4.17.15', 'npm:real-pkg@1.0.0']);
  const s = skips(m);
  assert.ok(s.find(x => x.unverifiable && /evil/.test(x.spec)));
  assert.ok(s.find(x => x.unverifiable && x.cls === 'ambiguous' && /local/.test(x.spec)), 'file: is local code: ambiguous, not a notice');
  assert.ok(s.find(x => x.unverifiable && x.cls === 'ambiguous' && /aliased/.test(x.spec)), 'an npm: alias is reported as ambiguous too');
});

test('package-lock: v3 direct vs transitive, non-registry resolved flagged', () => {
  const lock = { lockfileVersion: 3, packages: {
    '': { name: 'root' },
    'node_modules/lodash': { version: '4.17.15', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz' },
    'node_modules/a/node_modules/b': { version: '1.0.0', resolved: 'https://registry.npmjs.org/b/-/b-1.0.0.tgz' },
    'node_modules/@s/c': { version: '2.0.0', resolved: 'https://registry.npmjs.org/@s/c/-/c-2.0.0.tgz' },
    'node_modules/sneaky': { version: '1.0.0', resolved: 'https://evil.example/sneaky.tgz' },
  } };
  const all = p.fromPackageLock(JSON.stringify(lock), { transitive: true });
  assert.deepEqual(pkgs(all), ['npm:@s/c@2.0.0', 'npm:b@1.0.0', 'npm:lodash@4.17.15']);
  assert.ok(skips(all).find(x => x.unverifiable && /sneaky/.test(x.spec)));
  const direct = p.fromPackageLock(JSON.stringify(lock), { transitive: false });
  assert.deepEqual(pkgs(direct), ['npm:@s/c@2.0.0', 'npm:lodash@4.17.15']);
});

test('requirements.txt: pins, constraints, options, VCS and hashes', () => {
  const m = p.fromRequirements([
    'requests==2.31.0 --hash=sha256:abc',
    'flask>=2.0  # web',
    '-r other.txt',
    '--extra-index-url https://pypi.internal/simple',
    'pkg @ git+https://github.com/x/pkg',
    'Django[argon2]==4.2.1 ; python_version > "3.8"',
    'long==1.0 \\',
    '    --hash=sha256:def',
  ].join('\n'));
  assert.deepEqual(pkgs(m), ['pypi:Django@4.2.1', 'pypi:flask@', 'pypi:long@1.0', 'pypi:requests@2.31.0']);
  assert.ok(skips(m).find(x => x.unverifiable && /extra-index-url/.test(x.spec)));
  assert.ok(skips(m).find(x => x.unverifiable && /git\+/.test(x.spec)));
});

test('pyproject.toml: PEP 621 multi-line arrays and Poetry tables', () => {
  const m = p.fromPyproject(`
[project]
name = "x"
dependencies = [
  "httpx==0.27.0",
  "pydantic>=2",
]
[project.optional-dependencies]
dev = ["pytest==8.0.0"]
[tool.poetry.dependencies]
python = "^3.11"
rich = "13.7.1"
click = { version = "^8.1" }
mylib = { git = "https://github.com/x/mylib" }
[tool.black]
line-length = 100
`);
  assert.deepEqual(pkgs(m), ['pypi:click@', 'pypi:httpx@0.27.0', 'pypi:pydantic@', 'pypi:pytest@8.0.0', 'pypi:rich@13.7.1']);
  assert.ok(skips(m).find(x => x.unverifiable && x.spec === 'mylib'));
});

test('poetry.lock: packages with versions; non-PyPI sources flagged', () => {
  const m = p.fromPoetryLock(`
[[package]]
name = "requests"
version = "2.31.0"
description = "x"

[package.dependencies]
idna = ">=2.5"

[[package]]
name = "internal-lib"
version = "1.0.0"

[package.source]
type = "legacy"
url = "https://pypi.internal/simple"

[metadata]
lock-version = "2.0"
`);
  assert.deepEqual(pkgs(m), ['pypi:requests@2.31.0']);
  assert.ok(skips(m).find(x => x.unverifiable && /internal-lib/.test(x.spec)));
});

test('Gemfile and Gemfile.lock', () => {
  const g = p.fromGemfile(`source "https://rubygems.org"
gem "rails", "7.1.3"
gem 'puma', '~> 6.0'
gem "nokogiri"
gem "mine", git: "https://github.com/x/mine"
gem "private", source: "https://gems.internal"
`);
  assert.deepEqual(pkgs(g), ['rubygems:nokogiri@', 'rubygems:puma@', 'rubygems:rails@7.1.3']);
  assert.equal(skips(g).filter(x => x.unverifiable).length, 2);
  const l = p.fromGemfileLock(`GIT
  remote: https://github.com/x/mine
  revision: abc
  specs:
    mine (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.2-x86_64-linux)
      racc (~> 1.4)
    rails (7.1.3)
    racc (1.7.3)

PLATFORMS
  x86_64-linux
`);
  assert.deepEqual(pkgs(l), ['rubygems:nokogiri@1.16.2', 'rubygems:racc@1.7.3', 'rubygems:rails@7.1.3']);
  assert.ok(skips(l).find(x => /mine/.test(x.spec)));
});

test('MCP configs: npx, uvx, docker, url, VS Code servers key', () => {
  const m = p.fromMcpConfig(JSON.stringify({
    mcpServers: {
      github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@2025.4.8'] },
      fetch: { command: 'uvx', args: ['mcp-server-fetch'] },
      grafana: { command: 'docker', args: ['run', '-i', '--rm', 'mcp/grafana:1.0.0'] },
      remote: { url: 'https://mcp.example.com/sse' },
    },
    servers: { vs: { command: 'npx', args: ['some-mcp'] } },
  }));
  const mcp = [...m.values()].filter(i => i.kind === 'mcp').map(i => `${i.key}=${i.server}@${i.version || ''}`).sort();
  assert.deepEqual(mcp, ['fetch=mcp-server-fetch@', 'github=@modelcontextprotocol/server-github@2025.4.8', 'grafana=grafana@1.0.0', 'vs=some-mcp@']);
  // a remote server has no package identity: UNKNOWN, never judged by its (attacker-chosen) key
  assert.ok(skips(m).find(x => x.unverifiable && x.spec === 'remote' && /mcp\.example\.com/.test(x.reason)));
  // the npx/uvx packages are also checked as packages
  assert.deepEqual(pkgs(m), ['npm:@modelcontextprotocol/server-github@2025.4.8', 'npm:some-mcp@', 'pypi:mcp-server-fetch@']);
});

test('diffItems: only added or changed entries', () => {
  const before = JSON.stringify({ dependencies: { a: '1.0.0', b: '^2.0.0' } });
  const after = JSON.stringify({ dependencies: { a: '1.0.0', b: '^2.1.0', c: '3.0.0' } });
  const { items } = p.diffItems('package.json', before, after);
  assert.deepEqual(items.map(i => `${i.name}:${i.change}`).sort(), ['b:changed', 'c:added']);
  const bad = p.diffItems('package.json', before, '{not json', { file: 'package.json' });
  assert.equal(bad.errors.length, 1);
  // an unparseable manifest is an UNKNOWN finding, not just a note
  assert.equal(bad.items.length, 1);
  assert.ok(bad.items[0].kind === 'skip' && bad.items[0].unverifiable);
});
