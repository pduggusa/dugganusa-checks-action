# DugganUSA Checks

**We watched the open internet, then built the membrane between your AI agents and everything they install, call, read and obey.**

This Action puts that membrane in your pull requests. When a PR adds or changes a dependency or an MCP server, it asks two public DugganUSA checks about it before anything gets merged and installed:

- **check-package** (npm, PyPI, RubyGems): is this exact package on our malicious-package deny-list, does its registry reputation look like a staging package, and does this exact version have published vulnerabilities (OSV)?
- **Dredd** (MCP servers): do we know this server, does it have published CVEs affecting this version, and is anything in its dependency graph known to be compromised?

Threat intelligence you can check: every verdict in the job summary comes with the reason and the evidence IDs the API returned (MAL-, GHSA-, CVE-, PYSEC-), so you can verify it yourself.

## Quick start

```yaml
name: DugganUSA Checks
on:
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  membrane:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: dugganusa/dugganusa-checks-action@v1
        with:
          api-key: ${{ secrets.DUGGANUSA_API_KEY }}   # optional
```

A fuller example with `paths:` filters is in [`examples/dugganusa-checks.yml`](examples/dugganusa-checks.yml).

## What it reads

| File | Ecosystem | What counts as an item |
|---|---|---|
| `package.json` | npm | dependencies, dev, optional, peer |
| `package-lock.json`, `npm-shrinkwrap.json` | npm | every resolved package with its exact version |
| `requirements*.txt` | PyPI | each requirement; `==` pins get the version check |
| `pyproject.toml` | PyPI | PEP 621, dependency groups, Poetry tables |
| `poetry.lock` | PyPI | every locked package |
| `Gemfile`, `Gemfile.lock` | RubyGems | each gem; the lockfile gives exact versions |
| any `mcp.json` / `*.mcp.json`, `claude_desktop_config.json`, `.claude/settings.json`, `.vscode/settings.json`, `.gemini/settings.json`, `.cursor/settings.json` | MCP | each server in canonical form; `npx`/`uvx` packages are also checked as packages |

**Pull requests are diff-aware.** Only entries that are new or changed against the PR base are checked, including new transitive packages in a lockfile (that is where hijacked-dependency worms land). **Push, schedule and `workflow_dispatch` run a full scan** of every manifest, direct dependencies only by default to stay inside the free rate; set `include-transitive: true` to include everything.

Sources that cannot be judged by name are never silently dropped. A git URL, a tarball URL, a private index or a per-gem `source:` is reported as **UNKNOWN**, because the registry name we would check is not what your installer fetches.

The parsers follow what the installer actually does, and anything they cannot classify is UNKNOWN rather than skipped. Since the second security review the rules are **invariants, not lists of bad shapes**:

- **MCP launch identity is judged only for canonical forms.** `command` must be exactly `npx`, `uvx` or `docker` (no path, no `.cmd`, no wrapper), with args exactly `[-y] <pkg>[@version]` (npx) or `<pkg>[==version|@version]` (uvx) and nothing after the package, or `run [--rm] [-i] [-e NAME]... <image>[:tag|@digest]` (docker), nothing after the image, no entry keys beyond `command`/`args`/`env`/`type: stdio` and display metadata (so `cwd`, `envFile` and friends are out), and an `env` that sets none of `PATH`, `HOME`, `NODE_*`, `NODE_PATH`, `NODE_OPTIONS`, `npm_config_*`, `PIP_*`, `UV_*`, `PYTHON*`, `LD_*`, `DYLD_*`, `XDG_*`, `DOCKER_*`, proxies or CA bundles. An npx server is also ambiguous when npm exec could run a local executable instead: its name or unscoped name matches the name, a dependency or a `bin` of any `package.json` in the repository, a `bin` recorded in a v2/v3 npm lockfile, or a `node_modules/.bin` entry. (v1 lockfiles carry no bin data, so there only same-named packages are caught.) Everything else is UNKNOWN: ambiguous, with the reason. Remote servers (`url`/`type: http|sse`) are reported by host as UNKNOWN: not in corpus.
- **Local code is ambiguous everywhere** (`file:`/`link:`/relative-path specs, pip local paths and `-e .`, Poetry/uv path sources, `gemspec`, Gemfile.lock `PATH`). Only a declared `workspace:` member is a notice.
- **Gemfile:** only blank/comment lines, `source "url"`, `ruby "x"`, static `gem "name", "req", key: value` lines, `group`/`platforms`/`source ... do` blocks with a matching `end`, and the static `git_source` URL template are read. From the first line outside that subset to the end of the file, every entry is UNKNOWN: ambiguous.
- **JSON and TOML** objects are null-prototype; a `__proto__`, `constructor` or `prototype` key makes the file UNKNOWN: ambiguous.
- **Every limit** (lockfile nesting, override nesting, duplicate-key listing, directory depth, file size, line length, include depth) reports what it cut off as UNKNOWN: ambiguous; the `max-lookups` cap and an exhausted rate-limit budget report UNKNOWN: unchecked. Nothing is truncated silently, and both fail by default.
- **Scanned surfaces:** `package.json` (including `packageManager`: anything but a plain `npm|pnpm|yarn@x.y.z[+sha...]` is ambiguous), `package-lock.json`/`npm-shrinkwrap.json`, `requirements*.txt`, `pyproject.toml` (a `dynamic` dependency list or `tool.setuptools.dynamic` is ambiguous), `poetry.lock`, `Gemfile`/`Gemfile.lock`, and MCP configs: any `mcp.json` or `*.mcp.json`, `claude_desktop_config.json`, `.claude/settings*.json`, `.vscode/settings.json`, `.gemini/settings.json`, `.cursor/settings.json`. Formats we do not parse (`yarn.lock`, `pnpm-lock.yaml`, `uv.lock`, `Pipfile.lock`, `requirements*.in`, `setup.py`, ...) and installer config that redirects a registry (`.npmrc`, `pip.conf`, `uv.toml`, ...) are UNKNOWN: ambiguous when they change.

Files are read only if they are regular files inside the workspace: symlinks, FIFOs, devices and files over 32 MB are refused and reported as UNKNOWN.

## Verdicts and the job status

| Verdict | Means | Default job effect |
|---|---|---|
| **BLOCK** | Known-malicious package (deny-list or reputation), or Dredd BLOCK | **Fails the job** (error annotation) |
| **ADVISORY** | MCP server with a published CVE affecting this version | Warning |
| **REVIEW** | Not malicious, but this version has published vulnerabilities; or a suspicious reputation; or Dredd ALLOW without a dependency scan | Warning |
| **UNKNOWN: ambiguous** | Evasion-shaped: this check could not prove what would be installed or run (non-canonical MCP launcher, git/URL/file/tarball/alias spec, duplicate or prototype-shaped key, unresolvable override, Gemfile code, a limit hit, an unparsed manifest kind, a non-plain `packageManager`) | **Fails the job** (`fail-on-ambiguous`, default true) |
| **UNKNOWN: unchecked** | A clean identity the API never judged: unreachable, 5xx, timeout, HTTP 429 past the wait budget, `max-lookups` cap | **Fails the job** (`fail-on-unchecked`, default true): a pull request can pad itself to exhaust a rate budget |
| **UNKNOWN: not in corpus** | The API answered and holds no record (server or package not in our catalog), or a remote MCP server | Warning that says **not a pass** (`fail-on-unknown`, default false) |
| **ALLOW** | No known evidence against it | Nothing |

Inputs that change this:

- `fail-on: review` also fails on REVIEW and ADVISORY. `fail-on: none` reports only.
- `fail-on-unknown: true` also fails on UNKNOWN: not in corpus.
- `fail-on-unchecked: false` turns UNKNOWN: unchecked into a warning (for example on a keyless full scan you know will hit the rate limit). Then a pull request that adds enough packages to exhaust the budget can leave the malicious one unchecked and still pass.
- `fail-on-ambiguous: false` turns UNKNOWN: ambiguous into a warning. Do this only if you accept that a pull request can hide a BLOCK behind a git spec, a duplicate key or a wrapped launcher.

### Read this before trusting a green check

- **ALLOW is not proof of safety.** It means our deny-list, the reputation signals and OSV hold nothing against that name and version today. A package published an hour ago by an attacker can look exactly like that.
- **UNKNOWN is not a pass**, and it is counted, annotated and listed in the summary every time, split into its three classes. An **ambiguous** UNKNOWN fails by default: before this split, a BLOCK could be turned into a passing UNKNOWN just by rewriting the dependency as a git spec or adding a duplicate key. An **unchecked** UNKNOWN (the API never answered for it) also fails by default, because padding a pull request until the rate budget or `max-lookups` runs out is the same trick. A **not in corpus** UNKNOWN does not fail by default, because an unknown-but-clean MCP server is common and a check that is always red gets switched off. For the strict posture, set `fail-on-unknown: true`.
- **The canonical forms are strict on purpose.** `npx -y @modelcontextprotocol/server-filesystem /some/dir` is ambiguous: an argument after the package is handed to whatever the package runs, and `npx -y tsx ./evil.ts` has exactly the same shape. The parser does not guess which is which. A person does, through the owner gate below.
- **Context counts, not just the entry.** A repository `.npmrc`/`.yarnrc`/`bunfig.toml` that redirects the registry makes every npx server ambiguous; a `uv.toml`, `pip.conf` or `pyproject.toml` `[tool.uv]` index makes every uvx server ambiguous; a top-level `env` in a settings file that sets a launcher variable makes every server in that file ambiguous.

### Owner gate: `allow-ambiguous`

For a legitimate non-canonical MCP entry, list its fingerprint in `allow-ambiguous` (one per line; text before the fingerprint is a label for humans):

```yaml
allow-ambiguous: |
  .mcp.json#filesystem sha256:3f1c...e9
```

Every ambiguous MCP entry prints its fingerprint in the summary's Evidence column. The fingerprint is a sha256 over the file path and the entry's canonical JSON (container path, command, args, env names and values, every option, and any top-level env), so any change to that server re-triggers the gate. A line without a fingerprint honors nothing and is annotated. A honored entry is never silent: it is listed as **ALLOWED BY OWNER (ambiguous)** with its fingerprint and counted in `owner-allowed-count`, and the package it would fetch is still checked, so a BLOCK on it still fails the job. Fingerprints that match nothing are reported as stale. Only MCP entries can be gated; manifest findings cannot.
- **A range is checked by name only.** `"express": "^4.18.0"` gets the malicious-package check but not the version vulnerability check. Commit your lockfile and the exact versions are checked.
- No check is perfect. We cap our own confidence at 95%: something in any verdict list will be wrong, and you should treat these verdicts as one input to a decision, not a guarantee.

## Inputs

| Input | Default | |
|---|---|---|
| `api-key` | none | Optional DugganUSA API key. Pass it from a secret. Sent only as `Authorization: Bearer`, never in a URL, masked in logs. |
| `fail-on` | `block` | `block`, `review` or `none` |
| `fail-on-unknown` | `false` | Also fail on UNKNOWN: not in corpus |
| `fail-on-ambiguous` | `true` | Fail on UNKNOWN: ambiguous (evasion-shaped) |
| `fail-on-unchecked` | `true` | Fail on UNKNOWN: unchecked (API outage, rate limit, lookup cap) |
| `allow-ambiguous` | none | Owner gate: fingerprints of exact ambiguous MCP entries to accept (see above) |
| `mode` | `auto` | `auto` (diff on `pull_request`/`merge_group`, full otherwise), `diff`, `full` |
| `base-ref` | PR base SHA | Commit to diff against |
| `include-transitive` | `auto` | Lockfile transitives: yes in diff mode, no in full scans |
| `check-mcp` | `true` | Check MCP server configs with Dredd |
| `max-lookups` | `200` | Lookup cap per run; the rest are reported UNKNOWN: unchecked |
| `rate-per-minute` | auto | Client-side pacing for package lookups (10/min keyless, 60/min keyed) |
| `max-wait-seconds` | `300` | Total time the run may wait out HTTP 429s |
| `working-directory` | `.` | Directory to scan |

## Outputs

`result` (`pass`/`fail`), `block-count`, `review-count` (REVIEW plus ADVISORY), `unknown-count` (both classes), `ambiguous-count`, `unchecked-count`, `owner-allowed-count`, `allow-count`, and `report-path`: a JSON file with every verdict, reason, evidence ID and, for Dredd, the response signature.

## Rate limits

The Action works without a key. Keyless package checks share the anonymous rate (currently 10 per minute and 50 per day per source IP), and GitHub-hosted runners share egress IPs with other users, so a large PR or a full scan can run out. The Action paces itself under the per-minute cap, waits out a per-minute 429, and reports anything it could not check as UNKNOWN. It never reports an unchecked package as a pass. A free account key raises the limits; see the pricing page at analytics.dugganusa.com/pricing.

## Privacy

The Action sends package names, versions, ecosystems and MCP server names to `analytics.dugganusa.com`. It does not send file contents, repository names or source code.

## Development

Zero runtime dependencies. `npm test` runs the unit and end-to-end tests against a local stub API (no network).

## License

MIT. Copyright (c) 2026 DugganUSA LLC.
