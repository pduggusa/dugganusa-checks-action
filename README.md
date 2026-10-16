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
| `.mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings.json` | MCP | each server; `npx`/`uvx` launchers are also checked as packages |

**Pull requests are diff-aware.** Only entries that are new or changed against the PR base are checked, including new transitive packages in a lockfile (that is where hijacked-dependency worms land). **Push, schedule and `workflow_dispatch` run a full scan** of every manifest, direct dependencies only by default to stay inside the free rate; set `include-transitive: true` to include everything.

Sources that cannot be judged by name are never silently dropped. A git URL, a tarball URL, a private index or a per-gem `source:` is reported as **UNKNOWN**, because the registry name we would check is not what your installer fetches.

The parsers follow what the installer actually does, and anything they cannot classify is UNKNOWN rather than skipped: duplicate JSON keys, a lockfile entry whose `resolved` URL fetches a different package (that package is checked instead), `overrides`/`resolutions`, `-i`/`--index-url` (every package in the file becomes UNKNOWN), `-r` includes (followed inside the repository), `tool.uv.sources`, Poetry primary sources, Gemfile lines that are Ruby code rather than plain `gem` calls, and MCP servers launched by anything other than a recognized `npx`/`uvx`/`docker run` command. A remote (URL) MCP server is UNKNOWN: its config key is attacker-chosen text, not an identity. Lockfile formats we do not parse (`yarn.lock`, `pnpm-lock.yaml`, `uv.lock`, `Pipfile.lock`, ...) and installer config that redirects a registry (`.npmrc`, `pip.conf`, `uv.toml`, ...) are reported as UNKNOWN when they change.

Files are read only if they are regular files inside the workspace: symlinks, FIFOs, devices and files over 32 MB are refused and reported as UNKNOWN.

## Verdicts and the job status

| Verdict | Means | Default job effect |
|---|---|---|
| **BLOCK** | Known-malicious package (deny-list or reputation), or Dredd BLOCK | **Fails the job** (error annotation) |
| **ADVISORY** | MCP server with a published CVE affecting this version | Warning |
| **REVIEW** | Not malicious, but this version has published vulnerabilities; or a suspicious reputation; or Dredd ALLOW without a dependency scan | Warning |
| **UNKNOWN** | Nothing was judged: server not in our catalog, unsupported source, API unreachable, rate limit, lookup cap | Warning that says **not a pass** |
| **ALLOW** | No known evidence against it | Nothing |

Inputs that change this:

- `fail-on: review` also fails on REVIEW and ADVISORY. `fail-on: none` reports only.
- `fail-on-unknown: true` fails when anything could not be judged.

### Read this before trusting a green check

- **ALLOW is not proof of safety.** It means our deny-list, the reputation signals and OSV hold nothing against that name and version today. A package published an hour ago by an attacker can look exactly like that.
- **UNKNOWN is not a pass**, and it is counted, annotated and listed in the summary every time. The default does not fail on it, because an unknown MCP server is common and a check that is always red gets switched off. If you want the strict posture, set `fail-on-unknown: true`.
- **A range is checked by name only.** `"express": "^4.18.0"` gets the malicious-package check but not the version vulnerability check. Commit your lockfile and the exact versions are checked.
- No check is perfect. We cap our own confidence at 95%: something in any verdict list will be wrong, and you should treat these verdicts as one input to a decision, not a guarantee.

## Inputs

| Input | Default | |
|---|---|---|
| `api-key` | none | Optional DugganUSA API key. Pass it from a secret. Sent only as `Authorization: Bearer`, never in a URL, masked in logs. |
| `fail-on` | `block` | `block`, `review` or `none` |
| `fail-on-unknown` | `false` | Fail when anything could not be judged |
| `mode` | `auto` | `auto` (diff on `pull_request`/`merge_group`, full otherwise), `diff`, `full` |
| `base-ref` | PR base SHA | Commit to diff against |
| `include-transitive` | `auto` | Lockfile transitives: yes in diff mode, no in full scans |
| `check-mcp` | `true` | Check MCP server configs with Dredd |
| `max-lookups` | `200` | Lookup cap per run; the rest are reported UNKNOWN |
| `rate-per-minute` | auto | Client-side pacing for package lookups (10/min keyless, 60/min keyed) |
| `max-wait-seconds` | `300` | Total time the run may wait out HTTP 429s |
| `working-directory` | `.` | Directory to scan |

## Outputs

`result` (`pass`/`fail`), `block-count`, `review-count` (REVIEW plus ADVISORY), `unknown-count`, `allow-count`, and `report-path`: a JSON file with every verdict, reason, evidence ID and, for Dredd, the response signature.

## Rate limits

The Action works without a key. Keyless package checks share the anonymous rate (currently 10 per minute and 50 per day per source IP), and GitHub-hosted runners share egress IPs with other users, so a large PR or a full scan can run out. The Action paces itself under the per-minute cap, waits out a per-minute 429, and reports anything it could not check as UNKNOWN. It never reports an unchecked package as a pass. A free account key raises the limits; see the pricing page at analytics.dugganusa.com/pricing.

## Privacy

The Action sends package names, versions, ecosystems and MCP server names to `analytics.dugganusa.com`. It does not send file contents, repository names or source code.

## Development

Zero runtime dependencies. `npm test` runs the unit and end-to-end tests against a local stub API (no network).

## License

MIT. Copyright (c) 2026 DugganUSA LLC.
