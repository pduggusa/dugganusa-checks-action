# Changelog

## 1.3.0 - 2026-10-30

- **Run-on-open and install-time lures.** Pull requests are now checked for files that run code when a folder is opened or installed, which a dependency check never reads: npm install hooks (and `binding.gyp`) that fetch or evaluate code, a VS Code task set to run when the folder opens (also inside `.code-workspace`), agent hooks and helper commands in `.claude/settings.json`, dev container lifecycle commands (`initializeCommand` runs on the host), `yarnPath`, yarn plugins, `.pnpmfile.cjs`, a foreign npm registry and npm config keys that name a program. Local, no API call, bounded and linear. Only what a pull request adds or changes is reported, and a changed command is a new finding.
- New input `check-repo-lures` (default `true`). **Upgrade note:** a repository that already has, for example, a `postinstall` that downloads and runs a script will start failing a pull request that touches it under the default `fail-on: block`. Set `check-repo-lures: false` to defer.
- The same analyzer also runs as the `check-repo` MCP tool and a command line scanner (see the repository documentation). The analyzer was reviewed adversarially before release; two denial-of-service cases, output-injection paths and several ways to hide a lure were fixed.

## 1.2.2 - 2026-10-30

- **Performance fix:** the workflow-injection reader took about 10 seconds on a single 180 KB line of repeated colons and tags (an unanchored pattern). Lines are now capped and the pattern anchored; the same input runs in under a millisecond. A pathological workflow could stall a job's own check, never anything else.
- Detection hardening: block scalars with tags or anchors, `|2-` and `|-2` indicators, multi-line quoted and plain scalar continuations, and `if:` lines are no longer treated as data when they sit inside a scalar; a line is exempt only as a direct child of `env:` or `with:` or as a complete single-line `if:` condition. `run:` and `script:` values are never exempt.

## 1.2.1 - 2026-10-30

- Workflow injection check hardened after an independent review of 1.2.0: event fields are matched case-insensitively and in bracket form (`github.event.issue['title']`); whole-object and wildcard references (`toJSON(github.event.issue)`, `github.event.issue.*`) count as event text; a step the line-based parser cannot read (flow style, odd quoting) is reported as REVIEW `WFI-006` per line instead of passing silently; a second identical finding in a pull request diff is no longer collapsed into the first.

## 1.2.0 - 2026-10-30

- **Workflow script injection.** Workflow files are now checked for event text (an issue or pull request title or body, a comment, a branch name, a commit message) pasted into a `run:` script or `github-script` body, where the shell or JavaScript executes it. Also flagged: a privileged trigger that checks out the pull request head (BLOCK), an environment value re-evaluated by `eval`/`sh -c`/`source`, an external trigger with open permissions (REVIEW), and an AI agent action on a privileged trigger (advisory). Prompted by Radware's 2026-10-29 report of a campaign that hid shell commands in issue and pull request text across 61 repositories. Local, no API call, linear-time, bounded input.
- New input `check-workflow-injection` (default `true`). **Upgrade note:** a repository whose workflow has a genuinely injectable step will start failing under the default `fail-on: block`. Set `check-workflow-injection: false` to defer, but fixing it is the point: pass the value through `env:` and read it as `"$VAR"`.
- The findings table labels these rows "workflow injection" instead of "agent instructions".

## 1.1.2 - 2026-10-19

- A keyless run now shows a notice annotation and a summary link to a free API key, with the secret name to add. Nothing else changes: keyless runs still work at anonymous limits.
- README quickstart starts with the key: reuse an existing DugganUSA key (feed, API, MCP, Edge Shield; it's the same key), or get a free one.

## 1.1.1 (2026-10-18)

- `action.yml` description shortened to fit the GitHub Marketplace limit (125 characters). No behavior change.
- User-Agent is now `dugganusa-checks-action/1.1.1`.

## 1.1.0 (2026-10-18)

- **GitHub Actions are dependencies.** Workflows (`.github/workflows/*.yml`) and composite actions (`action.yml`) are read; each `uses: owner/repo@ref` is checked through check-package's new `github-actions` ecosystem. OSV does not evaluate version ranges for GitHub Actions, so the API evaluates them itself. A full-SHA pin is REVIEW when the action has published advisories (the 2025 tj-actions/changed-files compromise was malicious commits); floating `vX`/`vX.Y` tags are REVIEW; branch refs and `${{ }}` expressions are UNKNOWN, never skipped.
- **Agent instruction files.** `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, Copilot and Cursor rule files and `.claude` commands/agents/skills are scanned locally for invisible Unicode a model reads: zero-width, bidi overrides and isolates, stray variation selectors, and Unicode TAG characters (decoded in the report). BLOCK by default; a soft hyphen is REVIEW. No API call.
- check-package (server): a package whose every pre-record version is listed malicious now blocks unlisted later versions; a legitimate package compromised once stays scoped to its poisoned versions.
- User-Agent is now `dugganusa-checks-action/1.1.0`.

## 1.0.1 (2026-10-16)

- API calls (check-package and Dredd preflight) from a PUBLIC repository now send `x-dugganusa-repo`: the first 16 hex characters of the SHA-256 of the lowercase `GITHUB_REPOSITORY`, a stable key for a name that is already public. It lets the API count distinct adopting repositories and exclude DugganUSA's own CI. Private and internal repositories, and runs with a missing or unreadable event payload, send no marker (a short hash of a guessable name is reversible, so it is never sent for a non-public name).
- README: the Privacy section now lists everything the API receives (checked identifiers, `User-Agent`, the repository marker, the optional key).
- User-Agent is now `dugganusa-checks-action/1.0.1`.

## 1.0.0

- Initial Marketplace release.
