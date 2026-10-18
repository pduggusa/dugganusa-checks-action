# Changelog

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
