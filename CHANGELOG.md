# Changelog

## 1.0.1 (2026-10-16)

- API calls (check-package and Dredd preflight) from a PUBLIC repository now send `x-dugganusa-repo`: the first 16 hex characters of the SHA-256 of the lowercase `GITHUB_REPOSITORY`, a stable key for a name that is already public. It lets the API count distinct adopting repositories and exclude DugganUSA's own CI. Private and internal repositories, and runs with a missing or unreadable event payload, send no marker (a short hash of a guessable name is reversible, so it is never sent for a non-public name).
- README: the Privacy section now lists everything the API receives (checked identifiers, `User-Agent`, the repository marker, the optional key).
- User-Agent is now `dugganusa-checks-action/1.0.1`.

## 1.0.0

- Initial Marketplace release.
