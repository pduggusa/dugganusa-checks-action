# Changelog

## 1.0.1 (2026-10-16)

- Every API call (check-package and Dredd preflight) now sends `x-dugganusa-repo`, an opaque repository marker: the first 16 hex characters of the SHA-256 of the lowercase `GITHUB_REPOSITORY`. It lets the API count distinct adopting repositories and exclude DugganUSA's own CI. The raw repository name is never sent; the header is omitted when `GITHUB_REPOSITORY` is unset.
- README: the Privacy section now lists everything the API receives (checked identifiers, `User-Agent`, the repository marker, the optional key).
- User-Agent is now `dugganusa-checks-action/1.0.1`.

## 1.0.0

- Initial Marketplace release.
