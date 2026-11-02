# mock-pca — agent guide

Guide for coding agents working in this repository. Human contributors follow the same hard rules and conventions.

Development-only mock of the NG9-1-1 PCA PKI. Start with `README.md`, then `docs/DESIGN.md` (architecture and
decisions), `docs/PROFILES.md` (certificate profiles vs. the CP tables) and `docs/CP-NOTES.md` (CP ambiguities and our
interpretation). The normative source is the NG9-1-1 PKI Certificate Policy (CP) v1.3; it is not included in this
repository.

## Hard rules
- **Independence:** this repository is used to test NG9-1-1 relying-party software. Never import, copy or vendor code
  from software it is used to test; an independent implementation is the point (a shared bug would hide itself).
- Certificates, CSRs and CRLs are produced by **OpenSSL ≥ 3.0** (`bin/mockpca`, `profiles/`). Go code (`cmd/`,
  `internal/`) only checks, serves and (later) answers OCSP; it never issues certificates.
- Go 1.27.3, module `github.com/hagan-consulting/mock-pca`, **standard library only**. Adding any module (including
  `golang.org/x/...`) needs the maintainers' approval first.
- Never commit generated PKI material: private keys, CSRs, certificates, CRLs, `pki/` directories. `.gitignore`
  covers the defaults; test material is created in temporary directories at test time.
- Every certificate the tool issues is checked by `mockpca-lint` against the CP profile. Do not add a way to skip the
  lint for normal issuance. Deliberately non-conforming certificates (negative test fixtures) must be explicit,
  named as such, and still reported by the linter.
- Mock material must stay recognisable: the default PCA organisation contains `MOCK` and `NOT FOR PRODUCTION`, and
  examples use names under `.test` (RFC 6761).

## Supply-chain integrity (critical)
These tools produce test credentials for emergency-services (NG9-1-1) software; treat every third-party input as an
attack surface.
- Pin GitHub Actions to full 40-char commit SHAs (`uses: owner/repo@<sha> # vX.Y.Z`), container images by `@sha256:`
  digest, Go tools by exact version. Never a branch, `latest` or a floating tag. Resolve SHAs/digests from the upstream
  source yourself and only adopt releases public for at least a week.
- Tools downloaded in CI (e.g. ShellCheck) are pinned by exact version and SHA-256, checked with `sha256sum -c`. Where
  upstream publishes no checksum, take the digest from a second independent source as well, and record both in the
  workflow comment. Dependabot does not update these pins; update them by hand under the same rules.
- Workflows: top-level `permissions: {}`, minimal per-job permissions, `persist-credentials: false` on checkout, no
  `pull_request_target`, no untrusted `${{ }}` expressions inside `run:` scripts, no secrets in PR-triggered jobs.
- Never disable TLS verification, checksum or signature checks to make something work; stop and ask instead.

## Conventions
- `bin/mockpca` is a single bash script (bash ≥ 4.4, `set -euo pipefail`). It must run on Linux and macOS (with
  OpenSSL 3 from a package manager, not the system LibreSSL); Windows users run it under WSL (Git Bash is not
  supported). No GNU-only tool flags. Extensions go through generated config files; subject DNs are passed with
  `-subj` (the only way to set the subject of an external CSR), and every DN value is validated (`check_dn`) and
  escaped (`subj_escape`). Validate every user input before it reaches OpenSSL (no newlines, no `/` in Quad ID
  fields).
- OpenSSL ignores configuration it does not know or apply without an error (seen twice: an unknown directive, and
  `preserve = yes` in `openssl ca`). Prefer command-line flags for behaviour that matters, and cover it with an e2e
  check.
- Go: small packages, `context.Context` first on I/O, errors wrapped with `%w`, `log/slog` for logging, timeouts on
  every server. Tests: stdlib `testing`, table-driven, `t.Parallel()` where safe, `httptest`.
- Verify before committing: `scripts/check.sh` (gofmt, `go vet`, `go test -race ./...`) and `scripts/e2e.sh`
  (OpenSSL end-to-end run, needs `openssl` ≥ 3.0 and `curl`).

## Committing
- Small, logical commits (one feature or fix with its tests and docs). Imperative summary line, optional body. Commits
  made by a coding agent end with a `Co-Authored-By:` trailer naming the agent (for Claude:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`); human commits need no trailer.
- Stage explicit paths only (`git add <paths>`), never `git add -A`.
- User-visible changes get a one-line entry under `## [Unreleased]` in `CHANGELOG.md` (Keep a Changelog).
- Changes reach `main` through pull requests; never push to `main` directly or force-push a shared branch.
