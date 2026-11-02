# Contributing to mock-pca

Thank you for helping. mock-pca is a development-only mock of the NG9-1-1 PCA PKI (see [README.md](README.md)). This
file covers how to propose changes; the design is in [docs/DESIGN.md](docs/DESIGN.md), the certificate profiles in
[docs/PROFILES.md](docs/PROFILES.md) and our reading of unclear CP text in [docs/CP-NOTES.md](docs/CP-NOTES.md).

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems are not reported
in public issues: see [SECURITY.md](SECURITY.md).

## Issues

- **Bugs:** include your OS, `openssl version`, `bash --version`, `go version`, the command you ran and its output.
- **CP interpretation:** name the CP v1.3 section or table, the CP-NOTES entry (N-number) if there is one, and the
  reading you propose. Production certificates that differ from our profiles are especially useful.
- **Features:** describe the relying-party test you want to make possible.

## Development setup

| Tool | Version |
|---|---|
| Go | 1.27.3 (`go.mod`) |
| OpenSSL | ≥ 3.0 (not LibreSSL) |
| bash | ≥ 4.4 |
| curl | any (end-to-end test) |

Before opening a pull request, run both:

```bash
scripts/check.sh
```

```bash
scripts/e2e.sh
```

`check.sh` runs gofmt, `go vet`, `go test -race` (when cgo is available), `bash -n`, shellcheck (when installed; CI
uses the version pinned in `.github/workflows/ci.yml`) and the `bin/mockpca` unit tests.
`e2e.sh` builds a full mock PKI with OpenSSL in a temporary directory and checks issuance, linting, CRLs and OCSP.

## Rules

These keep the tool trustworthy as a test target. The full list, also used by coding agents, is in
[CLAUDE.md](CLAUDE.md).

- **Independence.** Never import, copy or vendor code from software this repository is used to test. An independent
  implementation is the point: a bug shared with the software under test would hide itself.
- **OpenSSL issues, Go checks.** Certificates, CSRs and CRLs are produced by OpenSSL (`bin/mockpca`, `profiles/`). Go
  code (`cmd/`, `internal/`) only checks and serves, and never issues certificates.
- **Go standard library only.** A new module (including `golang.org/x/...`) needs the maintainers' approval in an
  issue first.
- **The lint is mandatory.** Every certificate the tool issues passes `mockpca-lint`; do not add a way to skip it.
  Deliberately non-conforming certificates are negative test fixtures: explicit, named as such, and still reported by
  the linter.
- **Never commit generated PKI material:** keys, CSRs, certificates, CRLs, `pki/` directories. Tests create their
  material in temporary directories.
- **Recognisable mock material:** the default PCA organisation contains `MOCK` and `NOT FOR PRODUCTION`; examples use
  names under `.test` (RFC 6761).
- **Supply chain:** GitHub Actions pinned to full commit SHAs, tools to exact versions, no floating tags; workflows
  keep `permissions: {}` at the top and minimal per-job permissions. Never disable TLS, checksum or signature checks.
- **CP citations:** name the CP v1.3 section or table for every profile rule. A new interpretation of unclear CP text
  gets an entry in `docs/CP-NOTES.md`.

## Pull requests

- Changes reach `main` only through pull requests.
- Keep commits small and logical (one feature or fix with its tests and docs), with an imperative summary line.
- User-visible changes get a one-line entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md)
  ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)).
- Update README.md and the docs in the same pull request when behaviour changes.
- CI on pull requests from first-time contributors may wait for a maintainer's approval.

## License of contributions

mock-pca is licensed under the [Apache License 2.0](LICENSE). Unless you explicitly state otherwise, any contribution
you intentionally submit for inclusion is licensed under the same terms (section 5 of the license), without any
additional terms or conditions.
