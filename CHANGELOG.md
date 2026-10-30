# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `bin/mockpca`: OpenSSL-based mock PCA: `init` (PCA root), `ica` (Tier-2/Tier-n ICAs), `issue` and `sign-csr`
  (Agency, Agent, Element, Service, Signing certificates per CP v1.3 with the Quad ID), `revoke`, `crl`, `verify`,
  `list`, `lint`, `serve`. Every issued certificate is checked by `mockpca-lint`.
- `mockpca-serve`: HTTP publication of CA certificates and CRLs at the URLs in the certificates (OCSP: 501, see #1).
- `examples/demo.sh` sample hierarchy, `scripts/e2e.sh` OpenSSL end-to-end test, design, profile and CP notes docs.
- `mockpca-lint`: checks certificates against the NG9-1-1 PKI CP v1.3 profiles (PCA, ICA, Agency, Agent, Element,
  Service, Signing): names and string types, key sizes, key usage, validity, every §7.1.2 extension and the Quad ID.
- Repository scaffold: Go module (standard library only), checks, CI and Dependabot configuration.
