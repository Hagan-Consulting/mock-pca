# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `bin/mockpca`: OpenSSL-based mock PCA: `init` (PCA root), `ica` (Tier-2/Tier-n ICAs), `issue` and `sign-csr`
  (Agency, Agent, Element, Service, Signing certificates per CP v1.3 with the Quad ID), `revoke`, `crl`, `verify`,
  `list`, `lint`, `serve`. Every issued certificate is checked by `mockpca-lint`.
- `bin/mockpca` enforces the CP by default: a certificate failing the lint is revoked and moved to `rejected/`; only
  ICAs issue End-Entity certificates; no issuance below a revoked CA; unique subject DNs and Quad IDs (`--renew` for
  renewal and re-key); `sign-csr` checks the CSR's key (CP 6.1.6); the iD is the first dNSName in every profile;
  subjects in CP table order; NIOC Agency Certificates may be owned by the PCA's iD; no `certificateHold`; warnings
  for CRL lifetimes and republishing intervals over 24 hours.
- `mockpca-lint` checks subject attribute order, ICA CN tier and OU serial numbers, End-Entities issued by the PCA,
  anyExtendedKeyUsage and the RSA exponent; `-root` accepts NIOC Agency Certificates.
- `mockpca-serve`: HTTP publication of CA certificates and CRLs at the URLs in the certificates (OCSP: 501, see #1),
  revalidated by a content ETag.
- Supported platforms: Linux and macOS; Windows through WSL (Git Bash is not supported).
- `examples/demo.sh` sample hierarchy, `scripts/e2e.sh` OpenSSL end-to-end test, design, profile and CP notes docs.
- `mockpca-lint`: checks certificates against the NG9-1-1 PKI CP v1.3 profiles (PCA, ICA, Agency, Agent, Element,
  Service, Signing): names and string types, key sizes, key usage, validity, every §7.1.2 extension and the Quad ID.
- Repository scaffold: Go module (standard library only), checks, CI and Dependabot configuration.
