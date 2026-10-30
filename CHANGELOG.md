# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `bin/mockpca`: OpenSSL-based mock PCA: `init` (PCA root), `ica` (Tier-2/Tier-n ICAs, re-key with `--renew`),
  `issue` and `sign-csr` (Agency, Agent, Element, Service, Signing certificates per CP v1.3 with the Quad ID),
  `revoke`, `crl`, `verify`, `list`, `lint`, `serve`. It enforces the CP by default: every issued certificate must
  pass `mockpca-lint` (a failing one is revoked and moved to `rejected/`); only ICAs issue End-Entity certificates;
  no issuance below a revoked CA; unique subject DNs and Quad IDs (`--renew` for renewal and re-key); `sign-csr`
  checks the CSR's key (CP 6.1.6); the iD is the first dNSName; subjects in CP table order; NIOC Agency Certificates
  may be owned by the PCA's iD; no `certificateHold`; warnings for CRL lifetimes and republishing intervals over
  24 hours.
- `mockpca-lint`: checks certificates against the NG9-1-1 PKI CP v1.3 profiles (PCA, ICA, Agency, Agent, Element,
  Service, Signing): names, string types and attribute order, ICA tier and OU serial numbers, key sizes and RSA
  exponent, key usage and extKeyUsage, validity, every §7.1.2 extension, the Quad ID, and (given the issuer)
  signature, AKI, nesting and End-Entities issued by the PCA; `-root` accepts NIOC Agency Certificates.
- `mockpca-serve`: HTTP publication of CA certificates and CRLs at the URLs in the certificates, revalidated by a
  content ETag.
- OCSP responders for every mock CA (#1): `mockpca-serve -pki` answers GET and POST at `/ocsp/<ca>` (SHA-1 and
  SHA-256 CertIDs, responses signed by OpenSSL per request, RFC 5019 caching headers); delegated responder
  certificates issued with every CA (`ocsp-responder` profile, also in `mockpca-lint`) or CA-signed responses
  (`mockpca ocsp-signer`); fault injection per CA (`mockpca ocsp-fault`); stapling files (`mockpca ocsp-response`).
- `examples/demo.sh` sample hierarchy, `scripts/e2e.sh` OpenSSL end-to-end test, design, profile and CP notes docs.
- Repository scaffold: Go module (standard library only), checks, CI and Dependabot configuration. Supported
  platforms: Linux and macOS; Windows through WSL (Git Bash is not supported).
