# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `mockpca-lint`: checks certificates against the NG9-1-1 PKI CP v1.3 profiles (PCA, ICA, Agency, Agent, Element,
  Service, Signing): names and string types, key sizes, key usage, validity, every §7.1.2 extension and the Quad ID.
- Repository scaffold: Go module (standard library only), checks, CI and Dependabot configuration.
