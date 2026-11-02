# mock-pca

[![CI](https://github.com/Hagan-Consulting/mock-pca/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Hagan-Consulting/mock-pca/actions/workflows/ci.yml)

Development-only tooling that imitates the NG9-1-1 PSAP Credentialing Agency (PCA) PKI: a mock PCA root, any number
of Intermediate CAs (ICAs), and Agency, Agent, Element, Service and Signing certificates built per the
**NG9-1-1 PKI Certificate Policy (CP) v1.3**, plus CRLs for revocation testing.

It lets NG9-1-1 relying-party software be tested against PCA-shaped certificates without buying production
certificates.

**Status:** pre-1.0 development tool. Commands, options and the PKI directory layout may still change between
releases (see [CHANGELOG.md](CHANGELOG.md)).

> **Not for production.** The certificates and keys are for development and testing only. Private keys are stored
> unencrypted on disk. Never add a mock PCA root to a production trust bundle. The default PCA organisation is
> `MOCK NG911 PCA - NOT FOR PRODUCTION`.

> **Not affiliated.** This is an independent project of Hagan Consulting Inc. It is not affiliated with, endorsed or
> certified by NENA, the NG9-1-1 Interoperability Oversight Commission (NIOC) or the PSAP Credentialing Agency. Their
> names are used only to describe what the tool imitates. The mock certificates carry the CP's real policy and Quad ID
> OIDs so that relying-party software accepts them; they are safe only because they chain to a separate mock root
> (see [docs/DESIGN.md](docs/DESIGN.md#security-notes)).

## What you get

- **`bin/mockpca`**: a bash front end over `openssl ca`:
  - creates the PCA root and the ICAs (Tier-2, Tier-n, with the CP's pathLenConstraint rules)
  - issues End-Entity certificates from generated keys or external CSRs
  - revokes certificates and publishes CRLs
  - verifies certificates with OpenSSL
- **Certificate profiles** (`profiles/`): one OpenSSL extension file per CP profile, mapped to the CP tables in
  [docs/PROFILES.md](docs/PROFILES.md). Each certificate gets:
  - the Quad ID `otherName` (`idType/iD/roles/owner`, OID `1.3.6.1.4.1.55670.1.1`)
  - the CP policy OID `1.3.6.1.4.1.55670.1`
  - CRL distribution point and AIA URLs
  - PrintableString/UTF8String DNs per CP §3.1.1
- **`mockpca-lint`**: an independent Go checker that every issued certificate passes before it is handed out. It also
  works on certificates from other sources, e.g. a real PCA certificate.
- **`mockpca-serve`**: serves the CA certificates (`caIssuers`) and CRLs (`cRLDistributionPoints`) over HTTP, and
  answers OCSP at the AIA URL of every CA (`<base>/ocsp/<ca>`, GET and POST, SHA-1 and SHA-256 CertIDs). GET
  requests must follow RFC 9919 strictly (`/` sent as `%2F`, base64 padding present); others get
  `malformedRequest`, because this is a test target and broken clients should fail visibly. Each OCSP
  response is signed by OpenSSL from the CA's current database, so revocations show at once. Every CA has a delegated
  responder certificate (or signs with its own key), and faults can be injected per CA for relying-party tests.
  `mockpca serve` runs it, republishes the CRLs before they go stale and renews responder certificates.

## Requirements

| Tool | Version | Notes |
|---|---|---|
| bash | ≥ 4.4 | macOS ships 3.2: install a current bash from a package manager |
| OpenSSL | ≥ 3.0 | LibreSSL (macOS `/usr/bin/openssl`) is not supported; set `OPENSSL=/path/to/openssl` if needed |
| Go | 1.27.3 (`go.mod`) | builds `mockpca-lint` and `mockpca-serve` from this checkout on first use |
| curl | any | only for `scripts/e2e.sh` |

Platforms: Linux is tested. macOS (bash ≥ 4.4 and OpenSSL 3 from a package manager) is expected to work but untested;
reports are welcome. On Windows, use WSL; Git Bash is not supported. See [docs/DESIGN.md](docs/DESIGN.md#platforms).

## Quick start

```bash
examples/demo.sh
```

```bash
bin/mockpca serve --listen 127.0.0.1:8080
```

`examples/demo.sh` creates `./pki` with this hierarchy: PCA → `state` (Tier-2) → `county` (Tier-3), and PCA →
`region` (Tier-2). It issues one certificate per profile. The URLs in the certificates use
`http://pca.mock.test:8080` by default, so make that name resolve to the machine running `mockpca serve`, for example
with a hosts-file entry `127.0.0.1 pca.mock.test`. Or set the base URL before running the demo:

```bash
BASE_URL=http://127.0.0.1:8080 examples/demo.sh
```

Using the result with relying-party software:

| Purpose | File |
|---|---|
| PCA trust bundle (client CA file, CA file) | `pki/trust/pca.pem` |
| Server/client certificate chain | `pki/ee/<name>/fullchain.pem` |
| Private key | `pki/ee/<name>/key.pem` |
| Certificate only / issuing chain | `pki/ee/<name>/cert.pem`, `pki/ee/<name>/chain.pem` |

## Commands

```text
mockpca [--pki DIR] COMMAND [options]       (PKI directory: --pki, else $MOCKPCA_PKI, else ./pki)
```

| Command | Purpose |
|---|---|
| `init --base-url URL --id FQDN` | Create the PKI directory and the PCA root (RSA 4096, 10 years). `--org`, `--country`, `--cn`, `--ou-serial`, `--days`. |
| `ica --name N --parent CA --id FQDN --owner AGENCY_ID --org ORG --label LABEL` | Create an ICA (RSA 3072, ≤ 3 years). CN becomes `<LABEL> ICA Tier<n>`. `--pathlen` (Tier-2: 0–3, default 1; Tier-n: the issuer's minus one), `--st`, `--l`, `--country`, `--ou-serial`, `--days`. |
| `ica --name N --renew OLD [--days D] [--ou-serial S]` | Re-key ICA `OLD` (CP 3.1.5): new key and a new `OU=ICA-<serial>`, so the subject DN stays unique. Quad ID, parent, O, C, ST, L, label (hence the CN) and pathLenConstraint are kept; options that differ from `OLD` are refused. The new ICA gets its own directory, CRL and published certificate; `OLD` stays until it is revoked or expires. |
| `issue --ca CA --profile P --name N --id ID --roles R1,R2 --org ORG` | Generate a key and issue an End-Entity certificate. Profiles: `agency`, `agent`, `element`, `service`, `signing`. `--owner` (required except for agency), `--dns` and `--ip` (repeatable), `--ou`, `--st`, `--l`, `--country`, `--days` (default 90), `--key rsa:2048\|rsa:3072\|rsa:4096\|ec:P-256\|ec:P-384\|ec:P-521`, `--id-type` (signing only), `--renew NAME` (renewal or re-key of NAME: same subject DN and Quad ID). Only ICAs issue End-Entity certificates. |
| `sign-csr … --csr FILE` | Like `issue`, for a key generated elsewhere (the CP has Subscribers generate their own keys). The CA sets subject and extensions; nothing is copied from the CSR. The CSR's key must meet the profile (CP 6.1.6, Table 7). |
| `revoke --ee N \| --ca N [--reason R]` | Revoke an End-Entity certificate or an ICA and republish the issuer's CRL. Reasons: `unspecified`, `keyCompromise`, `CACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` (no `certificateHold`: the CP does not support suspension, 4.9.13). |
| `crl --ca N \| --all [--hours H \| --seconds S]` | Regenerate CRLs (default lifetime 24 h, CP Table 3). Short lifetimes produce stale CRLs for testing. Longer than 24 h is allowed for testing, with a warning. |
| `verify --ee N \| --ca N [--no-crl]` | `openssl verify` with `-x509_strict`, the CP policy OID (`-explicit_policy`) and all CRLs. |
| `list` | All CAs and certificates with status (V valid, R revoked, E expired). |
| `lint [flags] FILE…` | Run `mockpca-lint`. |
| `serve [--listen ADDR] [--crl-hours H] [--ocsp-nmin M]` | Serve `pki/www` and OCSP; republish CRLs every H/2 hours and, at least daily, renew responder certificates that expire within 7 days. More than 48 hours (republishing less often than daily, CP Table 3) is allowed for testing, with a warning. OCSP responses are valid for M minutes (default 60). |
| `ocsp-signer --ca N [--mode delegated\|ca] [--rotate] [--days D]` | Choose who signs the CA's OCSP responses: its delegated responder certificate (default; issued with the CA, in `ca/N/ocsp/`) or the CA key. `--rotate` issues a new responder certificate (default 30 days) and revokes the old one. |
| `ocsp-fault --ca N …` | Fault injection for the CA's responder; each call replaces the CA's faults. `--http-status N`, `--delay-ms N`, `--status unauthorized\|malformedRequest\|tryLater\|internalError`, `--sha1-only` (SHA-256 CertIDs get `unauthorized`), `--stale` (a response is replayed unchanged; past its nextUpdate after a minute), `--wrong-signer` (signed by a self-signed rogue certificate), `--no-nocheck` (signed by a negative fixture: a responder certificate issued by the CA but without `id-pkix-ocsp-nocheck`, made on demand in `ca/N/ocsp/negative-no-nocheck/` and reported by `mockpca-lint`), `--unknown` (every serial unknown); `--show`, `--clear`. |
| `ocsp-response --ee N [--out FILE] [--nmin M]` | Write a fresh DER OCSP response for a certificate (default `ee/N/ocsp.der`), e.g. as a staple. |

By default the tool does not produce CP violations. It enforces:
- Every certificate passes `mockpca-lint`. One that fails is revoked in its issuer's CRL and moved to `pki/rejected/`;
  nothing usable is left behind.
- Only ICAs issue End-Entity certificates (CP 1.4.1). A revoked CA, or a CA below a revoked ICA, cannot issue.
- Subject DNs and Quad IDs are unique in the PKI (CP 3.1.5, 7.1.2.11). Renewal and re-key are the exception:
  `issue --renew` keeps subject DN and Quad ID, `ica --renew` keeps the Quad ID and gets a new OU serial number.
- The Quad ID iD is also the subject CN, so it can be at most 64 characters (RFC 5280).
- The iD is the first dNSName: always for Agency, Element and Service certificates, and for Agent and Signing
  certificates when they have dNSNames (CP Table 30). An agent iD of the form `user@fqdn` therefore cannot have any.
- An Agency certificate's owner is its own iD, or the PCA's iD for a NIOC Agency Certificate (CP Table 28).
- Subject attributes are in the CP table order (C, O, OU, ST, L, CN for ICAs; C, O, L, ST, OU, CN for End-Entities).
- Validity is capped at the issuer's notAfter.

### Revocation testing recipes

| Scenario | How |
|---|---|
| Revoked End-Entity certificate | `bin/mockpca revoke --ee bcf --reason keyCompromise` |
| Revoked ICA (whole branch) | `bin/mockpca revoke --ca county --reason CACompromise` |
| Stale CRL (past `nextUpdate`) | `bin/mockpca crl --ca county --seconds 60` and wait a minute. A running `mockpca serve` republishes only every `--crl-hours`/2, but restarting it republishes all CRLs |
| Unreachable distribution point | Stop `mockpca serve` |
| Fresh CRLs again | `bin/mockpca crl --all` |
| OCSP `revoked` | `revoke` as above; the next OCSP answer shows it (no republishing needed) |
| OCSP responder down or slow | `bin/mockpca ocsp-fault --ca county --http-status 503` or `--delay-ms 5000` |
| OCSP `unknown`, error statuses, SHA-1-only responder, stale or wrongly signed responses | `bin/mockpca ocsp-fault --ca county --unknown` (or `--status tryLater`, `--sha1-only`, `--stale`, `--wrong-signer`); `--clear` ends it |
| Responder certificate without `id-pkix-ocsp-nocheck` (does the client reject it, or check the responder's revocation?) | `bin/mockpca ocsp-fault --ca county --no-nocheck` |

## Linting certificates from anywhere

```bash
bin/mockpca lint -issuer issuing-ca.pem cert.pem
```

```bash
bin/mockpca lint -root pki/trust/pca.pem fullchain.pem
```

- The profile is detected from the Quad ID, or given with `-profile`.
- With a full chain, the second certificate is used as the issuer.
- `-root` gives the PCA certificate, which lets the linter accept NIOC Agency Certificates (owner = the PCA's iD).
- Findings name the CP section/table. `ERROR` is a violated SHALL/MUST. `WARN` is a SHOULD, or content outside the
  CP profile.
- Exit status: 1 on errors (or on warnings with `-strict`), 2 on usage errors.

## Repository layout

```text
bin/mockpca            bash CLI (OpenSSL)
profiles/              ca.cnf (shared CA config) and one *.ext per CP profile
cmd/mockpca-lint       profile checker (Go, standard library)
cmd/mockpca-serve      HTTP publication of CA certificates and CRLs, OCSP (Go, standard library)
internal/lint          lint rules
internal/ocsp          OCSP request decoding, fault injection, OpenSSL signing
examples/demo.sh       sample hierarchy
scripts/check.sh       gofmt, go vet, go test -race, bash -n
scripts/e2e.sh         OpenSSL end-to-end test
docs/                  DESIGN.md, PROFILES.md, CP-NOTES.md
```

The generated PKI directory is described in [docs/DESIGN.md](docs/DESIGN.md#pki-directory).

## Development

```bash
scripts/check.sh
```

```bash
scripts/e2e.sh
```

How to contribute, and the rules for changes, are in [CONTRIBUTING.md](CONTRIBUTING.md) (coding agents:
[CLAUDE.md](CLAUDE.md)). The most important rule: this repository stays independent of the software it is used to
test. No code is shared with any relying party. Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

Report security vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Hagan Consulting Inc. Licensed under the [Apache License, Version 2.0](LICENSE); see also
[NOTICE](NOTICE).
