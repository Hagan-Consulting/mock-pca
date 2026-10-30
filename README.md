# mock-pca

Development-only tooling that imitates the NG9-1-1 PSAP Credentialing Agency (PCA) PKI: a mock PCA root, any number
of Intermediate CAs (ICAs), and Agency, Agent, Element, Service and Signing certificates built per the
**NG9-1-1 PKI Certificate Policy (CP) v1.3**, plus CRLs for revocation testing.

It lets NG9-1-1 software (for example the Service/Agency Locator) be tested against PCA-shaped certificates without
buying production certificates.

> **Not for production.** The certificates and keys are for development and testing only. Private keys are stored
> unencrypted on disk. Never add a mock PCA root to a production trust bundle. The default PCA organisation is
> `MOCK NG911 PCA - NOT FOR PRODUCTION`.

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
- **`mockpca-serve`**: serves the CA certificates (`caIssuers`) and CRLs (`cRLDistributionPoints`) over HTTP.
  `mockpca serve` runs it and republishes the CRLs before they go stale.

OCSP is planned, not built yet: [#1](https://github.com/Hagan-Consulting/mock-pca/issues/1). Certificates already
carry the OCSP URL the CP requires. Until then, `mockpca-serve` answers `501 Not Implemented` there, so relying parties
see an OCSP failure and fall back to CRLs.

## Requirements

| Tool | Version | Notes |
|---|---|---|
| bash | ≥ 4.4 | macOS ships 3.2: install a current bash from a package manager |
| OpenSSL | ≥ 3.0 | LibreSSL (macOS `/usr/bin/openssl`) is not supported; set `OPENSSL=/path/to/openssl` if needed |
| Go | 1.27.3 (`go.mod`) | builds `mockpca-lint` and `mockpca-serve` from this checkout on first use |
| curl | any | only for `scripts/e2e.sh` |

Tested on Linux. macOS (Homebrew bash and OpenSSL) and Windows Git Bash are intended to work but have not been
tested yet; see [docs/DESIGN.md](docs/DESIGN.md#platforms).

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

Using the result with relying-party software, e.g. the Service/Agency Locator:

| Purpose | File |
|---|---|
| PCA trust bundle (`client-ca-file`, `sal-cli -ca-file`) | `pki/trust/pca.pem` |
| Server/client certificate chain (`tls-cert-file`, `-cert-file`) | `pki/ee/<name>/fullchain.pem` |
| Private key (`tls-key-file`, `-key-file`) | `pki/ee/<name>/key.pem` |
| Certificate only / issuing chain | `pki/ee/<name>/cert.pem`, `pki/ee/<name>/chain.pem` |

## Commands

```text
mockpca [--pki DIR] COMMAND [options]       (PKI directory: --pki, else $MOCKPCA_PKI, else ./pki)
```

| Command | Purpose |
|---|---|
| `init --base-url URL --id FQDN` | Create the PKI directory and the PCA root (RSA 4096, 10 years). `--org`, `--country`, `--cn`, `--ou-serial`, `--days`. |
| `ica --name N --parent CA --id FQDN --owner AGENCY_ID --org ORG --label LABEL` | Create an ICA (RSA 3072, ≤ 3 years). CN becomes `<LABEL> ICA Tier<n>`. `--pathlen` (Tier-2: 0–3, default 1; Tier-n: the issuer's minus one), `--st`, `--l`, `--country`, `--ou-serial`, `--days`. |
| `issue --ca CA --profile P --name N --id ID --roles R1,R2 --org ORG` | Generate a key and issue an End-Entity certificate. Profiles: `agency`, `agent`, `element`, `service`, `signing`. `--owner` (required except for agency), `--dns` and `--ip` (repeatable), `--ou`, `--st`, `--l`, `--country`, `--days` (default 90), `--key rsa:2048\|rsa:3072\|rsa:4096\|ec:P-256\|ec:P-384\|ec:P-521`, `--id-type` (signing only). |
| `sign-csr … --csr FILE` | Like `issue`, for a key generated elsewhere (the CP has Subscribers generate their own keys). The CA sets subject and extensions; nothing is copied from the CSR. |
| `revoke --ee N \| --ca N [--reason R]` | Revoke an End-Entity certificate or an ICA and republish the issuer's CRL. |
| `crl --ca N \| --all [--hours H \| --seconds S]` | Regenerate CRLs (default lifetime 24 h, CP Table 3). Short lifetimes produce stale CRLs for testing. |
| `verify --ee N \| --ca N [--no-crl]` | `openssl verify` with `-x509_strict`, the CP policy OID (`-explicit_policy`) and all CRLs. |
| `list` | All CAs and certificates with status (V valid, R revoked, E expired). |
| `lint [flags] FILE…` | Run `mockpca-lint`. |
| `serve [--listen ADDR] [--crl-hours H]` | Serve `pki/www` and republish CRLs every H/2 hours. |

Rules the tool enforces:
- The Quad ID iD is also the subject CN, so it can be at most 64 characters (RFC 5280).
- Agency, Element and Service certificates always get the iD as their first dNSName (CP Table 30).
- An Agency certificate's owner is its own iD (CP Table 28).
- Validity is capped at the issuer's notAfter.

### Revocation testing recipes

| Scenario | How |
|---|---|
| Revoked End-Entity certificate | `bin/mockpca revoke --ee sal --reason keyCompromise` |
| Revoked ICA (whole branch) | `bin/mockpca revoke --ca county --reason CACompromise` |
| Stale CRL (past `nextUpdate`) | `bin/mockpca crl --ca county --seconds 60` and wait a minute. A running `mockpca serve` republishes only every `--crl-hours`/2, but restarting it republishes all CRLs |
| Unreachable distribution point | Stop `mockpca serve` |
| Fresh CRLs again | `bin/mockpca crl --all` |

## Linting certificates from anywhere

```bash
bin/mockpca lint -issuer issuing-ca.pem cert.pem
```

```bash
bin/mockpca lint fullchain.pem
```

- The profile is detected from the Quad ID, or given with `-profile`.
- With a full chain, the second certificate is used as the issuer.
- Findings name the CP section/table. `ERROR` is a violated SHALL/MUST. `WARN` is a SHOULD, or content outside the
  CP profile.
- Exit status: 1 on errors (or on warnings with `-strict`), 2 on usage errors.

## Repository layout

```text
bin/mockpca            bash CLI (OpenSSL)
profiles/              ca.cnf (shared CA config) and one *.ext per CP profile
cmd/mockpca-lint       profile checker (Go, standard library)
cmd/mockpca-serve      HTTP publication of CA certificates and CRLs (Go, standard library)
internal/lint          lint rules
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

Rules for contributors (and coding agents) are in [CLAUDE.md](CLAUDE.md). The most important one: this repository
stays independent of the software it is used to test. No code is shared with the Service/Agency Locator.
