# Design

## Goals

- Produce certificates, CRLs and OCSP responses that look like the NG9-1-1 PCA PKI's, per the NG9-1-1 PKI
  Certificate Policy v1.3, so relying-party software can be developed and tested without production certificates.
- A hierarchy of any shape: one PCA root, Tier-2 and Tier-n ICAs, and any number of End-Entity certificates of every
  CP profile.
- Revocation testing: revoke End-Entity certificates and ICAs; publish, expire and withhold CRLs.
- **Independence from the software under test.** Certificates are encoded by OpenSSL. The checks are written from the
  CP text, not shared with any relying party. A bug in a shared library would otherwise confirm itself.

Out of scope: production use, key protection (keys are unencrypted files; the CP's HSM, ceremony and audit
requirements in §5–6 are not imitated), registration-authority workflows, and delta or indirect CRLs.

## Components

```text
            ┌──────────────┐  issue.cnf (profiles/*.ext + DN + URLs + Quad ID)
 user ────► │ bin/mockpca  │ ───────────────────────────────► openssl req / ca / crl / verify
            │   (bash)     │ ──► mockpca-lint (every certificate) ──► pass / fail
            └──────┬───────┘
                   │ writes
                   ▼
            PKI directory ── www/ ──────► mockpca-serve (HTTP) ──► relying parties
                          └─ ca/<ca>/ ──► /ocsp/<ca> ── openssl ocsp -reqin/-respout (per request)
```

- **OpenSSL** does all signing: certificates and CRLs (`openssl ca`) and OCSP responses (`openssl ocsp`). Its
  database (`index.txt`) is the record of issued and revoked certificates.
- **`bin/mockpca`** validates input, builds the per-issuance OpenSSL configuration, runs OpenSSL, runs the linter,
  and assembles chains and published files.
- **`mockpca-lint`** (`internal/lint`) checks a certificate against a CP profile. It reads the encoded extensions
  itself (criticality, exact key-usage bits, the otherName, DN string types) and uses `crypto/x509` only for parsing
  the envelope and verifying signatures.
- **`mockpca-serve`** serves `www/` read-only and is the HTTP front end of the OCSP responders (`internal/ocsp`). It
  does not sign anything itself.

Go code uses the standard library only. A new module needs the maintainers' approval (CLAUDE.md).

## PKI directory

```text
pki/
  pki.conf                     base_url, default country, crl_hours, next ICA OU serial
  trust/pca.pem                trust anchor (the PCA certificate)
  ca/<name>/
    ca.key ca.csr ca.pem       key (PKCS#8, 0600), request, certificate
    chain.pem                  this CA and its issuers up to, not including, the PCA (ICAs only)
    issue.cnf                  the exact OpenSSL configuration the certificate was issued with
    ca.conf                    profile, parent, tier, pathlen, iD, subject, Quad ID, subject values kept by a re-key,
                               re-keyed name (written once the lint passed)
    index.txt crlnumber newcerts/  openssl ca database
    crl.pem                    current CRL (PEM)
    ocsp/cert.pem key.pem      delegated OCSP responder certificate and key (+ csr.pem, issue.cnf)
    ocsp/rogue-*.pem           self-signed rogue signer for the wrong-signer fault (created on demand)
    ocsp.conf                  signer=delegated|ca (default delegated)
    ocsp-fault.conf            injected OCSP faults (read by mockpca-serve on every request)
  ee/<name>/
    key.pem csr.pem cert.pem   key (absent for sign-csr), request, certificate
    chain.pem fullchain.pem    issuing chain without the PCA; cert + chain
    issue.cnf ee.conf          issuance configuration; profile, issuing CA, iD, subject, Quad ID, renewed name
  rejected/<name>-<serial>/    certificates that failed the lint (revoked in their issuer's CRL)
  www/
    certs/<ca>.cer             DER CA certificates (caIssuers)
    crl/<ca>.crl               DER CRLs (cRLDistributionPoints)
```

`ca.conf`, `ee.conf` and `pki.conf` are `key=value` files that the script reads but never sources. Files in `www/`
are replaced atomically (written to a temporary file, then renamed), so the server never serves a partial CRL.

## URLs

The base URL is fixed at `init` and baked into every certificate:

| Extension | In | URL |
|---|---|---|
| `authorityInfoAccess` caIssuers | End-Entity | `<base>/certs/<issuing-ca>.cer` |
| `authorityInfoAccess` OCSP | ICA | `<base>/ocsp/<parent-ca>` |
| `authorityInfoAccess` OCSP | End-Entity | `<base>/ocsp/<issuing-ca>` |
| `cRLDistributionPoints` | ICA | `<base>/crl/<parent-ca>.crl` |
| `cRLDistributionPoints` | End-Entity | `<base>/crl/<issuing-ca>.crl` |

Changing the base URL means creating a new PKI. Pick a stable development name (`pca.mock.test`, resolved through
a hosts file or container DNS) rather than a temporary address.

## Issuance flow

1. Validate every input:
   - names, FQDNs, roles (no `/`, which delimits the Quad ID)
   - DN values: no characters that are special in OpenSSL config files, at most 64 characters
   - base URL: no commas, which separate AIA entries in OpenSSL syntax
   - CP rules that do not depend on OpenSSL: only ICAs issue End-Entity certificates (CP 1.4.1); the issuing CA and
     all its ancestors are not revoked; the subject DN and Quad ID are unique in the PKI (CP 3.1.5, 7.1.2.11),
     except for renewal and re-key: `issue --renew NAME` keeps NAME's subject DN and Quad ID, and `ica --renew NAME`
     keeps NAME's Quad ID, parent, subject values and pathLenConstraint with a new key and a new OU serial number,
     so its subject DN stays unique (3.1.5); for `sign-csr`, the CSR's key meets the profile (CP 6.1.6, Table 7)
   - build `mockpca-lint` before anything is signed
2. Write `issue.cnf`:
   - URL and pathLenConstraint variables in its default section
   - a `[req]` section with `string_mask = MASK:0x2002`, which gives PrintableString where possible and UTF8String
     otherwise (CP §3.1.1)
   - the profile's extension section from `profiles/<profile>.ext`
   - a `[mockpca_san]` section with the Quad ID `otherName` and the DNS/IP entries
3. Create a CSR (`issue`), or check the signature of a supplied one (`sign-csr`).
4. Sign with `openssl ca`:
   - the subject comes from `-subj`, never from the CSR, in the CP table order (`-preserveDN`; OpenSSL 3.0 ignores
     `preserve = yes` in the configuration file and would reorder the DN by the policy section)
   - extensions come from `issue.cnf`; `copy_extensions = none`
   - validity is capped at the issuer's notAfter
   - serials are random (`rand_serial`)
5. Run `mockpca-lint` (with the issuer and the PCA certificate). `openssl ca` has already recorded the certificate,
   so on failure it is revoked in the issuer's database (reason `superseded`), the issuer's CRL is republished, the
   certificate's directory moves to `rejected/<name>-<serial>/` (the name and Quad ID become free again) and the
   command fails. A failing PCA certificate in `init` removes the new PKI.
6. Only then write `ca.conf`/`ee.conf`, build `chain.pem` and `fullchain.pem`; for CAs, also publish
   `www/certs/<name>.cer` and an initial CRL.

Lesson from early prototypes: OpenSSL ignores configuration directives it does not know, without an error. One
prototype silently produced certificates without their AIA, CDP and policy extensions. That is why the lint step is
mandatory and cannot be skipped. (`preserve = yes` above is a second example: accepted and not applied.)

## Revocation and CRLs

- `revoke` marks the certificate in its issuer's `index.txt` and republishes that issuer's CRL at once. An ICA is
  revoked in its parent's CRL. The PCA cannot be revoked; remove it from trust bundles instead.
- CRLs are v2, with `authorityKeyIdentifier` and `cRLNumber`, no critical extensions, and are signed with SHA-256/RSA
  (CP §7.2, Table 39). The default lifetime is 24 hours (Table 3). `mockpca serve` republishes all CRLs every half
  lifetime, so served CRLs stay fresh. `crl --seconds N` makes short-lived CRLs for stale-CRL tests. Lifetimes over
  24 hours (`crl`) or republishing intervals over 24 hours (`serve --crl-hours` over 48) are allowed for testing and
  print a warning, because CP Table 3 requires a new CRL at least every 24 hours.
- Suspension (`certificateHold`) is not offered: the CP does not support it (4.9.13).
- A revoked CA, or a CA below a revoked ICA, cannot issue new certificates.
- `mockpca-serve` sends a strong ETag (SHA-256 of the file) and revalidates with `If-None-Match` only.
  `If-Modified-Since` is not used for 304 answers, because `http.ServeContent` compares it in whole seconds and would
  keep a client on a CRL republished within the same second.

## OCSP

Every CA answers OCSP at `<base>/ocsp/<ca>` (the URL in its certificates' AIA): an ICA for the End-Entity
certificates it issued, the PCA for the ICAs. `mockpca-serve` is only the front end:

1. **Decoding** (`internal/ocsp`): POST bodies (`application/ocsp-request`) and GET paths (RFC 6960 A.1) up to
   64 KiB. GET is strict (maintainer policy: the tool is a test target, so clients that do not follow the RFCs
   fail visibly instead of being worked around). RFC 9919 section 6 requires base64 per RFC 4648 section 4,
   nothing outside its alphabet, URL-encoded per RFC 3986, where `/` separates path segments and must be sent as
   `%2F`; RFC 4648 section 3.2 requires padding. An unescaped `/`, a missing padding, whitespace or non-zero padding
   bits are `malformedRequest`, with the reason logged; unescaped `+` and `=` are valid path characters and accepted.
   `/ocsp/` requests reach the responder before the ServeMux, whose path cleaning would otherwise redirect a request
   with `//` instead of answering it. The DER is parsed as an OCSPRequest with `encoding/asn1` (at most 32 CertIDs)
   before OpenSSL sees it. The built-in `openssl ocsp -port` server was not used: in tests with OpenSSL 3.0.13
   one malformed request terminated it, it answered from a stale index, and its own man page calls it a test tool.
2. **Signing**: one `openssl ocsp -index ca/<ca>/index.txt -CA ca/<ca>/ca.pem -rsigner … -rkey … -rmd sha256 -nmin N
   -reqin … -respout …` run per request, so the database is read fresh and revocations show at once. SHA-1 and
   SHA-256 CertIDs are answered (RFC 9919). The signer is the CA's delegated responder certificate (default) or the
   CA key (`ocsp-signer --mode ca`; CA certificates assert digitalSignature, CP Table 8).
3. **Limits**: at most 4 OpenSSL processes at once; waiting for a slot plus the run is bounded by 10 seconds
   (`tryLater` when no slot frees up, `internalError` when OpenSSL fails). Malformed requests get `malformedRequest`,
   requests for a CA the PKI does not have `unauthorized`. The server never crashes on input.
4. **Caching**: every signed response has thisUpdate and nextUpdate (`-nmin`, default 60 minutes). Its HTTP headers
   follow RFC 9919 sections 6 and 7.2 (RFC 5019 5, 6.2) and are taken from the signed response itself: Last-Modified
   is its thisUpdate, Expires its nextUpdate, `Cache-Control: max-age=<n>, public, no-transform, must-revalidate`
   with n ending at least a second before nextUpdate (0 once it has passed, as for a replayed stale response), and
   the ETag the hex SHA-256 of the response. Signed responses, faults included, never carry `no-cache` (RFC 9919
   7.2 forbids it for authoritative responses); unsigned error responses are sent with `Cache-Control: no-cache`. A
   signed response whose times cannot be read is not sent (`internalError`).
5. **Faults** (`ocsp-fault`): read from `ca/<ca>/ocsp-fault.conf` on every request, set only by the command, never
   by request input. HTTP status, delay (≤ 25 s), fixed unsigned error statuses, SHA-1 only (`unauthorized` for any
   other CertID hash, for RFC 9919 fallback clients), stale (the first response, valid for one minute, is replayed
   unchanged; the server keeps up to 1024 in memory), wrong signer (a self-signed rogue certificate outside the PKI),
   no nocheck (a negative fixture: a responder certificate issued by the CA itself but without
   `id-pkix-ocsp-nocheck`, from `profiles/negative-ocsp-responder-no-nocheck.ext`, made only on demand in
   `ca/<ca>/ocsp/negative-no-nocheck/` and reported by `mockpca-lint`, or the command fails; it tests whether clients
   reject such responses or check the responder's revocation status, RFC 6960 4.2.2.2.1) and unknown (OpenSSL
   answers from an empty database, so the response is properly signed).
6. **Responder certificates** (`profiles/ocsp-responder.ext`, CP-NOTES N21): issued with every CA (RSA 2048, 30 days,
   capped at the CA's notAfter), checked by `mockpca-lint -profile ocsp-responder`; `ocsp-signer --rotate` replaces one
   and revokes the old one; `mockpca serve` checks at least daily, independent of the CRL interval, and renews those
   that expire within 7 days.
7. **Stapling**: `ocsp-response --ee NAME` writes a fresh response signed the same way, for servers that load
   staples from files.

## Platforms

Tested: Linux. Expected to work but untested: macOS (bash ≥ 4.4 and OpenSSL 3 from a package manager). Windows users
run the tool under WSL; Git Bash is not supported (maintainer decision): its path conversion rewrites the `-subj`
arguments.

- The script avoids GNU-only tool flags.
- OpenSSL runs inside each CA's directory, and the CA configuration uses `dir = .`.
- `.gitattributes` keeps LF line endings for the script and the profiles, also in Windows checkouts used from WSL.
- `OPENSSL_CONF=/dev/null` keeps system OpenSSL configuration from changing results. Go tools are built into
  `.build/`, unless `MOCKPCA_LINT` and `MOCKPCA_SERVE` name prebuilt binaries.
- Container image (`Dockerfile`): Debian trixie-slim with Debian's OpenSSL 3 and bash, `bin/mockpca`, `profiles/`
  and `examples/` under `/opt/mockpca` (the repository layout the script expects), and `mockpca-lint` and
  `mockpca-serve` built in a separate Go stage, so the image has no Go toolchain. It runs as an unprivileged user
  (uid 10001) with the PKI in `/pki` (`MOCKPCA_PKI`). The image has no `VOLUME`, so `docker run` never creates an
  anonymous volume that would lose the PKI between commands. Base images are pinned by digest.

Only Linux has been tested so far. Running `scripts/e2e.sh` on macOS is an open task.

## Container image publishing

CI publishes `ghcr.io/hagan-consulting/mock-pca` after its checks pass (`.github/workflows/publish-image.yml`, called
from `ci.yml`): `edge` and `sha-<short commit>` on every push to `main`; `X.Y.Z`, `X.Y`, `latest` and `sha-<short
commit>` on a release tag `vX.Y.Z` (only on `main`, with a CHANGELOG section). Each architecture is built on a native
runner (`ubuntu-24.04`, `ubuntu-24.04-arm`) with BuildKit provenance (`mode=max`) and an SBOM, without caches, pushed
by digest and then smoke-tested by pulling that digest (`scripts/container-test.sh`); one index then combines both,
and `actions/attest` pushes a signed build provenance attestation for it (repository variable `ATTEST_IMAGES=false`
turns this off).

Every publish ends with `tools/ghcr-prune`, which applies this retention policy to the package:

| Version | Kept |
|---|---|
| Any tag other than `sha-*` (`X.Y.Z`, `X.Y`, `latest`, `edge`) | forever (`edge` until the next `main` build moves it) |
| Tagged only `sha-<commit>` (older `main` builds) | 14 days, then deleted by the next publish |
| Untagged, and neither an entry of a kept image index (platform images, attestation manifests) nor a referrer of a kept manifest (pushed attestations) | not kept: deleted by the same publish |

The prune works out the whole plan before deleting anything and stops with nothing deleted on any error (including a
manifest whose content does not match its digest, or a nested index it cannot protect) or when the plan has more than
100 deletions. It logs every version with its decision and reason, and the version ids of deletions, which GitHub
can restore for 30 days. Deleting needs the repository to have the Admin role on the package (package settings →
Manage Actions access). All publishes run one at a time across refs (concurrency group `ghcr-publish-mock-pca`,
`queue: max`), so the prune never sees another run's per-architecture images before they are combined. Pruning
runs only when something is published, so expired images stay until the next push to `main` or release tag. The
per-architecture tags of 0.1.0 (`0.1.0-amd64`, `0.1.0-arm64`) are not `sha-*` and are therefore kept; a maintainer
can delete them by hand.

The policy matches the one in the maintainers' other projects; `tools/ghcr-prune` is an independent implementation
(CLAUDE.md, independence rule).

## Security notes

- This is development tooling. Keys are unencrypted PKCS#8 files, created with `umask 077`.
- Generated material never enters the repository (`.gitignore`; tests use temporary directories).
- Mock material is easy to recognise: the default PCA organisation contains `MOCK … NOT FOR PRODUCTION`, and the
  examples use `.test` names (RFC 6761).
- Mock certificates carry the CP's real OIDs (policy `1.3.6.1.4.1.55670.1`, Quad ID `1.3.6.1.4.1.55670.1.1`) on
  purpose: relying parties check them, so certificates without them would not test anything. This does not make them
  valid in production: they chain only to a mock PCA root generated per PKI directory, which must never be added to a
  production trust bundle.
- `mockpca-serve`:
  - serves only names matching `<ca>.cer`/`<ca>.crl`, opened through `os.Root`, so symbolic links cannot escape
    `www/`
  - accepts GET/HEAD for files and GET/POST for OCSP, has timeouts on every server phase, and caps header size
  - OCSP: CA names are checked against the names `mockpca` creates before any path is built; requests are parsed
    before OpenSSL sees them and written to a private temporary directory; OpenSSL runs without a shell and with
    `OPENSSL_CONF=/dev/null`; the request decoder is fuzz-tested

## Planned

- Deliberately non-conforming certificates (negative test fixtures): expired, not yet valid, missing CDP/AIA, wrong
  policy, extKeyUsage on Agency certificates. Today `scripts/e2e.sh` builds one ad hoc to test the linter.
- Comparing the mock profiles with the published production PCA and ICA certificates (CP Table 1:
  ng911ioc.org/library) and recording differences in [CP-NOTES.md](CP-NOTES.md).
- macOS test runs.
- An independent CRL check in `mockpca-lint` (CRLs are checked with OpenSSL only today).
