# Design

## Goals

- Produce certificates, CRLs and (later) OCSP responses that look like the NG9-1-1 PCA PKI's, per the NG9-1-1 PKI
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
            PKI directory ── www/ ──► mockpca-serve (HTTP) ──► relying parties
```

- **OpenSSL** (`openssl ca`) does all signing: certificates, CRLs and, in future, OCSP responses (#1). Its database
  (`index.txt`) is the record of issued and revoked certificates.
- **`bin/mockpca`** validates input, builds the per-issuance OpenSSL configuration, runs OpenSSL, runs the linter,
  and assembles chains and published files.
- **`mockpca-lint`** (`internal/lint`) checks a certificate against a CP profile. It reads the encoded extensions
  itself (criticality, exact key-usage bits, the otherName, DN string types) and uses `crypto/x509` only for parsing
  the envelope and verifying signatures.
- **`mockpca-serve`** serves `www/` read-only. It does not sign anything.

Go code uses the standard library only. A new module needs the product owner's approval (CLAUDE.md).

## PKI directory

```text
pki/
  pki.conf                     base_url, default country, crl_hours, next ICA OU serial
  trust/pca.pem                trust anchor (the PCA certificate)
  ca/<name>/
    ca.key ca.csr ca.pem       key (PKCS#8, 0600), request, certificate
    chain.pem                  this CA and its issuers up to, not including, the PCA (ICAs only)
    issue.cnf                  the exact OpenSSL configuration the certificate was issued with
    ca.conf                    profile, parent, tier, pathlen, iD, subject, Quad ID (written once the lint passed)
    index.txt crlnumber newcerts/  openssl ca database
    crl.pem                    current CRL (PEM)
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
     except for `--renew NAME`, which must keep NAME's subject and Quad ID; for `sign-csr`, the CSR's key meets the
     profile (CP 6.1.6, Table 7)
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

Lesson from the feasibility study: OpenSSL ignores configuration directives it does not know, without an error. One
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

## Platforms

Supported: Linux and macOS (bash ≥ 4.4 and OpenSSL 3 from a package manager). Windows users run the tool under WSL;
Git Bash is not supported (product owner decision): its path conversion rewrites the `-subj` arguments.

- The script avoids GNU-only tool flags.
- OpenSSL runs inside each CA's directory, and the CA configuration uses `dir = .`.
- `.gitattributes` keeps LF line endings for the script and the profiles, also in Windows checkouts used from WSL.
- `OPENSSL_CONF=/dev/null` keeps system OpenSSL configuration from changing results. Go tools are built into
  `.build/`.

Only Linux has been tested so far. Running `scripts/e2e.sh` on macOS is an open task.

## Security notes

- This is development tooling. Keys are unencrypted PKCS#8 files, created with `umask 077`.
- Generated material never enters the repository (`.gitignore`; tests use temporary directories).
- Mock material is easy to recognise: the default PCA organisation contains `MOCK … NOT FOR PRODUCTION`, and the
  examples use `.test` names (RFC 6761).
- `mockpca-serve`:
  - serves only names matching `<ca>.cer`/`<ca>.crl`, opened through `os.Root`, so symbolic links cannot escape
    `www/`
  - accepts GET/HEAD only, has timeouts on every server phase, and caps header size

## Planned

- OCSP responder, delegated responder certificates, stapling files and fault injection:
  [#1](https://github.com/Hagan-Consulting/mock-pca/issues/1).
- Deliberately non-conforming certificates (negative test fixtures): expired, not yet valid, missing CDP/AIA, wrong
  policy, extKeyUsage on Agency certificates. Today `scripts/e2e.sh` builds one ad hoc to test the linter.
- Comparing the mock profiles with the published production PCA and ICA certificates (CP Table 1:
  ng911ioc.org/library) and recording differences in [CP-NOTES.md](CP-NOTES.md).
- macOS test runs.
- An independent CRL check in `mockpca-lint` (CRLs are checked with OpenSSL only today).
