# Certificate profiles

How each profile in `profiles/` maps to the NG9-1-1 PKI Certificate Policy v1.3. "Lint" names what `mockpca-lint`
enforces (E = error, W = warning). Interpretations of unclear CP text are in [CP-NOTES.md](CP-NOTES.md).

## Common to all certificates

| Item | Value | CP | Lint |
|---|---|---|---|
| Version | v3 | 7.1.1 | E |
| Serial | random, positive, ≤ 20 octets (`rand_serial`) | Table 13 | E |
| Signature | sha256WithRSAEncryption (all CA keys are RSA) | 7.1.3 | E if not in the CP list |
| DN strings | PrintableString, or UTF8String when not encodable; C is PrintableString | 3.1.1 | E |
| subjectKeyIdentifier | non-critical, Method 1 (SHA-1 of subjectPublicKey) | Tables 32/33 | E |
| authorityKeyIdentifier | non-critical, keyIdentifier only, Method 1 (not in the PCA) | Tables 19/20 | E; W if issuer/serial present |
| subjectAltName | non-critical; exactly one Quad ID `otherName` `1.3.6.1.4.1.55670.1.1` as UTF8String `idType/iD/roles/owner` | 7.1.2.11, Tables 29/30 | E |
| Unknown extensions | none | 7.1.2 | E if critical, W otherwise |
| Subject attribute order | as in the CP tables (below) | Tables 2, 34–36 | W |
| RSA public exponent | 65537 (odd, > 2^16) | 6.1.6 (FIPS 186-4) | E |
| Uniqueness | subject DN and Quad ID unique in the PKI (`--renew` exempt) | 3.1.5, 7.1.2.11 | tool only |

## PCA (`pca.ext`)

| Item | Value | CP |
|---|---|---|
| Subject | `[C=US], O=MOCK NG911 PCA - NOT FOR PRODUCTION, OU=PCA-<n>, CN=PCA Root` (lint: OU `PCA-<digits>`) | Table 2, Table 34 |
| Key / validity | RSA 4096 / 10 years (3650 days) | Table 7, Table 12 |
| basicConstraints | critical, cA, no pathLenConstraint | Table 21 |
| keyUsage | critical: digitalSignature, keyCertSign, cRLSign | Table 8 |
| Quad ID | `cAId/<pca-id>/PCA/<pca-id>` | 7.1.2.11, Table 28 |
| certificatePolicies, AIA, CDP | not included | Table 14 |

## ICA (`ica.ext`)

| Item | Value | CP |
|---|---|---|
| Subject | `C, O, OU=ICA-<n>, [ST], [L], CN=<label> ICA Tier<n>` (Table 2 order; lint also accepts Table 35's C, O, OU, L, ST, CN, and `Tier<n>`, `Tier <n>`, `Tier-<n>` with n = issuer's tier + 1) | Table 2, Table 35, 3.1.2 |
| Key / validity | RSA 3072 / up to 3 years, capped at the issuer's notAfter | Table 7, Table 12, 6.3.2 |
| basicConstraints | critical, cA; pathLenConstraint 0–3 under the PCA, else the issuer's minus one | Tables 22/23 |
| keyUsage | critical: digitalSignature, keyCertSign, cRLSign | Table 8 |
| authorityInfoAccess | non-critical, OCSP `<base>/ocsp/<parent>` | Table 17 |
| cRLDistributionPoints | non-critical, `<base>/crl/<parent>.crl` | Table 24 |
| certificatePolicies | non-critical, `1.3.6.1.4.1.55670.1`, no qualifiers | Table 37, 7.1.8 |
| Quad ID | `cAId/<ica-id>/ICA/<owner-agency-id>` | 7.1.2.11, Table 28 |
| subjectInfoAccess | not included (MAY) | Table 31 |

## End-Entity certificates

All End-Entity profiles share:

| Item | Value | CP |
|---|---|---|
| Subject | `C, O, [L], [ST], [OU], CN=<iD>` | Tables 2, 36 |
| Issuer | an ICA, never the PCA (lint: E) | 1.4.1 |
| Validity | default 90 days; ≤ 3 years (lint: W above 3 months and 1 year) | Table 12, 6.3.2 |
| authorityInfoAccess | non-critical, caIssuers `<base>/certs/<ca>.cer` and OCSP `<base>/ocsp/<ca>` | Table 18 |
| cRLDistributionPoints | non-critical, `<base>/crl/<ca>.crl` | Table 25 |
| certificatePolicies | non-critical, `1.3.6.1.4.1.55670.1`, no qualifiers | Table 38, 7.1.8 |
| Quad ID owner | the iD of the Agency controlling the entity; an Agency certificate's own iD, or the PCA's iD for a NIOC Agency Certificate | Table 28 |

| Profile | idType | Key (default) | keyUsage (critical) | extKeyUsage (critical) | dNSName |
|---|---|---|---|---|---|
| `agency` | agencyId | RSA 2048 | digitalSignature, nonRepudiation (Table 9) | none (7.1.2.9) | required, first = iD |
| `agent` | agentId | RSA 2048 | digitalSignature, nonRepudiation (Table 9) | none (7.1.2.9) | optional; first = iD if present (so only with an FQDN iD) |
| `element` | elementId | RSA 2048 | digitalSignature, keyEncipherment (Table 10) | serverAuth, clientAuth (Table 26) | required, first = iD |
| `service` | serviceId | RSA 2048 | digitalSignature, keyEncipherment (Table 10) | serverAuth, clientAuth (Table 26) | required, first = iD |
| `signing` | elementId (`--id-type`) | ECDSA P-256 | digitalSignature (Table 11) | codeSigning (Table 27) | optional; first = iD if present |

Key sizes (Table 7): authentication certificates need RSA ≥ 2048. Signing certificates use 256-bit ECC; the linter
also accepts P-384, P-521 and Ed25519 ("meet or exceed"). iPAddress entries are allowed in every End-Entity profile
(Table 30). Wildcard dNSNames are not allowed.

TLS note: Agency and Agent certificates have neither keyEncipherment nor extKeyUsage. They work for TLS 1.3 and
ECDHE key exchange in TLS 1.2 (signatures only), not for RSA key transport.

## OCSP responder (`ocsp-responder.ext`)

One delegated responder certificate per CA, issued by that CA (the PCA's answers for the ICAs). The CP fixes only part
of this profile; the rest is our interpretation, see [CP-NOTES.md](CP-NOTES.md) N21.

| Item | Value | CP | Lint |
|---|---|---|---|
| Subject | `C, O=<the CA's O>, CN=ocsp.<CA iD>` | Tables 2, 36 (as End-Entities) | E |
| Key / validity | RSA 2048 / 30 days (`ocsp-signer --days`), capped at the CA's notAfter | Table 7 (CSS ≥ 2048 RSA) | E below 2048 or non-RSA |
| keyUsage | critical: digitalSignature only | RFC 5280 4.2.1.3 | E |
| extKeyUsage | critical: id-kp-OCSPSigning | 7.3, RFC 6960 4.2.2.2 | E |
| id-pkix-ocsp-nocheck | non-critical, NULL | 7.3, RFC 6960 4.2.2.2.1 | E |
| certificatePolicies | non-critical, `1.3.6.1.4.1.55670.1` | 4.10 (a CSS asserts the policy OIDs it is authoritative for) | E |
| subjectAltName | Quad ID `elementId/ocsp.<CA iD>/OCSPResponder/<CA owner>` | 7.1.2.11 | E |
| SKI / AKI | Method 1 | Tables 32/33, 19/20 | E |
| AIA / CDP | not included (nocheck: no revocation checking of the responder) | RFC 5019 2.2.2 (RFC 9919 3.2.2) recommends neither | W |
| Issuer | the CA it answers for; the PCA may issue its own (CSS Certificates, 1.4.1) | 7.3 | E (signature, nesting) |

## OCSP responses

| Item | Value | CP / RFC |
|---|---|---|
| Signer | the CA's delegated responder (default) or the CA key (`ocsp-signer --mode ca`) | 7.3 |
| Signature | sha256WithRSAEncryption (`-rmd sha256`) | 7.1.3 |
| CertID hashes | SHA-256 and SHA-1 answered | RFC 9919 3.1.1, RFC 5019 |
| thisUpdate / nextUpdate | always; nextUpdate 60 minutes by default (`serve --ocsp-nmin`) | RFC 5019 2.2.4 (RFC 9919 3.2.4); client freshness check: RFC 5019 4 (RFC 9919 5) |
| Nonces | ignored (no nonce in responses) | RFC 5019 2.2.1, 4 (RFC 9919 3.2.1, 5) |
| HTTP requests | POST, and GET with the base64 request URL-encoded in the path; GET is strict: `/` must be `%2F` and padding present, otherwise `malformedRequest` | RFC 6960 A.1, RFC 9919 6 (RFC 3986, RFC 4648 3.2, 4) |
| HTTP responses | `application/ocsp-response`; Last-Modified = thisUpdate, Expires = nextUpdate, `Cache-Control: max-age=<n>, public, no-transform, must-revalidate` with n ending before nextUpdate, ETag = hex SHA-256 of the response; `no-cache` only on unsigned error responses | RFC 9919 6, 7.2 (RFC 5019 5, 6.2) |

## CRLs (`ca.cnf`)

| Item | Value | CP |
|---|---|---|
| Version | v2 | 7.2.1 |
| Extensions | authorityKeyIdentifier, cRLNumber; none critical | Table 39, 7.2.2 |
| Signature | sha256WithRSAEncryption | Table 39 |
| Lifetime | 24 hours by default (`--hours`, `--seconds`) | Table 3 |
| Empty CRL | no revokedCertificates field | Table 39 |
