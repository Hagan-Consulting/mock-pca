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

## PCA (`pca.ext`)

| Item | Value | CP |
|---|---|---|
| Subject | `[C=US] O=MOCK NG911 PCA - NOT FOR PRODUCTION, OU=PCA-<n>, CN=PCA Root` | Table 2, Table 34 |
| Key / validity | RSA 4096 / 10 years (3650 days) | Table 7, Table 12 |
| basicConstraints | critical, cA, no pathLenConstraint | Table 21 |
| keyUsage | critical: digitalSignature, keyCertSign, cRLSign | Table 8 |
| Quad ID | `cAId/<pca-id>/PCA/<pca-id>` | 7.1.2.11, Table 28 |
| certificatePolicies, AIA, CDP | not included | Table 14 |

## ICA (`ica.ext`)

| Item | Value | CP |
|---|---|---|
| Subject | `C, [ST], [L], O, OU=ICA-<n>, CN=<label> ICA Tier<n>` | Table 2, Table 35 |
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
| Subject | `C, [ST], [L], O, [OU], CN=<iD>` | Table 36 |
| Validity | default 90 days; ≤ 3 years (lint: W above 3 months and 1 year) | Table 12, 6.3.2 |
| authorityInfoAccess | non-critical, caIssuers `<base>/certs/<ca>.cer` and OCSP `<base>/ocsp/<ca>` | Table 18 |
| cRLDistributionPoints | non-critical, `<base>/crl/<ca>.crl` | Table 25 |
| certificatePolicies | non-critical, `1.3.6.1.4.1.55670.1`, no qualifiers | Table 38, 7.1.8 |
| Quad ID owner | the iD of the Agency controlling the entity; an Agency certificate's own iD | Table 28 |

| Profile | idType | Key (default) | keyUsage (critical) | extKeyUsage (critical) | dNSName |
|---|---|---|---|---|---|
| `agency` | agencyId | RSA 2048 | digitalSignature, nonRepudiation (Table 9) | none (7.1.2.9) | required, first = iD |
| `agent` | agentId | RSA 2048 | digitalSignature, nonRepudiation (Table 9) | none (7.1.2.9) | optional |
| `element` | elementId | RSA 2048 | digitalSignature, keyEncipherment (Table 10) | serverAuth, clientAuth (Table 26) | required, first = iD |
| `service` | serviceId | RSA 2048 | digitalSignature, keyEncipherment (Table 10) | serverAuth, clientAuth (Table 26) | required, first = iD |
| `signing` | elementId (`--id-type`) | ECDSA P-256 | digitalSignature (Table 11) | codeSigning (Table 27) | optional; first = iD if present |

Key sizes (Table 7): authentication certificates need RSA ≥ 2048. Signing certificates use 256-bit ECC; the linter
also accepts P-384, P-521 and Ed25519 ("meet or exceed"). iPAddress entries are allowed in every End-Entity profile
(Table 30). Wildcard dNSNames are not allowed.

TLS note: Agency and Agent certificates have neither keyEncipherment nor extKeyUsage. They work for TLS 1.3 and
ECDHE key exchange in TLS 1.2 (signatures only), not for RSA key transport.

## CRLs (`ca.cnf`)

| Item | Value | CP |
|---|---|---|
| Version | v2 | 7.2.1 |
| Extensions | authorityKeyIdentifier, cRLNumber; none critical | Table 39, 7.2.2 |
| Signature | sha256WithRSAEncryption | Table 39 |
| Lifetime | 24 hours by default (`--hours`, `--seconds`) | Table 3 |
| Empty CRL | no revokedCertificates field | Table 39 |
