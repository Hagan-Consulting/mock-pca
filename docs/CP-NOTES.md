# CP v1.3 notes and interpretations

The CP text is inconsistent or silent in places. These are the decisions this tool makes. Every entry names the CP
location so it can be revisited when the CP changes or when production certificates show a different reading.

| # | CP location | Issue | mock-pca decision |
|---|---|---|---|
| N1 | Table 2 vs. Table 34 | PCA CN is `cn=PCA Root` in Table 2, `<Name> CA` in Table 34 | Default `PCA Root`; `init --cn` overrides. Lint only requires a CN. |
| N2 | §1.2.2 vs. Table 14 | §1.2.2: certificates "issued by the PCA" contain the policy OID; Table 14 lists no certificatePolicies for the PCA certificate | The PCA certificate (self-signed trust anchor) has none. Lint allows it. |
| N3 | Table 14 | No authorityKeyIdentifier listed for the PCA certificate | Not included. Lint allows it (must match its own key if present). |
| N4 | Table 2 vs. Table 35 | ICA subject `c=` is required in Table 2 and optional in Table 35 | Always included. Lint warns when it is missing. |
| N5 | Table 2 vs. Table 35 | ICA OU: `ou=ICA-<serial>` (Table 2), `<CA type> CA-<serial>` (Table 35); Table 2 shows the End-Entity issuer OU as `ou=CA-<serial>` | `OU=ICA-<n>` with a per-PKI counter. Lint requires `CA-` in the OU. |
| N6 | Table 15 vs. §7.1.6/Table 37 | certificatePolicies is MAY in Table 15 and SHALL in §7.1.6 for ICAs | Included. Lint requires it. |
| N7 | Table 8 | CA digitalSignature "set if the CA signs OCSP responses" | Always set, so a CA can sign its own OCSP responses (#1). |
| N8 | §7.1.2.11 | idType list includes "servicedId" | Read as `serviceId` (NENA i3 Service Identifier). |
| N9 | §7.1.2.11 | Signing Certificates get no idType | `elementId` by default; `--id-type` selects agencyId, agentId, elementId or serviceId. |
| N10 | §7.1.2.11 | "The iD value for all Certificates SHALL be an FQDN", but the agentId example is `jsmith@psap.allegheny.pa.us` | Agents accept `user@fqdn` or an FQDN. Other profiles need an FQDN. |
| N11 | Table 30 | "the first DNS Name MUST be the iD", which an agentId cannot be | The tool adds no dNSName for agents unless asked. Lint warns (not errors) on a mismatch for agents. |
| N12 | Table 30 vs. Table 28 | End-Entity owner is included "if applicable" | Always written. Lint warns when an End-Entity Quad ID has no owner, and errors for CA certificates. |
| N13 | Table 36 + RFC 5280 | CN SHALL equal the iD, but RFC 5280 limits commonName to 64 characters | iDs longer than 64 characters are refused. The CP does not address this. |
| N14 | Table 23 | Tier-n pathLenConstraint shown as "5–n", while the text says "issuer's minus one" | Issuer's minus one. |
| N15 | Table 22 | Tier-2 pathLenConstraint 0–3 "as approved by NIOC" | `ica --pathlen`, default 1. |
| N16 | Table 7 | "256-bit ECC" for Signing Certificates; "SHALL meet or exceed" | P-256 by default; lint accepts P-256/384/521 and Ed25519 (listed in §7.1.3). |
| N17 | §6.3.2 | End-Entity validity SHOULD NOT exceed 1 year and SHOULD be ≤ 3 months | Default 90 days. Lint warns above 3 months and above 1 year, and errors above 3 years (Table 12). |
| N18 | §6.3.2 | ICA keys sign certificates for at most 2 years | Not enforced (one key per CA; no key rollover yet). |
| N19 | §3.1.1 vs. RFC 5280 | The CP requires PrintableString where encodable; RFC 5280 recommends UTF8String | CP rule (`string_mask = MASK:0x2002`). Lint errors on a UTF8String that could be PrintableString. |
| N20 | Table 15 | subjectInfoAccess MAY be included in ICAs with non-zero pathLenConstraint | Not included. |
| N21 | §7.3, §6.1.5 | OCSP responder (CSS) certificates: only key size (≥ 2048 RSA) and `id-pkix-ocsp-nocheck` are specified | To be decided with the OCSP feature, #1. |
| N22 | Table 39 | "This CP requires use of RSA signatures" for CRLs | All CA keys are RSA. |
