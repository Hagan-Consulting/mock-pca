# CP v1.3 notes and interpretations

The CP text is inconsistent or silent in places. These are the decisions this tool makes. Every entry names the CP
location so it can be revisited when the CP changes or when production certificates show a different reading.

| # | CP location | Issue | mock-pca decision |
|---|---|---|---|
| N1 | Table 2 vs. Table 34 | PCA CN is `cn=PCA Root` in Table 2, `<Name> CA` in Table 34 | Default `PCA Root`; `init --cn` overrides. Lint only requires a CN. |
| N2 | §1.2.2 vs. Table 14 | §1.2.2: certificates "issued by the PCA" contain the policy OID; Table 14 lists no certificatePolicies for the PCA certificate | The PCA certificate (self-signed trust anchor) has none. Lint allows it. |
| N3 | Table 14 | No authorityKeyIdentifier listed for the PCA certificate | Not included. Lint allows it (must match its own key if present). |
| N4 | Table 2 vs. Table 35 | ICA subject `c=` is required in Table 2 and optional in Table 35 | Always included. Lint warns when it is missing. |
| N5 | Table 2 vs. Table 35 | ICA OU: `ou=ICA-<serial>` (Table 2), `<CA type> CA-<serial>` (Table 35); Table 2 shows the End-Entity issuer OU as `ou=CA-<serial>` | `OU=ICA-<n>` with a per-PKI counter that skips numbers in use. Lint requires `<CA type>CA-<digits>` (e.g. `ICA-1`, `Intermediate CA-1`) and rejects `PCA-` for ICAs; the PCA needs `PCA-<digits>` (Table 34). |
| N6 | Table 15 vs. §7.1.6/Table 37 | certificatePolicies is MAY in Table 15 and SHALL in §7.1.6 for ICAs | Included. Lint requires it. |
| N7 | Table 8 | CA digitalSignature "set if the CA signs OCSP responses" | Always set, so a CA can sign its own OCSP responses (#1). |
| N8 | §7.1.2.11 | idType list includes "servicedId" | Read as `serviceId` (NENA i3 Service Identifier). |
| N9 | §7.1.2.11 | Signing Certificates get no idType | `elementId` by default; `--id-type` selects agencyId, agentId, elementId or serviceId. |
| N10 | §7.1.2.11 | "The iD value for all Certificates SHALL be an FQDN", but the agentId example is `jsmith@psap.allegheny.pa.us` | Agents accept `user@fqdn` or an FQDN. Other profiles need an FQDN. |
| N11 | Table 30 | "the first DNS Name MUST be the iD", which an agentId of the form `user@fqdn` cannot be | The rule applies to every profile: when an Agent or Signing certificate has dNSNames, the iD comes first, so an agent with a `user@fqdn` iD cannot have dNSNames. Lint: a mismatch is an error. |
| N12 | Table 30 vs. Table 28 | End-Entity owner is included "if applicable" | Always written. Lint warns when an End-Entity Quad ID has no owner, and errors for CA certificates. |
| N13 | Table 36 + RFC 5280 | CN SHALL equal the iD, but RFC 5280 limits commonName to 64 characters | iDs longer than 64 characters are refused. The CP does not address this. |
| N14 | Table 23 | Tier-n pathLenConstraint shown as "5–n", while the text says "issuer's minus one" | Issuer's minus one. |
| N15 | Table 22 | Tier-2 pathLenConstraint 0–3 "as approved by NIOC" | `ica --pathlen`, default 1. |
| N16 | Table 7 | "256-bit ECC" for Signing Certificates; "SHALL meet or exceed" | P-256 by default; lint accepts P-256/384/521 and Ed25519 (listed in §7.1.3). |
| N17 | §6.3.2 | End-Entity validity SHOULD NOT exceed 1 year and SHOULD be ≤ 3 months | Default 90 days. Lint warns above 3 months and above 1 year, and errors above 3 years (Table 12). |
| N18 | §6.3.2 | ICA keys sign certificates for at most 2 years | Not enforced (one key per CA; no key rollover yet). |
| N19 | §3.1.1 vs. RFC 5280 | The CP requires PrintableString where encodable; RFC 5280 recommends UTF8String | CP rule (`string_mask = MASK:0x2002`). Lint errors on a UTF8String that could be PrintableString. |
| N20 | Table 15 | subjectInfoAccess MAY be included in ICAs with non-zero pathLenConstraint | Not included. |
| N21 | §7.3, §6.1.5, §4.10 | OCSP responder (CSS) certificates: only signing by the issuing CA, `id-pkix-ocsp-nocheck`, key size (≥ 2048 RSA) and the policy OIDs (§4.10) are specified | One delegated responder per CA, issued by that CA (the PCA answers for ICAs; §1.4.1 lets it issue CSS Certificates). Profile ([PROFILES.md](PROFILES.md)): critical keyUsage digitalSignature (RFC 5280 4.2.1.3) and critical extKeyUsage id-kp-OCSPSigning (RFC 6960 4.2.2.2), nocheck, CP policy OID, SKI/AKI, no AIA/CDP (nocheck; RFC 5019 2.2.2 recommends neither), subject and SAN as End-Entities with the Quad ID `elementId/ocsp.<CA iD>/OCSPResponder/<CA owner>` (the CP defines no idType or role for a CSS; "All NIOC Certificates MUST contain the SAN extension" in §7.1.2.11), 30-day validity. Responses: SHA-256 signatures, SHA-1 and SHA-256 CertIDs (RFC 9919 obsoletes the CP's RFC 5019 citation), CA-signed mode optional. |
| N22 | Table 39 | "This CP requires use of RSA signatures" for CRLs | All CA keys are RSA. |
| N23 | Table 2 vs. Table 35 | ICA subject order: c, o, ou, [st], [l], cn (Table 2) vs. C, O, OU, L, ST, CN (Table 35) | Issued in the Table 2 order (§7.1.4 refers to §3.1.1). Lint accepts both orders and warns on any other (product owner decision: order deviations are warnings). End-Entities: c, o, [l], [st], [ou], cn (Tables 2 and 36 agree). |
| N24 | Table 2, Table 35 vs. §3.1.2 | ICA CN "<Name> ICA Tier<#>" (Table 2) vs. "SHOULD display the tier level (i.e., Tier-2)" (§3.1.2) | Issued as `Tier<n>`; lint accepts `Tier<n>`, `Tier <n>` and `Tier-<n>` and, with the issuer, checks that n is the issuer's tier plus one (the PCA is Tier 1). |
| N25 | Table 28 | Owner of a "NIOC Agency Certificate" is the "iD of PCA" | `issue --profile agency --owner <pca-id>` is allowed; lint accepts it with `-root` (the PCA certificate) and warns without it. |
| N26 | §3.1.5, §7.1.2.11 | subjectDN and Quad ID SHALL be unique; renewal and re-key keep them | Duplicates in the PKI are refused. `issue --renew NAME` issues an End-Entity renewal or re-key with NAME's subject DN and Quad ID ("using the same subjectDN when an End-Entity Certificate is Re-Keyed or Renewed, does not violate name uniqueness"). `ica --renew NAME` re-keys an ICA: same Quad ID, parent, O, C, ST, L, label and pathLenConstraint, new key and a new `OU=ICA-<serial>` ("The subjectDN in CA Certificates is unique when Certificates are Re-Keyed due to the serial number used in the ou= field"); the old ICA stays until revoked or expired. `unique_subject = no` in `ca.cnf` only lets OpenSSL accept End-Entity renewals. |
| N27 | §4.9.13 | "Suspension is not supported by this CP" | No `certificateHold` revocation reason. |
| N28 | Table 3 | Routine CRLs at least every 24 hours | Default lifetime 24 hours, republished every 12 hours by `serve`. Longer lifetimes/intervals are allowed for testing with a warning (product owner decision). |
| N29 | §1.4.1 | The PCA issues "ICA Certificates, CSS Certificates, and CRLs" | The PCA never issues End-Entity certificates; lint reports an End-Entity certificate issued by a self-signed certificate. |
