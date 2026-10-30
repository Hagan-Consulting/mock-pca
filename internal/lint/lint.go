// Package lint checks X.509 certificates against the certificate profiles of
// the NG9-1-1 PKI Certificate Policy (CP) v1.3: names (§3.1.1, Table 2,
// §7.1.4), key sizes and algorithms (Table 7, §7.1.3), key usage (Tables
// 8–11), validity (Table 12) and the extensions of §7.1.2 (Tables 14–38).
//
// Extensions are inspected in their encoded form (criticality, exact bits,
// the Quad ID otherName, string types) instead of relying only on a parser's
// view of them.
package lint

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

// Profile is a certificate profile of the CP.
type Profile string

// The CP certificate profiles. Agency, Agent, Element and Service
// certificates are Authentication Certificates (Table 7).
const (
	PCA     Profile = "pca"
	ICA     Profile = "ica"
	Agency  Profile = "agency"
	Agent   Profile = "agent"
	Element Profile = "element"
	Service Profile = "service"
	Signing Profile = "signing"
	// OCSPResponder is a delegated OCSP responder (CSS) certificate (CP 7.3,
	// RFC 6960 4.2.2.2); see docs/CP-NOTES.md N21 for the profile.
	OCSPResponder Profile = "ocsp-responder"
)

// Profiles lists every profile.
var Profiles = []Profile{PCA, ICA, Agency, Agent, Element, Service, Signing, OCSPResponder}

// ParseProfile returns the profile named s.
func ParseProfile(s string) (Profile, error) {
	for _, p := range Profiles {
		if string(p) == s {
			return p, nil
		}
	}
	return "", fmt.Errorf("unknown profile %q", s)
}

func (p Profile) isCA() bool { return p == PCA || p == ICA }

// idType returns the Quad ID idType required for the profile, or "" when the
// CP does not fix one (Signing Certificates).
func (p Profile) idType() string {
	switch p {
	case PCA, ICA:
		return "cAId"
	case Agency:
		return "agencyId"
	case Agent:
		return "agentId"
	case Element:
		return "elementId"
	case Service:
		return "serviceId"
	}
	return ""
}

// Severity of a finding.
type Severity int

// Severities: Error for a violated SHALL/MUST, Warn for a SHOULD or for
// content the CP profile does not describe.
const (
	Warn Severity = iota + 1
	Error
)

func (s Severity) String() string {
	if s == Error {
		return "ERROR"
	}
	return "WARN"
}

// Finding is one deviation from the CP profile.
type Finding struct {
	Severity Severity
	// Ref names the CP section or table, e.g. "7.1.2.3 Table 16".
	Ref string
	Msg string
}

func (f Finding) String() string { return fmt.Sprintf("%s [CP %s] %s", f.Severity, f.Ref, f.Msg) }

// Options for Check.
type Options struct {
	// Issuer is the issuing CA certificate. When set, the signature, the
	// issuer name, the authorityKeyIdentifier, validity nesting and the ICA
	// pathLenConstraint are checked against it. Ignored for the PCA, which
	// is checked as self-signed. An End-Entity certificate issued by a
	// self-signed certificate (the PCA) is reported (CP 1.4.1).
	Issuer *x509.Certificate
	// Root is the PCA certificate. When set, an Agency Certificate whose
	// Quad ID owner is the PCA's iD (a NIOC Agency Certificate, Table 28) is
	// accepted; without it such an owner is only a warning.
	Root *x509.Certificate
}

// HasErrors reports whether any finding is an Error.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == Error {
			return true
		}
	}
	return false
}

type checker struct {
	c    *x509.Certificate
	p    Profile
	iss  *x509.Certificate
	root *x509.Certificate
	quad *Quad
	out  []Finding
}

func (k *checker) errorf(ref, format string, args ...any) {
	k.out = append(k.out, Finding{Error, ref, fmt.Sprintf(format, args...)})
}

func (k *checker) warnf(ref, format string, args ...any) {
	k.out = append(k.out, Finding{Warn, ref, fmt.Sprintf(format, args...)})
}

// Check returns the findings for c checked against profile p.
func Check(c *x509.Certificate, p Profile, o Options) []Finding {
	k := &checker{c: c, p: p, iss: o.Issuer, root: o.Root}
	if p == PCA {
		k.iss = c
	}
	k.basics()
	k.extensions()
	k.keyUsage()
	k.extKeyUsage()
	k.basicConstraints()
	k.keyIdentifiers()
	k.subjectAltName()
	k.subjectName()
	k.policies()
	k.distributionPoints()
	k.authorityInfoAccess()
	k.issuer()
	k.noCheck()
	return k.out
}

// Detect guesses the profile of c from its Quad ID and extKeyUsage: a
// non-CA certificate with id-kp-OCSPSigning is an OCSP responder, one with
// id-kp-codeSigning a Signing Certificate, whatever its idType.
func Detect(c *x509.Certificate) (Profile, error) {
	q, err := quadOf(c)
	if err != nil {
		return "", err
	}
	if q.IDType != "cAId" {
		for _, u := range c.ExtKeyUsage {
			switch u {
			case x509.ExtKeyUsageOCSPSigning:
				return OCSPResponder, nil
			case x509.ExtKeyUsageCodeSigning:
				return Signing, nil
			}
		}
	}
	switch q.IDType {
	case "cAId":
		switch q.Roles {
		case "PCA":
			return PCA, nil
		case "ICA":
			return ICA, nil
		}
		return "", fmt.Errorf("cAId Quad ID with roles %q (want PCA or ICA)", q.Roles)
	case "agencyId":
		return Agency, nil
	case "agentId":
		return Agent, nil
	case "serviceId":
		return Service, nil
	case "elementId":
		return Element, nil
	}
	return "", fmt.Errorf("unknown Quad ID idType %q", q.IDType)
}

func quadOf(c *x509.Certificate) (*Quad, error) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidSAN) {
			san, err := parseSAN(e.Value)
			if err != nil {
				return nil, err
			}
			for _, on := range san.otherNames {
				if on.oid.Equal(OIDQuadID) {
					return ParseQuad(on.value)
				}
			}
		}
	}
	return nil, fmt.Errorf("no Quad ID otherName (%s) in subjectAltName", OIDQuadID)
}

func (k *checker) basics() {
	c := k.c
	if c.Version != 3 {
		k.errorf("7.1.1", "version is v%d, want v3", c.Version)
	}
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 {
		k.errorf("7.1 Table 13", "serialNumber must be a positive integer")
	} else {
		n := len(c.SerialNumber.Bytes())
		if c.SerialNumber.Bytes()[0]&0x80 != 0 {
			n++ // DER needs a leading zero octet
		}
		if n > 20 {
			k.errorf("7.1 Table 13", "serialNumber is %d octets, at most 20 allowed", n)
		}
	}
	if !allowedSignature[c.SignatureAlgorithm] {
		k.errorf("7.1.3", "signature algorithm %s is not allowed", c.SignatureAlgorithm)
	}
	k.publicKey()
	k.validity()
}

type extNeed int

const (
	required   extNeed = iota + 1
	optional           // MAY
	unexpected         // not in the CP profile: warning
	forbidden          // SHALL NOT: error
)

type extRule struct {
	need     extNeed
	critical bool
	ref      string
}

func (k *checker) rules() map[string]extRule {
	r := map[string]extRule{}
	set := func(oid asn1.ObjectIdentifier, need extNeed, critical bool, ref string) {
		r[oid.String()] = extRule{need, critical, ref}
	}
	switch k.p {
	case PCA:
		set(oidBC, required, true, "7.1.2.1 Table 14")
		set(oidKU, required, true, "7.1.2.1 Table 14")
		set(oidSAN, required, false, "7.1.2.1 Table 14")
		set(oidSKI, required, false, "7.1.2.1 Table 14")
		set(oidAKI, optional, false, "7.1.2.1 Table 14")
		set(oidCP, optional, false, "7.1.2.1 Table 14")
	case ICA:
		set(oidAIA, required, false, "7.1.2.2 Table 15")
		set(oidAKI, required, false, "7.1.2.2 Table 15")
		set(oidBC, required, true, "7.1.2.2 Table 15")
		set(oidCP, required, false, "7.1.6 Table 37")
		set(oidCDP, required, false, "7.1.2.2 Table 15")
		set(oidKU, required, true, "7.1.2.2 Table 15")
		set(oidSAN, required, false, "7.1.2.2 Table 15")
		set(oidSIA, optional, false, "7.1.2.2 Table 15")
		set(oidSKI, required, false, "7.1.2.2 Table 15")
	case OCSPResponder:
		// CP 7.3: id-pkix-ocsp-nocheck; extKeyUsage id-kp-OCSPSigning per
		// RFC 6960 4.2.2.2, keyUsage digitalSignature per RFC 5280 4.2.1.3; the
		// rest as End-Entity Certificates where it applies (N21). No
		// revocation pointers are needed (nocheck), so AIA/CDP are optional.
		set(oidNoCheck, required, false, "7.3")
		set(oidEKU, required, true, "7.3, RFC 6960 4.2.2.2")
		set(oidKU, required, true, "RFC 5280 4.2.1.3")
		set(oidAKI, required, false, "7.1.2.3 Table 16")
		set(oidSKI, required, false, "7.1.2.3 Table 16")
		set(oidSAN, required, false, "7.1.2.11")
		set(oidCP, required, false, "4.10")
		set(oidAIA, optional, false, "7.1.2.3 Table 16")
		set(oidCDP, optional, false, "7.1.2.3 Table 16")
		set(oidBC, unexpected, false, "7.1.2.3 Table 16")
	default:
		set(oidAIA, required, false, "7.1.2.3 Table 16")
		set(oidAKI, required, false, "7.1.2.3 Table 16")
		set(oidCP, required, false, "7.1.2.3 Table 16")
		set(oidCDP, required, false, "7.1.2.3 Table 16")
		set(oidKU, required, true, "7.1.2.3 Table 16")
		set(oidSAN, required, false, "7.1.2.3 Table 16")
		set(oidSKI, required, false, "7.1.2.3 Table 16")
		set(oidBC, unexpected, false, "7.1.2.3 Table 16")
		switch k.p {
		case Agency, Agent:
			set(oidEKU, forbidden, true, "7.1.2.9")
		default:
			set(oidEKU, required, true, "7.1.2.3 Table 16")
		}
	}
	return r
}

func (k *checker) extensions() {
	rules := k.rules()
	seen := map[string]bool{}
	for _, e := range k.c.Extensions {
		id := e.Id.String()
		seen[id] = true
		r, ok := rules[id]
		name := extName(e.Id)
		switch {
		case !ok && e.Critical:
			k.errorf("7.1.2", "unknown critical extension %s", name)
		case !ok:
			k.warnf("7.1.2", "extension %s is not in the CP profile", name)
		case r.need == forbidden:
			k.errorf(r.ref, "extension %s SHALL NOT be included", name)
		case r.need == unexpected:
			k.warnf(r.ref, "extension %s is not in the CP profile", name)
		case e.Critical != r.critical:
			k.errorf(r.ref, "extension %s criticality is %t, want %t", name, e.Critical, r.critical)
		}
	}
	for id, r := range rules {
		if r.need == required && !seen[id] {
			oid, _ := parseOID(id)
			k.errorf(r.ref, "extension %s is missing", extName(oid))
		}
	}
}

func (k *checker) has(oid asn1.ObjectIdentifier) bool {
	for _, e := range k.c.Extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func (k *checker) ext(oid asn1.ObjectIdentifier) []byte {
	for _, e := range k.c.Extensions {
		if e.Id.Equal(oid) {
			return e.Value
		}
	}
	return nil
}

var kuNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "nonRepudiation"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

func (k *checker) keyUsage() {
	if !k.has(oidKU) {
		return
	}
	var must, may x509.KeyUsage
	var ref string
	switch k.p {
	case PCA, ICA:
		must, may, ref = x509.KeyUsageCertSign|x509.KeyUsageCRLSign, x509.KeyUsageDigitalSignature, "6.1.7.1 Table 8"
	case Agency, Agent:
		must, ref = x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment, "6.1.7.2 Table 9"
	case Element, Service:
		must, ref = x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, "6.1.7.2 Table 10"
	case Signing:
		must, ref = x509.KeyUsageDigitalSignature, "6.1.7.2 Table 11"
	case OCSPResponder:
		must, ref = x509.KeyUsageDigitalSignature, "RFC 5280 4.2.1.3"
	}
	got := k.c.KeyUsage
	for _, n := range kuNames {
		switch {
		case must&n.bit != 0 && got&n.bit == 0:
			k.errorf(ref, "keyUsage %s is not set", n.name)
		case (must|may)&n.bit == 0 && got&n.bit != 0:
			k.errorf(ref, "keyUsage %s is set", n.name)
		}
	}
}

func (k *checker) extKeyUsage() {
	if !k.has(oidEKU) {
		return
	}
	var want []x509.ExtKeyUsage
	var ref string
	switch k.p {
	case Element, Service:
		want, ref = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, "7.1.2.9 Table 26"
	case Signing:
		want, ref = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, "7.1.2.9 Table 27"
	case OCSPResponder:
		want, ref = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, "7.3, RFC 6960 4.2.2.2"
	default:
		return // reported by extensions()
	}
	got := map[x509.ExtKeyUsage]bool{}
	for _, u := range k.c.ExtKeyUsage {
		got[u] = true
	}
	for _, w := range want {
		if !got[w] {
			k.errorf(ref, "extKeyUsage %s is missing", ekuName(w))
		}
		delete(got, w)
	}
	for u := range got {
		if u == x509.ExtKeyUsageAny {
			// CP 6.1.7: extKeyUsage SHALL be consistent with keyUsage.
			k.errorf("6.1.7", "extKeyUsage anyExtendedKeyUsage is not consistent with the profile's keyUsage")
			continue
		}
		k.warnf(ref, "extKeyUsage %s is not in the CP profile", ekuName(u))
	}
	for _, u := range k.c.UnknownExtKeyUsage {
		k.warnf(ref, "extKeyUsage %s is not in the CP profile", u)
	}
}

func ekuName(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageServerAuth:
		return "id-kp-serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "id-kp-clientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "id-kp-codeSigning"
	case x509.ExtKeyUsageOCSPSigning:
		return "id-kp-OCSPSigning"
	case x509.ExtKeyUsageAny:
		return "anyExtendedKeyUsage"
	}
	return fmt.Sprintf("ExtKeyUsage(%d)", u)
}

func (k *checker) basicConstraints() {
	c := k.c
	if !k.p.isCA() {
		if c.BasicConstraintsValid && c.IsCA {
			k.errorf("7.1.2.3", "End-Entity Certificate asserts cA")
		}
		return
	}
	if !c.BasicConstraintsValid {
		return // missing extension reported by extensions()
	}
	if !c.IsCA {
		k.errorf("7.1.2.6", "basicConstraints cA is not set")
	}
	hasLen := c.MaxPathLen >= 0
	if k.p == PCA {
		if hasLen {
			k.errorf("7.1.2.6 Table 21", "pathLenConstraint is %d, SHALL be None", c.MaxPathLen)
		}
		return
	}
	if !hasLen {
		k.errorf("7.1.2.6 Table 22", "pathLenConstraint is not set")
		return
	}
	// Tier-2 ICAs take 0–3 and every lower tier its issuer's minus one, so no
	// ICA can exceed 3 whatever its issuer.
	if c.MaxPathLen > 3 {
		k.errorf("7.1.2.6 Tables 22/23", "ICA pathLenConstraint is %d, SHALL be 0–3", c.MaxPathLen)
		return
	}
	if k.iss == nil || !k.iss.BasicConstraintsValid || selfSigned(k.iss) {
		return
	}
	switch want := k.iss.MaxPathLen - 1; {
	case k.iss.MaxPathLen < 0:
		// Issuer has no constraint: nothing to derive from.
	case want < 0:
		k.errorf("7.1.2.6", "issuer pathLenConstraint 0 does not allow a subordinate CA")
	case c.MaxPathLen != want:
		k.errorf("7.1.2.6 Table 23", "Tier-n ICA pathLenConstraint is %d, SHALL be the issuer's minus one (%d)", c.MaxPathLen, want)
	}
}

func selfSigned(c *x509.Certificate) bool { return bytes.Equal(c.RawIssuer, c.RawSubject) }

func (k *checker) keyIdentifiers() {
	c := k.c
	if k.has(oidSKI) {
		want, err := keyIDMethod1(c.RawSubjectPublicKeyInfo)
		switch {
		case err != nil:
			k.errorf("7.1.2.13", "subjectPublicKeyInfo: %v", err)
		case !bytes.Equal(c.SubjectKeyId, want):
			k.errorf("7.1.2.13 Tables 32/33", "subjectKeyIdentifier is not calculated per Method 1 (SHA-1 of subjectPublicKey)")
		}
	}
	raw := k.ext(oidAKI)
	if raw == nil {
		return
	}
	aki, err := parseAKI(raw)
	if err != nil {
		k.errorf("7.1.2.5", "authorityKeyIdentifier: %v", err)
		return
	}
	if aki.keyID == nil {
		k.errorf("7.1.2.5 Tables 19/20", "authorityKeyIdentifier has no keyIdentifier")
	}
	if aki.issuerOrSerial {
		k.warnf("7.1.2.5 Tables 19/20", "authorityKeyIdentifier carries authorityCertIssuer/serialNumber; the CP profile has keyIdentifier only")
	}
	if k.iss != nil && aki.keyID != nil {
		want, err := keyIDMethod1(k.iss.RawSubjectPublicKeyInfo)
		if err == nil && !bytes.Equal(aki.keyID, want) {
			k.errorf("7.1.2.5 Tables 19/20", "authorityKeyIdentifier does not match the issuer's key (Method 1)")
		}
	}
}

func (k *checker) policies() {
	raw := k.ext(oidCP)
	if raw == nil {
		return
	}
	pols, err := parsePolicies(raw)
	if err != nil {
		k.errorf("7.1.6", "certificatePolicies: %v", err)
		return
	}
	found := false
	for _, p := range pols {
		if p.qualifiers {
			k.errorf("7.1.8", "policy %s has policy qualifiers", p.oid)
		}
		if p.oid.Equal(OIDPolicy) {
			found = true
		} else {
			k.warnf("7.1.6", "policy %s is not the CP policy", p.oid)
		}
	}
	if !found {
		k.errorf("1.2.2, 7.1.6", "certificatePolicies does not assert %s", OIDPolicy)
	}
}

func (k *checker) distributionPoints() {
	if !k.has(oidCDP) {
		return
	}
	ref := "7.1.2.8 Tables 24/25"
	if len(k.c.CRLDistributionPoints) == 0 {
		k.errorf(ref, "cRLDistributionPoints has no URL distributionPointName")
	}
	for _, u := range k.c.CRLDistributionPoints {
		if !httpURL(u) {
			k.warnf(ref, "CRL distribution point %q is not an http(s) URL", u)
		}
	}
}

func (k *checker) authorityInfoAccess() {
	if !k.has(oidAIA) {
		return
	}
	c := k.c
	ref := "7.1.2.4 Table 18"
	if k.p == ICA {
		ref = "7.1.2.4 Table 17"
	}
	if len(c.OCSPServer) == 0 {
		k.errorf(ref, "authorityInfoAccess has no OCSP accessLocation")
	}
	switch {
	case k.p == ICA && len(c.IssuingCertificateURL) > 0:
		k.warnf(ref, "authorityInfoAccess caIssuers is not in the ICA profile")
	case k.p != ICA && len(c.IssuingCertificateURL) == 0:
		k.errorf(ref, "authorityInfoAccess has no caIssuers accessLocation")
	}
	for _, u := range append(append([]string{}, c.OCSPServer...), c.IssuingCertificateURL...) {
		if !httpURL(u) {
			k.warnf(ref, "authorityInfoAccess location %q is not an http(s) URL", u)
		}
	}
}

func httpURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

func (k *checker) issuer() {
	if len(k.c.RawIssuer) <= 2 { // empty SEQUENCE
		k.errorf("7.1.4", "issuer name is empty")
	}
	if k.iss == nil {
		return
	}
	if !bytes.Equal(k.c.RawIssuer, k.iss.RawSubject) {
		k.errorf("7.1.4", "issuer name does not match the issuer certificate's subject")
	}
	if err := k.c.CheckSignatureFrom(k.iss); err != nil {
		k.errorf("7.1.3", "signature does not verify with the issuer certificate: %v", err)
	}
	// The PCA issues CSS (OCSP responder) certificates itself (CP 1.4.1).
	if !k.p.isCA() && k.p != OCSPResponder && selfSigned(k.iss) {
		k.errorf("1.4.1", "End-Entity Certificates are issued by ICAs, not by the PCA")
	}
}

// noCheck checks the id-pkix-ocsp-nocheck extension of an OCSP responder:
// its value is NULL (RFC 6960 4.2.2.2.1).
func (k *checker) noCheck() {
	v := k.ext(oidNoCheck)
	if v == nil || k.p != OCSPResponder {
		return
	}
	if !bytes.Equal(v, []byte{0x05, 0x00}) {
		k.errorf("7.3, RFC 6960 4.2.2.2.1", "id-pkix-ocsp-nocheck value is not NULL")
	}
}
