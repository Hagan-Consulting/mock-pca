package lint

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"regexp"
	"strings"
)

func (k *checker) subjectAltName() {
	raw := k.ext(oidSAN)
	if raw == nil {
		return
	}
	ref := "7.1.2.11 Table 30"
	if k.p.isCA() {
		ref = "7.1.2.11 Table 29"
	}
	san, err := parseSAN(raw)
	if err != nil {
		k.errorf(ref, "%v", err)
		return
	}
	var quads []otherName
	for _, on := range san.otherNames {
		if on.oid.Equal(OIDQuadID) {
			quads = append(quads, on)
		} else {
			k.warnf(ref, "otherName %s is not in the CP profile", on.oid)
		}
	}
	switch len(quads) {
	case 0:
		k.errorf(ref, "no Quad ID otherName (%s)", OIDQuadID)
	case 1:
	default:
		k.errorf("7.1.2.11", "%d Quad ID otherNames, SHALL be a single quad", len(quads))
	}
	if len(quads) > 0 {
		if quads[0].tag != asn1.TagUTF8String {
			k.errorf(ref, "Quad ID value is not a UTF8String (universal tag %d)", quads[0].tag)
		}
		k.checkQuad(quads[0].value)
	}
	for _, f := range san.others {
		k.warnf(ref, "GeneralName %s is not in the CP profile", f)
	}
	if san.total > 100 {
		k.warnf("7.1.2.11", "%d subjectAltName entries, SHOULD NOT be more than 100", san.total)
	}
	for _, d := range san.dns {
		if strings.Contains(d, "*") {
			k.errorf("7.1.2.11 Table 30", "wildcard dNSName %q is not allowed", d)
		}
	}
	if k.p.isCA() {
		if len(san.dns) > 0 || san.ips > 0 {
			k.warnf(ref, "dNSName/iPAddress entries are not in the CA profile (otherName only)")
		}
		return
	}
	if k.quad == nil {
		return
	}
	switch k.p {
	case Agency, Element, Service:
		if len(san.dns) == 0 {
			k.errorf("7.1.2.11", "%s Certificates SHALL contain a dNSName", k.p)
			return
		}
	}
	if len(san.dns) > 0 && san.dns[0] != k.quad.ID {
		if k.p == Agent {
			// An agentId (user@domain) cannot be a dNSName.
			k.warnf("7.1.2.11 Table 30", "first dNSName %q is not the iD %q", san.dns[0], k.quad.ID)
		} else {
			k.errorf("7.1.2.11 Table 30", "first dNSName %q is not the iD %q", san.dns[0], k.quad.ID)
		}
	}
}

var knownIDTypes = map[string]bool{"agencyId": true, "agentId": true, "elementId": true, "serviceId": true}

func (k *checker) checkQuad(s string) {
	const ref = "7.1.2.11"
	q, err := ParseQuad(s)
	if err != nil {
		k.errorf(ref, "Quad ID %q: %v", s, err)
		return
	}
	k.quad = q
	if want := k.p.idType(); want != "" && q.IDType != want {
		k.errorf(ref, "Quad ID idType is %q, want %q", q.IDType, want)
	} else if want == "" && !knownIDTypes[q.IDType] {
		k.errorf(ref, "Quad ID idType %q is not an i3 identifier type", q.IDType)
	}
	if k.p == Agent {
		if !ValidAgentID(q.ID) {
			k.errorf(ref, "Quad ID iD %q is not an agent identifier (user@fqdn) or FQDN", q.ID)
		}
	} else if !ValidFQDN(q.ID) {
		k.errorf(ref, "Quad ID iD %q is not an FQDN", q.ID)
	}
	for _, r := range strings.Split(q.Roles, ",") {
		if r == "" || strings.ContainsAny(r, " \t") {
			k.errorf(ref, "Quad ID roles %q: empty role or whitespace", q.Roles)
			break
		}
	}
	switch {
	case k.p == PCA && q.Roles != "PCA":
		k.errorf(ref, "Quad ID roles is %q, SHALL be \"PCA\"", q.Roles)
	case k.p == ICA && q.Roles != "ICA":
		k.errorf(ref, "Quad ID roles is %q, SHALL be \"ICA\"", q.Roles)
	}
	switch {
	case q.Owner == "" && k.p.isCA():
		k.errorf("7.1.2.11 Table 28", "Quad ID has no owner")
	case q.Owner == "":
		k.warnf("7.1.2.11 Table 28", "Quad ID has no owner")
	case !ValidFQDN(q.Owner):
		k.errorf("7.1.2.11 Table 28", "Quad ID owner %q is not an FQDN", q.Owner)
	case (k.p == PCA || k.p == Agency) && q.Owner != q.ID:
		k.errorf("7.1.2.11 Table 28", "Quad ID owner %q SHALL be the certificate's own iD %q", q.Owner, q.ID)
	}
}

var (
	icaCN     = regexp.MustCompile(`ICA Tier\s*[0-9]+$`)
	countryRE = regexp.MustCompile(`^[A-Z]{2}$`)
	// Upper bounds from RFC 5280 Appendix A.
	attrMax = map[string]int{
		oidCN.String(): 64, oidOrg.String(): 64, oidOrgUnit.String(): 64,
		oidLocality.String(): 128, oidState.String(): 128,
	}
	attrNames = map[string]string{
		oidCountry.String(): "C", oidState.String(): "ST", oidLocality.String(): "L",
		oidOrg.String(): "O", oidOrgUnit.String(): "OU", oidCN.String(): "CN",
	}
)

func (k *checker) subjectName() {
	ref := "7.1.4.3 Table 36"
	switch k.p {
	case PCA:
		ref = "7.1.4.1 Table 34"
	case ICA:
		ref = "7.1.4.2 Table 35"
	}
	attrs, err := parseName(k.c.RawSubject)
	if err != nil {
		k.errorf("7.1.4", "subject: %v", err)
		return
	}
	got := map[string]string{}
	multi := false
	for _, a := range attrs {
		id := a.oid.String()
		name, known := attrNames[id]
		if !known || (k.p == PCA && (name == "ST" || name == "L")) {
			k.warnf(ref, "subject attribute %s is not in the CP profile", a.oid)
			continue
		}
		if _, dup := got[name]; dup {
			k.warnf(ref, "subject attribute %s appears more than once", name)
		}
		got[name] = a.value
		multi = multi || a.multi
		k.stringType(name, a)
		if max := attrMax[id]; max > 0 && len([]rune(a.value)) > max {
			k.errorf(ref, "subject %s is longer than %d characters", name, max)
		}
	}
	if multi {
		k.warnf("3.1.1", "subject has a multi-valued RDN")
	}
	need := func(name string) bool {
		if _, ok := got[name]; !ok {
			k.errorf(ref, "subject %s is missing", name)
			return false
		}
		return true
	}
	switch k.p {
	case PCA:
		need("O")
		need("CN")
		if need("OU") && !strings.HasPrefix(got["OU"], "PCA-") {
			k.errorf(ref, "subject OU %q SHALL be PCA-<serial number>", got["OU"])
		}
	case ICA:
		if _, ok := got["C"]; !ok {
			k.warnf("3.1.1 Table 2", "subject C is missing (Table 2 lists it for ICA subjects; Table 35 marks it optional)")
		}
		need("O")
		if need("OU") && !strings.Contains(got["OU"], "CA-") {
			k.errorf(ref, "subject OU %q SHALL be <CA type> CA-<serial number>, e.g. ICA-1", got["OU"])
		}
		if need("CN") && !icaCN.MatchString(got["CN"]) {
			k.errorf(ref, "subject CN %q SHALL be <Name> ICA Tier<#>", got["CN"])
		}
	default:
		need("C")
		need("O")
		if need("CN") && k.quad != nil && got["CN"] != k.quad.ID {
			k.errorf(ref, "subject CN %q SHALL equal the Quad ID iD %q", got["CN"], k.quad.ID)
		}
	}
}

// stringType checks §3.1.1: PrintableString, or UTF8String when the value
// cannot be encoded as PrintableString; countryName is always
// PrintableString (RFC 5280).
func (k *checker) stringType(name string, a attr) {
	const ref = "3.1.1"
	switch {
	case name == "C":
		if a.tag != asn1.TagPrintableString || !countryRE.MatchString(a.value) {
			k.errorf(ref, "subject C %q SHALL be a two-letter ISO 3166-1 code as PrintableString", a.value)
		}
	case a.tag == asn1.TagPrintableString:
		if !printable(a.value) {
			k.errorf(ref, "subject %s PrintableString contains invalid characters", name)
		}
	case a.tag == asn1.TagUTF8String:
		if printable(a.value) {
			k.errorf(ref, "subject %s %q is a UTF8String but SHALL be a PrintableString when it can be encoded as one", name, a.value)
		}
	default:
		k.errorf(ref, "subject %s has string type %d, SHALL be PrintableString or UTF8String", name, a.tag)
	}
}

func (k *checker) publicKey() {
	const ref = "6.1.5 Table 7"
	minRSA := map[Profile]int{PCA: 4096, ICA: 3072, Agency: 2048, Agent: 2048, Element: 2048, Service: 2048}
	switch pub := k.c.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.p == Signing {
			k.errorf(ref, "Signing Certificates SHALL use a 256-bit (or larger) ECC key, not RSA")
		} else if bits := pub.N.BitLen(); bits < minRSA[k.p] {
			k.errorf(ref, "RSA key is %d bits, %s Certificates need at least %d", bits, k.p, minRSA[k.p])
		}
	case *ecdsa.PublicKey:
		if k.p != Signing {
			k.errorf(ref, "%s Certificates SHALL use an RSA key", k.p)
		} else if c := pub.Curve; c != elliptic.P256() && c != elliptic.P384() && c != elliptic.P521() {
			k.errorf("7.1.3", "ECC curve %s is not allowed", c.Params().Name)
		}
	case ed25519.PublicKey:
		if k.p != Signing {
			k.errorf(ref, "%s Certificates SHALL use an RSA key", k.p)
		}
	default:
		k.errorf("7.1.3", "unsupported public key type %T", pub)
	}
}

func (k *checker) validity() {
	const ref = "6.3.2 Table 12"
	c := k.c
	if !c.NotAfter.After(c.NotBefore) {
		k.errorf(ref, "notAfter is not after notBefore")
		return
	}
	years := 3
	if k.p == PCA {
		years = 10
	}
	if c.NotAfter.After(c.NotBefore.AddDate(years, 0, 0)) {
		k.errorf(ref, "validity exceeds the maximum of %d years", years)
	} else if !k.p.isCA() {
		switch {
		case c.NotAfter.After(c.NotBefore.AddDate(1, 0, 0)):
			k.warnf("6.3.2", "End-Entity validity SHOULD NOT exceed one year")
		case c.NotAfter.After(c.NotBefore.AddDate(0, 3, 0)):
			k.warnf("6.3.2", "End-Entity validity SHOULD be at most three months (except with PA approval)")
		}
	}
	if k.iss != nil && k.p != PCA &&
		(c.NotBefore.Before(k.iss.NotBefore) || c.NotAfter.After(k.iss.NotAfter)) {
		k.errorf("6.3.2", "validity is not contained in the issuer's validity")
	}
}
