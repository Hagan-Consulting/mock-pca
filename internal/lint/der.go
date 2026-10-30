package lint

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// OIDs of the CP (§1.2.2).
var (
	// OIDPolicy is the CP policy OID asserted in certificatePolicies.
	OIDPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55670, 1}
	// OIDQuadID is the otherName type-id of the Quad ID in subjectAltName.
	OIDQuadID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55670, 1, 1}
)

var (
	oidSKI = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidKU  = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidBC  = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidCDP = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidCP  = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidAKI = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidEKU = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidAIA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidSIA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
	// id-pkix-ocsp-nocheck (RFC 6960 4.2.2.2.1).
	oidNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

	oidCountry  = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidLocality = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidState    = asn1.ObjectIdentifier{2, 5, 4, 8}
	oidOrg      = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrgUnit  = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCN       = asn1.ObjectIdentifier{2, 5, 4, 3}
)

var extNames = map[string]string{
	oidSKI.String():     "subjectKeyIdentifier",
	oidKU.String():      "keyUsage",
	oidSAN.String():     "subjectAltName",
	oidBC.String():      "basicConstraints",
	oidCDP.String():     "cRLDistributionPoints",
	oidCP.String():      "certificatePolicies",
	oidAKI.String():     "authorityKeyIdentifier",
	oidEKU.String():     "extKeyUsage",
	oidAIA.String():     "authorityInfoAccess",
	oidSIA.String():     "subjectInfoAccess",
	oidNoCheck.String(): "id-pkix-ocsp-nocheck",
}

func extName(oid asn1.ObjectIdentifier) string {
	if n, ok := extNames[oid.String()]; ok {
		return n
	}
	return oid.String()
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		oid = append(oid, n)
	}
	return oid, nil
}

var allowedSignature = map[x509.SignatureAlgorithm]bool{
	x509.SHA256WithRSA:   true,
	x509.SHA384WithRSA:   true,
	x509.SHA512WithRSA:   true,
	x509.ECDSAWithSHA256: true,
	x509.ECDSAWithSHA384: true,
	x509.ECDSAWithSHA512: true,
	x509.PureEd25519:     true,
}

// keyIDMethod1 returns the RFC 5280 §4.2.1.2 method (1) key identifier: the
// SHA-1 hash of the subjectPublicKey BIT STRING value.
func keyIDMethod1(spki []byte) ([]byte, error) {
	var s struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(spki, &s); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("trailing data")
	}
	h := sha1.Sum(s.PublicKey.Bytes)
	return h[:], nil
}

type otherName struct {
	oid asn1.ObjectIdentifier
	// tag is the universal tag of the value (12 = UTF8String).
	tag   int
	value string
}

type sanEntries struct {
	otherNames []otherName
	dns        []string
	ips        int
	// others counts GeneralName forms the CP profile does not list.
	others []string
	total  int
}

var generalNameForms = map[int]string{
	1: "rfc822Name", 3: "x400Address", 4: "directoryName", 5: "ediPartyName",
	6: "uniformResourceIdentifier", 8: "registeredID",
}

func parseSAN(der []byte) (*sanEntries, error) {
	var names []asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &names); err != nil {
		return nil, fmt.Errorf("subjectAltName: %w", err)
	} else if len(rest) > 0 {
		return nil, errors.New("subjectAltName: trailing data")
	}
	s := &sanEntries{total: len(names)}
	for _, n := range names {
		if n.Class != asn1.ClassContextSpecific {
			return nil, errors.New("subjectAltName: GeneralName is not context-specific")
		}
		switch n.Tag {
		case 0:
			on, err := parseOtherName(n.Bytes)
			if err != nil {
				return nil, err
			}
			s.otherNames = append(s.otherNames, on)
		case 2:
			s.dns = append(s.dns, string(n.Bytes))
		case 7:
			s.ips++
		default:
			s.others = append(s.others, generalNameForms[n.Tag])
		}
	}
	return s, nil
}

// parseOtherName parses the contents of an otherName GeneralName:
// type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY.
func parseOtherName(b []byte) (otherName, error) {
	var on otherName
	rest, err := asn1.Unmarshal(b, &on.oid)
	if err != nil {
		return on, fmt.Errorf("otherName type-id: %w", err)
	}
	var wrapper asn1.RawValue
	if rest, err = asn1.Unmarshal(rest, &wrapper); err != nil {
		return on, fmt.Errorf("otherName value: %w", err)
	}
	if len(rest) > 0 || wrapper.Class != asn1.ClassContextSpecific || wrapper.Tag != 0 || !wrapper.IsCompound {
		return on, errors.New("otherName value is not [0] EXPLICIT")
	}
	var v asn1.RawValue
	if rest, err = asn1.Unmarshal(wrapper.Bytes, &v); err != nil {
		return on, fmt.Errorf("otherName value: %w", err)
	}
	if len(rest) > 0 || v.Class != asn1.ClassUniversal {
		return on, errors.New("otherName value is not a single universal type")
	}
	on.tag, on.value = v.Tag, string(v.Bytes)
	return on, nil
}

type akiInfo struct {
	keyID          []byte
	issuerOrSerial bool
}

func parseAKI(der []byte) (akiInfo, error) {
	var seq asn1.RawValue
	var a akiInfo
	if rest, err := asn1.Unmarshal(der, &seq); err != nil {
		return a, err
	} else if len(rest) > 0 || seq.Tag != asn1.TagSequence {
		return a, errors.New("not a SEQUENCE")
	}
	b := seq.Bytes
	for len(b) > 0 {
		var f asn1.RawValue
		var err error
		if b, err = asn1.Unmarshal(b, &f); err != nil {
			return a, err
		}
		switch {
		case f.Class == asn1.ClassContextSpecific && f.Tag == 0:
			a.keyID = f.Bytes
		case f.Class == asn1.ClassContextSpecific && (f.Tag == 1 || f.Tag == 2):
			a.issuerOrSerial = true
		default:
			return a, fmt.Errorf("unexpected field [%d]", f.Tag)
		}
	}
	return a, nil
}

type policyInfo struct {
	oid        asn1.ObjectIdentifier
	qualifiers bool
}

func parsePolicies(der []byte) ([]policyInfo, error) {
	var raw []struct {
		Policy     asn1.ObjectIdentifier
		Qualifiers asn1.RawValue `asn1:"optional"`
	}
	if rest, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("trailing data")
	}
	out := make([]policyInfo, len(raw))
	for i, p := range raw {
		out[i] = policyInfo{p.Policy, len(p.Qualifiers.FullBytes) > 0}
	}
	return out, nil
}

// attr is one attribute of a distinguished name with its string type.
type attr struct {
	oid   asn1.ObjectIdentifier
	tag   int
	value string
	// multi marks an attribute of a multi-valued RDN.
	multi bool
}

func parseName(der []byte) ([]attr, error) {
	var rdns []asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &rdns); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("trailing data")
	}
	var out []attr
	for _, rdn := range rdns {
		if rdn.Tag != asn1.TagSet {
			return nil, errors.New("RDN is not a SET")
		}
		var atvs []attr
		b := rdn.Bytes
		for len(b) > 0 {
			var atv struct {
				Type  asn1.ObjectIdentifier
				Value asn1.RawValue
			}
			var err error
			if b, err = asn1.Unmarshal(b, &atv); err != nil {
				return nil, err
			}
			atvs = append(atvs, attr{oid: atv.Type, tag: atv.Value.Tag, value: string(atv.Value.Bytes)})
		}
		for i := range atvs {
			atvs[i].multi = len(atvs) > 1
		}
		out = append(out, atvs...)
	}
	return out, nil
}

// printable reports whether s can be encoded as an ASN.1 PrintableString.
func printable(s string) bool {
	for _, r := range s {
		switch {
		case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9':
		case strings.ContainsRune(" '()+,-./:=?", r):
		default:
			return false
		}
	}
	return true
}
