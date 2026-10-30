package lint

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test PKI: PCA → ICA Tier2 (pathlen 1) → ICA Tier3 (pathlen 0) → End-Entities.
// The certificates are built with crypto/x509 directly; the SAN (Quad ID
// otherName) and the critical extKeyUsage need hand-encoded extensions.

const base = "http://pca.mock.test:8080"

type testKeys struct {
	pca, ica2, ica3, ee *rsa.PrivateKey
	small               *rsa.PrivateKey
	ec                  *ecdsa.PrivateKey
}

var keys = sync.OnceValue(func() testKeys {
	gen := func(bits int) *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			panic(err)
		}
		return k
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return testKeys{pca: gen(4096), ica2: gen(3072), ica3: gen(3072), ee: gen(2048), small: gen(1024), ec: ec}
})

var start = time.Now().Add(-time.Hour).Truncate(time.Second)

func keyID(t testing.TB, pub crypto.PublicKey) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	id, err := keyIDMethod1(spki)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustMarshal(t testing.TB, v any, params ...string) []byte {
	t.Helper()
	b, err := asn1.MarshalWithParams(v, strings.Join(params, ","))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sanExt encodes a subjectAltName with one otherName of type oid whose value
// is a string with the given ASN.1 params ("utf8", "ia5"), then dNSNames.
func sanExt(t testing.TB, oid asn1.ObjectIdentifier, value, params string, dns ...string) pkix.Extension {
	t.Helper()
	inner := mustMarshal(t, value, params)
	on := append(mustMarshal(t, oid), mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})...)
	names := []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: on}}
	for _, d := range dns {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(d)})
	}
	return pkix.Extension{Id: oidSAN, Value: mustMarshal(t, names)}
}

func quadSAN(t testing.TB, quad string, dns ...string) pkix.Extension {
	return sanExt(t, OIDQuadID, quad, "utf8", dns...)
}

var (
	oidServerAuth  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
)

func ekuExt(t testing.TB, critical bool, oids ...asn1.ObjectIdentifier) pkix.Extension {
	return pkix.Extension{Id: oidEKU, Critical: critical, Value: mustMarshal(t, oids)}
}

func mustOID(ints ...uint64) x509.OID {
	oid, err := x509.OIDFromInts(ints)
	if err != nil {
		panic(err)
	}
	return oid
}

var policy = mustOID(1, 3, 6, 1, 4, 1, 55670, 1)

var serial atomic.Int64

func create(t testing.TB, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(1000 + serial.Add(1))
	}
	if tmpl.SubjectKeyId == nil {
		tmpl.SubjectKeyId = keyID(t, pub)
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pcaTmpl(t testing.TB) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"MOCK PCA - NOT FOR PRODUCTION"}, OrganizationalUnit: []string{"PCA-1"}, CommonName: "PCA Root"},
		NotBefore:             start,
		NotAfter:              start.AddDate(10, 0, -1),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            -1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtraExtensions:       []pkix.Extension{quadSAN(t, "cAId/pca.mock.test/PCA/pca.mock.test")},
	}
}

func icaTmpl(t testing.TB, tier int, issuerCA string) *x509.Certificate {
	pathLen := 3 - tier // Tier2 → 1, Tier3 → 0
	return &x509.Certificate{
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"Mock 911"}, OrganizationalUnit: []string{"ICA-" + string(rune('0'+tier))}, CommonName: "Mock ICA Tier" + string(rune('0'+tier))},
		NotBefore:             start,
		NotAfter:              start.AddDate(3, 0, -tier),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		OCSPServer:            []string{base + "/ocsp/" + issuerCA},
		CRLDistributionPoints: []string{base + "/crl/" + issuerCA + ".crl"},
		Policies:              []x509.OID{policy},
		ExtraExtensions:       []pkix.Extension{quadSAN(t, "cAId/ica"+string(rune('0'+tier))+".mock.test/ICA/agency.mock.test")},
	}
}

type hierarchy struct {
	pca, ica2, ica3 *x509.Certificate
}

// panicTB reports fatal errors by panicking; for the shared fixtures built
// outside any test.
type panicTB struct{ testing.TB }

func (panicTB) Helper()                      {}
func (panicTB) Fatal(args ...any)            { panic(fmt.Sprint(args...)) }
func (panicTB) Fatalf(f string, args ...any) { panic(fmt.Sprintf(f, args...)) }

var pki = sync.OnceValue(func() hierarchy {
	t := panicTB{}
	k := keys()
	pca := create(t, pcaTmpl(t), nil, &k.pca.PublicKey, k.pca)
	ica2 := create(t, icaTmpl(t, 2, "pca"), pca, &k.ica2.PublicKey, k.pca)
	ica3 := create(t, icaTmpl(t, 3, "ica2"), ica2, &k.ica3.PublicKey, k.ica2)
	return hierarchy{pca, ica2, ica3}
})

func eeTmpl(t testing.TB, p Profile) *x509.Certificate {
	tmpl := &x509.Certificate{
		NotBefore:             start,
		NotAfter:              start.AddDate(0, 0, 90),
		OCSPServer:            []string{base + "/ocsp/ica3"},
		IssuingCertificateURL: []string{base + "/certs/ica3.cer"},
		CRLDistributionPoints: []string{base + "/crl/ica3.crl"},
		Policies:              []x509.OID{policy},
	}
	id := "psap.county.mock.test"
	var quad string
	var dns []string
	switch p {
	case Agency:
		quad, dns = "agencyId/"+id+"/urn:emergency:service:responder.psap,urn:emergency:service:responder.police.local/"+id, []string{id}
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	case Agent:
		id = "jsmith@psap.county.mock.test"
		quad = "agentId/" + id + "/Dispatching,CallTaking/psap.county.mock.test"
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	case Element, Service:
		id = "esrp.county.mock.test"
		idType := map[Profile]string{Element: "elementId", Service: "serviceId"}[p]
		quad, dns = idType+"/"+id+"/ESRP,Bridge/psap.county.mock.test", []string{id, "localhost"}
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ekuExt(t, true, oidServerAuth, oidClientAuth))
	case Signing:
		id = "log.county.mock.test"
		quad = "elementId/" + id + "/LoggingService/psap.county.mock.test"
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ekuExt(t, true, oidCodeSigning))
	}
	tmpl.Subject = pkix.Name{Country: []string{"US"}, Organization: []string{"Mock County PSAP"}, CommonName: id}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, quadSAN(t, quad, dns...))
	return tmpl
}

// replaceExt replaces (or adds) an extension in tmpl.ExtraExtensions.
func replaceExt(tmpl *x509.Certificate, e pkix.Extension) {
	for i, x := range tmpl.ExtraExtensions {
		if x.Id.Equal(e.Id) {
			tmpl.ExtraExtensions[i] = e
			return
		}
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, e)
}

func rawName(t testing.TB, atvs ...pkix.AttributeTypeAndValue) []byte {
	var seq pkix.RDNSequence
	for _, a := range atvs {
		seq = append(seq, pkix.RelativeDistinguishedNameSET{a})
	}
	return mustMarshal(t, seq)
}

func str(oid asn1.ObjectIdentifier, tag int, v string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{Type: oid, Value: asn1.RawValue{Tag: tag, Bytes: []byte(v)}}
}

type issued struct {
	cert   *x509.Certificate
	issuer *x509.Certificate
}

// build issues a certificate of profile p after applying mutate to its
// template; key, when not nil, replaces the subject public key.
func build(t *testing.T, p Profile, key crypto.PublicKey, mutate func(t *testing.T, tmpl *x509.Certificate)) issued {
	t.Helper()
	k, h := keys(), pki()
	var tmpl *x509.Certificate
	var pub crypto.PublicKey
	var parent *x509.Certificate
	var signer crypto.Signer
	switch p {
	case PCA:
		tmpl, pub, signer = pcaTmpl(t), &k.pca.PublicKey, k.pca
	case ICA:
		tmpl, pub, parent, signer = icaTmpl(t, 3, "ica2"), &k.ica3.PublicKey, h.ica2, k.ica2
	case Signing:
		tmpl, pub, parent, signer = eeTmpl(t, p), &k.ec.PublicKey, h.ica3, k.ica3
	default:
		tmpl, pub, parent, signer = eeTmpl(t, p), &k.ee.PublicKey, h.ica3, k.ica3
	}
	if key != nil {
		pub = key
	}
	if mutate != nil {
		mutate(t, tmpl)
	}
	return issued{create(t, tmpl, parent, pub, signer), parent}
}

func TestConformingProfiles(t *testing.T) {
	t.Parallel()
	h := pki()
	for _, p := range Profiles {
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()
			c := build(t, p, nil, nil)
			if fs := Check(c.cert, p, Options{Issuer: c.issuer}); len(fs) > 0 {
				t.Errorf("findings for a conforming %s certificate:\n%s", p, join(fs))
			}
			got, err := Detect(c.cert)
			if err != nil || got != p {
				t.Errorf("Detect = %q, %v; want %q", got, err, p)
			}
		})
	}
	t.Run("ica tier2", func(t *testing.T) {
		t.Parallel()
		if fs := Check(h.ica2, ICA, Options{Issuer: h.pca}); len(fs) > 0 {
			t.Errorf("findings:\n%s", join(fs))
		}
	})
}

func join(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString("  " + f.String() + "\n")
	}
	return b.String()
}

func TestViolations(t *testing.T) {
	t.Parallel()
	k, h := keys(), pki()
	tests := []struct {
		name    string
		profile Profile
		// key replaces the subject public key.
		key    crypto.PublicKey
		mutate func(t *testing.T, tmpl *x509.Certificate)
		// issuer overrides the issuing certificate passed to Check.
		issuer *x509.Certificate
		sev    Severity
		want   string
	}{
		{"agency with extKeyUsage", Agency, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, ekuExt(t, true, oidClientAuth))
		}, nil, Error, "extKeyUsage SHALL NOT"},
		{"element without CDP", Element, nil, func(t *testing.T, c *x509.Certificate) {
			c.CRLDistributionPoints = nil
		}, nil, Error, "cRLDistributionPoints is missing"},
		{"element EKU not critical", Element, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, ekuExt(t, false, oidServerAuth, oidClientAuth))
		}, nil, Error, "extKeyUsage criticality"},
		{"element EKU without clientAuth", Element, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, ekuExt(t, true, oidServerAuth))
		}, nil, Error, "id-kp-clientAuth is missing"},
		{"element without keyEncipherment", Element, nil, func(t *testing.T, c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageDigitalSignature
		}, nil, Error, "keyEncipherment is not set"},
		{"agent with keyEncipherment", Agent, nil, func(t *testing.T, c *x509.Certificate) {
			c.KeyUsage |= x509.KeyUsageKeyEncipherment
		}, nil, Error, "keyEncipherment is set"},
		{"keyUsage not critical", Agency, nil, func(t *testing.T, c *x509.Certificate) {
			// digitalSignature + nonRepudiation: BIT STRING 0b11000000, 6 unused bits.
			replaceExt(c, pkix.Extension{Id: oidKU, Value: mustMarshal(t, asn1.BitString{Bytes: []byte{0xc0}, BitLength: 2})})
		}, nil, Error, "keyUsage criticality"},
		{"wildcard dNSName", Element, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, quadSAN(t, "elementId/esrp.county.mock.test/ESRP/psap.county.mock.test", "esrp.county.mock.test", "*.county.mock.test"))
		}, nil, Error, "wildcard dNSName"},
		{"first dNSName is not the iD", Element, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, quadSAN(t, "elementId/esrp.county.mock.test/ESRP/psap.county.mock.test", "localhost", "esrp.county.mock.test"))
		}, nil, Error, "first dNSName"},
		{"agency without dNSName", Agency, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, quadSAN(t, "agencyId/psap.county.mock.test/urn:emergency:service:responder.psap/psap.county.mock.test"))
		}, nil, Error, "SHALL contain a dNSName"},
		{"CN is not the iD", Service, nil, func(t *testing.T, c *x509.Certificate) {
			c.Subject.CommonName = "other.county.mock.test"
		}, nil, Error, "SHALL equal the Quad ID iD"},
		{"wrong idType", Element, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, quadSAN(t, "agencyId/esrp.county.mock.test/ESRP/psap.county.mock.test", "esrp.county.mock.test"))
		}, nil, Error, `idType is "agencyId"`},
		{"quad without owner", Element, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, quadSAN(t, "elementId/esrp.county.mock.test/ESRP", "esrp.county.mock.test"))
		}, nil, Warn, "no owner"},
		{"quad as IA5String", Element, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, sanExt(t, OIDQuadID, "elementId/esrp.county.mock.test/ESRP/psap.county.mock.test", "ia5", "esrp.county.mock.test"))
		}, nil, Error, "not a UTF8String"},
		{"quad with wrong OID", Element, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, sanExt(t, asn1.ObjectIdentifier{1, 2, 3}, "elementId/esrp.county.mock.test/ESRP/psap.county.mock.test", "utf8", "esrp.county.mock.test"))
		}, nil, Error, "no Quad ID otherName"},
		{"agency owner is not its iD", Agency, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, quadSAN(t, "agencyId/psap.county.mock.test/urn:emergency:service:responder.psap/state.mock.test", "psap.county.mock.test"))
		}, nil, Error, "SHALL be the certificate's own iD"},
		{"no policy", Element, nil, func(t *testing.T, c *x509.Certificate) {
			c.Policies = nil
		}, nil, Error, "certificatePolicies is missing"},
		{"other policy", Element, nil, func(t *testing.T, c *x509.Certificate) {
			c.Policies = []x509.OID{mustOID(2, 23, 140, 1, 2, 2)}
		}, nil, Error, "does not assert 1.3.6.1.4.1.55670.1"},
		{"no AIA", Agent, nil, func(t *testing.T, c *x509.Certificate) {
			c.OCSPServer, c.IssuingCertificateURL = nil, nil
		}, nil, Error, "authorityInfoAccess is missing"},
		{"AIA without caIssuers", Agent, nil, func(t *testing.T, c *x509.Certificate) {
			c.IssuingCertificateURL = nil
		}, nil, Error, "no caIssuers"},
		{"ICA AIA without OCSP", ICA, nil, func(t *testing.T, c *x509.Certificate) {
			c.OCSPServer = nil
			c.IssuingCertificateURL = []string{base + "/certs/ica2.cer"}
		}, nil, Error, "no OCSP accessLocation"},
		{"EE validity four years", Agency, nil, func(t *testing.T, c *x509.Certificate) {
			c.NotAfter = start.AddDate(4, 0, 0)
		}, h.pca, Error, "maximum of 3 years"},
		{"EE validity 200 days", Agency, nil, func(t *testing.T, c *x509.Certificate) {
			c.NotAfter = start.AddDate(0, 0, 200)
		}, nil, Warn, "at most three months"},
		{"EE outlives its issuer", Agency, nil, func(t *testing.T, c *x509.Certificate) {
			c.NotAfter = h.ica3.NotAfter.Add(time.Hour)
		}, nil, Error, "not contained in the issuer's validity"},
		{"Tier-3 ICA pathlen not issuer minus one", ICA, nil, func(t *testing.T, c *x509.Certificate) {
			c.MaxPathLen, c.MaxPathLenZero = 1, false
		}, nil, Error, "issuer's minus one"},
		{"PCA with pathlen", PCA, nil, func(t *testing.T, c *x509.Certificate) {
			c.MaxPathLen = 2
		}, nil, Error, "SHALL be None"},
		{"PCA roles", PCA, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, quadSAN(t, "cAId/pca.mock.test/ICA/pca.mock.test"))
		}, nil, Error, `SHALL be "PCA"`},
		{"PCA OU", PCA, nil, func(t *testing.T, c *x509.Certificate) {
			c.Subject.OrganizationalUnit = []string{"Root"}
		}, nil, Error, "PCA-<serial number>"},
		{"ICA CN without tier", ICA, nil, func(t *testing.T, c *x509.Certificate) {
			c.Subject.CommonName = "Mock ICA"
		}, nil, Error, "ICA Tier<#>"},
		{"ICA key too small", ICA, &k.small.PublicKey, nil, nil, Error, "need at least 3072"},
		{"O as UTF8String although printable", Agency, nil, func(t *testing.T, c *x509.Certificate) {
			c.RawSubject = rawName(t, str(oidCountry, asn1.TagPrintableString, "US"), str(oidOrg, asn1.TagUTF8String, "Mock County PSAP"), str(oidCN, asn1.TagPrintableString, "psap.county.mock.test"))
		}, nil, Error, "SHALL be a PrintableString"},
		{"C as UTF8String", Agency, nil, func(t *testing.T, c *x509.Certificate) {
			c.RawSubject = rawName(t, str(oidCountry, asn1.TagUTF8String, "US"), str(oidOrg, asn1.TagPrintableString, "Mock County PSAP"), str(oidCN, asn1.TagPrintableString, "psap.county.mock.test"))
		}, nil, Error, "two-letter ISO 3166-1 code as PrintableString"},
		{"EE without C", Agency, nil, func(t *testing.T, c *x509.Certificate) {
			c.Subject.Country = nil
		}, nil, Error, "subject C is missing"},
		{"unknown critical extension", Element, nil, func(t *testing.T, c *x509.Certificate) {
			replaceExt(c, pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}})
		}, nil, Error, "unknown critical extension 1.2.3.4"},
		{"wrong issuer", Element, nil, nil, h.ica2, Error, "signature does not verify"},
		{"SKI not method 1", Agent, nil, func(t *testing.T, c *x509.Certificate) {
			c.SubjectKeyId = []byte{1, 2, 3, 4}
		}, nil, Error, "Method 1"},
		{"signing with RSA", Signing, &k.ee.PublicKey, nil, nil, Error, "256-bit (or larger) ECC"},
		{"EE asserts cA", Agent, nil, func(t *testing.T, c *x509.Certificate) {
			c.BasicConstraintsValid, c.IsCA = true, true
		}, nil, Error, "asserts cA"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := build(t, tc.profile, tc.key, tc.mutate)
			iss := c.issuer
			if tc.issuer != nil {
				iss = tc.issuer
			}
			fs := Check(c.cert, tc.profile, Options{Issuer: iss})
			for _, f := range fs {
				if f.Severity == tc.sev && strings.Contains(f.Msg, tc.want) {
					return
				}
			}
			t.Errorf("no %s finding containing %q; got:\n%s", tc.sev, tc.want, join(fs))
		})
	}
}

func TestSerialLength(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		bytes []byte
		bad   bool
	}{
		{[]byte{0x7f, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}, false}, // 20 octets
		{[]byte{0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}, true},  // 21 with sign octet
	} {
		c := build(t, Agent, nil, nil).cert
		c.SerialNumber = new(big.Int).SetBytes(tc.bytes)
		k := &checker{c: c, p: Agent}
		k.basics()
		got := false
		for _, f := range k.out {
			got = got || strings.Contains(f.Msg, "serialNumber is")
		}
		if got != tc.bad {
			t.Errorf("serial %x: finding = %t, want %t", tc.bytes, got, tc.bad)
		}
	}
}

func TestParseQuad(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want Quad
		bad  bool
	}{
		{in: "agencyId/a.test/r1,r2/a.test", want: Quad{"agencyId", "a.test", "r1,r2", "a.test"}},
		{in: "elementId/e.test/ESRP", want: Quad{"elementId", "e.test", "ESRP", ""}},
		{in: "agencyId/a.test", bad: true},
		{in: "a/b/c/d/e", bad: true},
		{in: "agencyId//r/a.test", bad: true},
	}
	for _, tc := range tests {
		q, err := ParseQuad(tc.in)
		if (err != nil) != tc.bad {
			t.Errorf("ParseQuad(%q) error = %v, want error %t", tc.in, err, tc.bad)
			continue
		}
		if !tc.bad && *q != tc.want {
			t.Errorf("ParseQuad(%q) = %+v, want %+v", tc.in, *q, tc.want)
		}
		if !tc.bad && q.String() != tc.in {
			t.Errorf("String() = %q, want %q", q.String(), tc.in)
		}
	}
}

func TestValidIDs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		s           string
		fqdn, agent bool
	}{
		{"psap.county.mock.test", true, true},
		{"a-b.c1.test", true, true},
		{"localhost", false, false},
		{"Upper.test", false, false},
		{"-a.test", false, false},
		{"*.county.test", false, false},
		{"jsmith@psap.county.test", false, true},
		{"j smith@psap.county.test", false, false},
		{"jsmith@localhost", false, false},
	} {
		if got := ValidFQDN(tc.s); got != tc.fqdn {
			t.Errorf("ValidFQDN(%q) = %t", tc.s, got)
		}
		if got := ValidAgentID(tc.s); got != tc.agent {
			t.Errorf("ValidAgentID(%q) = %t", tc.s, got)
		}
	}
}

func TestParseProfile(t *testing.T) {
	t.Parallel()
	for _, p := range Profiles {
		if got, err := ParseProfile(string(p)); err != nil || got != p {
			t.Errorf("ParseProfile(%q) = %q, %v", p, got, err)
		}
	}
	if _, err := ParseProfile("root"); err == nil {
		t.Error("ParseProfile(root) succeeded")
	}
}
