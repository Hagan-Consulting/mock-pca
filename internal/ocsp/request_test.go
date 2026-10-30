package ocsp

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// buildRequest encodes an OCSPRequest with one CertID per hash algorithm.
func buildRequest(t testing.TB, hashes ...asn1.ObjectIdentifier) []byte {
	t.Helper()
	var list []singleRequest
	for i, h := range hashes {
		list = append(list, singleRequest{ReqCert: certID{
			HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: h, Parameters: asn1.NullRawValue},
			IssuerNameHash: bytes.Repeat([]byte{1}, 20),
			IssuerKeyHash:  bytes.Repeat([]byte{2}, 20),
			SerialNumber:   big.NewInt(int64(1000 + i)),
		}})
	}
	der, err := asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{RequestList: list}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseRequest(t *testing.T) {
	t.Parallel()
	good := buildRequest(t, OIDSHA256, OIDSHA1)
	ids, err := ParseRequest(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || !ids[0].HashAlgorithm.Equal(OIDSHA256) || !ids[1].HashAlgorithm.Equal(OIDSHA1) ||
		ids[1].Serial.Int64() != 1001 {
		t.Errorf("ids = %+v", ids)
	}
	empty, err := asn1.Marshal(ocspRequest{})
	if err != nil {
		t.Fatal(err)
	}
	many := make([]asn1.ObjectIdentifier, maxCertIDs+1)
	for i := range many {
		many[i] = OIDSHA1
	}
	for name, der := range map[string][]byte{
		"empty input":        nil,
		"garbage":            []byte("garbage"),
		"trailing data":      append(append([]byte{}, good...), 0),
		"empty request list": empty,
		"too many CertIDs":   buildRequest(t, many...),
		"too large":          make([]byte, MaxRequestSize+1),
	} {
		if _, err := ParseRequest(der); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestReadRequest(t *testing.T) {
	t.Parallel()
	der, b64 := requestWithAllChars(t)
	tests := []struct {
		name   string
		method string
		body   []byte
		rest   string
		ok     bool
	}{
		{"POST", "POST", der, "", true},
		{"POST too large", "POST", make([]byte, MaxRequestSize+1), "", false},
		{"POST garbage", "POST", []byte("x"), "", false},
		{"GET escaped", "GET", nil, url.PathEscape(b64), true},
		{"GET %2F, raw + and =", "GET", nil, strings.ReplaceAll(b64, "/", "%2F"), true},
		{"GET raw /", "GET", nil, "MAo/MAo=", false},
		{"GET raw //", "GET", nil, "MAo//MAo=", false},
		{"GET without padding", "GET", nil, "MAo", false},
		{"GET whitespace", "GET", nil, "MAo%0A=", false},
		{"GET non-zero padding bits", "GET", nil, "MAp=", false},
		{"GET bad base64", "GET", nil, "%%%", false},
		{"GET not base64", "GET", nil, "not*base64", false},
		{"GET empty", "GET", nil, "", false},
		{"GET too long", "GET", nil, strings.Repeat("A", 4*MaxRequestSize), false},
		{"PUT", "PUT", der, "", false},
	}
	for _, tc := range tests {
		r := httptest.NewRequest(tc.method, "/ocsp/ca", bytes.NewReader(tc.body))
		got, ids, err := ReadRequest(r, tc.rest)
		if tc.ok {
			if err != nil || !bytes.Equal(got, der) || len(ids) != 1 {
				t.Errorf("%s: err %v, ids %v", tc.name, err, ids)
			}
		} else if err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	// A GET body is ignored.
	r := httptest.NewRequest(http.MethodGet, "/ocsp/ca", strings.NewReader("ignored"))
	if _, _, err := ReadRequest(r, url.PathEscape(b64)); err != nil {
		t.Errorf("GET with a body: %v", err)
	}
}

// requestWithAllChars returns a request whose base64 contains '+', '/' and
// '=', so that the GET cases exercise all three.
func requestWithAllChars(t *testing.T) ([]byte, string) {
	t.Helper()
	for n := 1; n < 5000; n++ {
		der := buildRequest(t, OIDSHA256)
		// Vary the serial number until the encoding has every character.
		var req ocspRequest
		if _, err := asn1.Unmarshal(der, &req); err != nil {
			t.Fatal(err)
		}
		c := &req.TBSRequest.RequestList[0].ReqCert
		h := sha256.Sum256([]byte{byte(n), byte(n >> 8)})
		c.IssuerNameHash, c.IssuerKeyHash = h[:20], h[12:]
		c.SerialNumber = new(big.Int).Lsh(big.NewInt(int64(n)), uint(n%17))
		der, err := asn1.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		b64 := base64.StdEncoding.EncodeToString(der)
		if strings.Contains(b64, "+") && strings.Contains(b64, "/") && strings.HasSuffix(b64, "=") {
			return der, b64
		}
	}
	t.Fatal("no request encodes to base64 with '+', '/' and '='")
	return nil, ""
}

func TestErrorResponse(t *testing.T) {
	t.Parallel()
	var resp struct {
		Status asn1.Enumerated
	}
	rest, err := asn1.Unmarshal(ErrorResponse(StatusUnauthorized), &resp)
	if err != nil || len(rest) > 0 || resp.Status != StatusUnauthorized {
		t.Errorf("ErrorResponse: %v %v %d", err, rest, resp.Status)
	}
}

func FuzzParseRequest(f *testing.F) {
	f.Add(buildRequest(f, OIDSHA256))
	f.Add(buildRequest(f, OIDSHA1, OIDSHA256))
	f.Add([]byte{0x30, 0x03, 0x30, 0x01, 0x30})
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, der []byte) {
		ids, err := ParseRequest(der)
		if err == nil && (len(ids) == 0 || len(ids) > maxCertIDs) {
			t.Fatalf("accepted %d CertIDs", len(ids))
		}
		if err != nil && !errors.Is(err, ErrMalformed) {
			t.Fatalf("error %v is not ErrMalformed", err)
		}
	})
}
