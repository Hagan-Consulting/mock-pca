package ocsp

import (
	"bytes"
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
	der := buildRequest(t, OIDSHA256)
	b64 := base64.StdEncoding.EncodeToString(der)
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
		{"GET unescaped slashes and plus", "GET", nil, b64, true},
		{"GET without padding", "GET", nil, strings.TrimRight(b64, "="), true},
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
