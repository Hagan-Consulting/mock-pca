// Package ocsp is the HTTP front end of the mock PCA's OCSP responders. It
// decodes and checks OCSP requests (RFC 6960 A.1, RFC 5019, RFC 9919), applies
// the fault injection configured for a CA, and has OpenSSL sign every
// response (`openssl ocsp -reqin … -respout …`, one run per request). Go code
// never signs anything (CLAUDE.md).
package ocsp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// MaxRequestSize is the largest OCSP request accepted (POST body or decoded
// GET path).
const MaxRequestSize = 64 << 10

// maxCertIDs bounds the requestList.
const maxCertIDs = 32

// Hash algorithm OIDs of CertIDs (RFC 9919 3.1.1: SHA-256, SHA-1 for RFC
// 5019 compatibility).
var (
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// ErrMalformed is returned for requests that are not a well-formed
// OCSPRequest; the responder answers malformedRequest.
var ErrMalformed = errors.New("malformed OCSP request")

// CertID is the part of a request's CertID the responder looks at.
type CertID struct {
	HashAlgorithm asn1.ObjectIdentifier
	Serial        *big.Int
}

type certID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

type singleRequest struct {
	ReqCert    certID
	Extensions asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type tbsRequest struct {
	Version       int           `asn1:"explicit,tag:0,default:0,optional"`
	RequestorName asn1.RawValue `asn1:"explicit,tag:1,optional"`
	RequestList   []singleRequest
	Extensions    asn1.RawValue `asn1:"explicit,tag:2,optional"`
}

type ocspRequest struct {
	TBSRequest tbsRequest
	Signature  asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// ParseRequest checks that der is exactly one OCSPRequest (RFC 6960 4.1.1)
// and returns its CertIDs.
func ParseRequest(der []byte) ([]CertID, error) {
	if len(der) == 0 || len(der) > MaxRequestSize {
		return nil, fmt.Errorf("%w: size %d", ErrMalformed, len(der))
	}
	var req ocspRequest
	rest, err := asn1.Unmarshal(der, &req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	list := req.TBSRequest.RequestList
	if len(list) == 0 || len(list) > maxCertIDs {
		return nil, fmt.Errorf("%w: %d CertIDs", ErrMalformed, len(list))
	}
	ids := make([]CertID, len(list))
	for i, r := range list {
		c := r.ReqCert
		if len(c.IssuerNameHash) == 0 || len(c.IssuerKeyHash) == 0 || c.SerialNumber == nil {
			return nil, fmt.Errorf("%w: incomplete CertID", ErrMalformed)
		}
		ids[i] = CertID{HashAlgorithm: c.HashAlgorithm.Algorithm, Serial: c.SerialNumber}
	}
	return ids, nil
}

// errTooLarge marks a request over MaxRequestSize.
var errTooLarge = fmt.Errorf("%w: larger than %d bytes", ErrMalformed, MaxRequestSize)

// ReadRequest returns the DER OCSP request of r: the body of a POST, or for a
// GET the escaped path remainder after the CA name (RFC 6960 A.1: the URL
// encoding of the base64 encoding of the DER request). The DER is checked
// with ParseRequest.
func ReadRequest(r *http.Request, escapedRest string) ([]byte, []CertID, error) {
	var der []byte
	switch r.Method {
	case http.MethodPost:
		b, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestSize+1))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: reading body: %v", ErrMalformed, err)
		}
		if len(b) > MaxRequestSize {
			return nil, nil, errTooLarge
		}
		der = b
	case http.MethodGet:
		b, err := decodeGET(escapedRest)
		if err != nil {
			return nil, nil, err
		}
		der = b
	default:
		return nil, nil, fmt.Errorf("method %s", r.Method)
	}
	ids, err := ParseRequest(der)
	if err != nil {
		return nil, nil, err
	}
	return der, ids, nil
}

// base64Repertoire is the alphabet of RFC 4648 section 4 with its padding.
var base64Repertoire = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

// decodeGET decodes a GET request strictly (the tool is a test target:
// clients that do not follow the RFCs fail visibly). RFC 9919 section 6: the
// request is base64 per RFC 4648 section 4, with nothing outside its
// alphabet, and URL-encoded per RFC 3986, where '/' separates path segments
// and so must be sent as %2F. RFC 4648 section 3.2: padding is required.
// Raw '+' and '=' are sub-delims, valid unescaped in a path.
func decodeGET(escaped string) ([]byte, error) {
	if escaped == "" {
		return nil, fmt.Errorf("%w: GET without a request", ErrMalformed)
	}
	// base64 of MaxRequestSize bytes, URL-escaped (up to 3 bytes per char).
	if len(escaped) > 3*base64.StdEncoding.EncodedLen(MaxRequestSize) {
		return nil, errTooLarge
	}
	if strings.Contains(escaped, "/") {
		return nil, fmt.Errorf("%w: unescaped '/' in GET request (RFC 9919 6, RFC 3986)", ErrMalformed)
	}
	s, err := url.PathUnescape(escaped)
	if err != nil {
		return nil, fmt.Errorf("%w: URL encoding: %v", ErrMalformed, err)
	}
	if !base64Repertoire.MatchString(s) {
		return nil, fmt.Errorf("%w: characters outside the base64 alphabet in GET request (RFC 9919 6)", ErrMalformed)
	}
	der, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 with padding required (RFC 4648 3.2, 4): %v", ErrMalformed, err)
	}
	if len(der) > MaxRequestSize {
		return nil, errTooLarge
	}
	return der, nil
}

// OCSPResponseStatus values (RFC 6960 4.2.1).
const (
	StatusMalformedRequest = 1
	StatusInternalError    = 2
	StatusTryLater         = 3
	StatusUnauthorized     = 6
)

// ErrorResponse is an unsigned OCSPResponse with only a responseStatus:
// SEQUENCE { ENUMERATED status }.
func ErrorResponse(status int) []byte {
	return []byte{0x30, 0x03, 0x0a, 0x01, byte(status)}
}
