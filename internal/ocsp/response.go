package ocsp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// The structures of an OCSPResponse (RFC 6960 4.2.1) as far as the caching
// headers need them: the thisUpdate and nextUpdate of its SingleResponses.

var oidBasicResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspResponse struct {
	Status        asn1.Enumerated
	ResponseBytes responseBytes `asn1:"explicit,tag:0,optional"`
}

type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Version     int `asn1:"explicit,tag:0,default:0,optional"`
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []singleResponse
	Extensions  []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type singleResponse struct {
	CertID     certID
	CertStatus asn1.RawValue
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

// parseBasicResponse returns the BasicOCSPResponse of a successful response.
func parseBasicResponse(der []byte) (*basicResponse, error) {
	var resp ocspResponse
	if rest, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("trailing data")
	}
	if resp.Status != 0 || !resp.ResponseBytes.ResponseType.Equal(oidBasicResponse) {
		return nil, fmt.Errorf("not a successful basic response (status %d)", resp.Status)
	}
	var basic basicResponse
	if rest, err := asn1.Unmarshal(resp.ResponseBytes.Response, &basic); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("trailing data in BasicOCSPResponse")
	}
	return &basic, nil
}

// validity returns the window in which a signed response is fresh: the
// latest thisUpdate and the earliest nextUpdate of its SingleResponses. A
// response without nextUpdate is an error (the responder always sets it,
// RFC 5019 2.2.4, RFC 9919 3.2.4).
func validity(der []byte) (thisUpdate, nextUpdate time.Time, err error) {
	basic, err := parseBasicResponse(der)
	if err != nil {
		return thisUpdate, nextUpdate, err
	}
	rs := basic.TBSResponseData.Responses
	if len(rs) == 0 {
		return thisUpdate, nextUpdate, errors.New("no SingleResponse")
	}
	for i, r := range rs {
		if r.NextUpdate.IsZero() {
			return thisUpdate, nextUpdate, errors.New("SingleResponse without nextUpdate")
		}
		if i == 0 || r.ThisUpdate.After(thisUpdate) {
			thisUpdate = r.ThisUpdate
		}
		if i == 0 || r.NextUpdate.Before(nextUpdate) {
			nextUpdate = r.NextUpdate
		}
	}
	return thisUpdate, nextUpdate, nil
}
