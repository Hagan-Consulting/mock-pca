// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

package ocsp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner stands in for openssl: it records the arguments and writes an
// OCSPResponse to the -respout file whose thisUpdate is now (or the
// current second), whose nextUpdate is -nmin minutes later and whose
// signature bytes are the marker "signed:<signer dir>/<signer>:<index>:<nmin>".
type fakeRunner struct {
	mu      sync.Mutex
	calls   [][]string
	block   chan struct{} // if set, Run waits for it (ignoring ctx, like a stuck process)
	now     time.Time     // thisUpdate; the current second if zero
	garbage bool          // write bytes that are not an OCSPResponse
}

func (f *fakeRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, args)
	f.mu.Unlock()
	if f.block != nil {
		<-f.block
	}
	arg := func(name string) string { return args[slices.Index(args, name)+1] }
	signer := arg("-rsigner")
	marker := "signed:" + filepath.Base(filepath.Dir(signer)) + "/" + filepath.Base(signer) + ":" + arg("-index") + ":" + arg("-nmin")
	if f.garbage {
		return nil, os.WriteFile(arg("-respout"), []byte(marker), 0o600)
	}
	nmin, err := strconv.Atoi(arg("-nmin"))
	if err != nil {
		return nil, err
	}
	this := f.now
	if this.IsZero() {
		this = time.Now().UTC().Truncate(time.Second)
	}
	der, err := fakeResponse(marker, this, this.Add(time.Duration(nmin)*time.Minute))
	if err != nil {
		return nil, err
	}
	return nil, os.WriteFile(arg("-respout"), der, 0o600)
}

// fakeResponse encodes a successful basic OCSPResponse with one 'good'
// SingleResponse and the marker as signature bytes.
func fakeResponse(marker string, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	keyHash, err := asn1.Marshal(bytes.Repeat([]byte{3}, 20))
	if err != nil {
		return nil, err
	}
	basic, err := asn1.Marshal(basicResponse{
		TBSResponseData: responseData{
			ResponderID: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: keyHash},
			ProducedAt:  thisUpdate,
			Responses: []singleResponse{{
				CertID: certID{
					HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: OIDSHA256, Parameters: asn1.NullRawValue},
					IssuerNameHash: bytes.Repeat([]byte{1}, 32),
					IssuerKeyHash:  bytes.Repeat([]byte{2}, 32),
					SerialNumber:   big.NewInt(1000),
				},
				CertStatus: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0},
				ThisUpdate: thisUpdate,
				NextUpdate: nextUpdate,
			}},
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: asn1.NullRawValue},
		Signature:          asn1.BitString{Bytes: []byte(marker), BitLength: 8 * len(marker)},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ocspResponse{ResponseBytes: responseBytes{ResponseType: oidBasicResponse, Response: basic}})
}

// marker returns the signature bytes of a fakeResponse ("" if it is none).
func marker(der []byte) string {
	basic, err := parseBasicResponse(der)
	if err != nil {
		return ""
	}
	return string(basic.Signature.Bytes)
}

func (f *fakeRunner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// newPKI creates ca/<name>/ with the files the responder needs.
func newPKI(t *testing.T, cas ...string) string {
	t.Helper()
	pki := t.TempDir()
	for _, ca := range cas {
		d := filepath.Join(pki, "ca", ca)
		for _, f := range []string{"ca.conf", "ca.pem", "ca.key", "index.txt", "ocsp/cert.pem", "ocsp/key.pem",
			"ocsp/rogue-cert.pem", "ocsp/rogue-key.pem", "ocsp/negative-no-nocheck/cert.pem", "ocsp/negative-no-nocheck/key.pem"} {
			p := filepath.Join(d, f)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return pki
}

func newResponder(t *testing.T, pki string, run Runner, cfg Config) *httptest.Server {
	t.Helper()
	cfg.PKI, cfg.Runner, cfg.Log = pki, run, slog.New(slog.DiscardHandler)
	if cfg.NMin == 0 {
		cfg.NMin = 60
	}
	rs, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(rs)
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, srv *httptest.Server, path string, body []byte) (*http.Response, []byte) {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+path, "application/ocsp-request", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func get(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func setFault(t *testing.T, pki, ca, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(pki, "ca", ca, "ocsp-fault.conf"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResponder(t *testing.T) {
	t.Parallel()
	pki := newPKI(t, "county")
	run := &fakeRunner{}
	srv := newResponder(t, pki, run, Config{})
	der := buildRequest(t, OIDSHA256)
	index := filepath.Join(pki, "ca", "county", "index.txt")

	resp, body := post(t, srv, "/ocsp/county", der)
	if resp.StatusCode != 200 || marker(body) != "signed:ocsp/cert.pem:"+index+":60" {
		t.Fatalf("POST: %d %q", resp.StatusCode, body)
	}
	if ct, cc := resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control"); ct != "application/ocsp-response" ||
		!regexp.MustCompile(`^max-age=35[0-9][0-9], public, no-transform, must-revalidate$`).MatchString(cc) ||
		resp.Header.Get("Expires") == "" || resp.Header.Get("ETag") == "" {
		t.Errorf("headers: %v", resp.Header)
	}
	args := run.calls[0]
	for _, want := range [][]string{
		{"-CA", filepath.Join(pki, "ca", "county", "ca.pem")},
		{"-rkey", filepath.Join(pki, "ca", "county", "ocsp", "key.pem")},
		{"-rmd", "sha256"},
	} {
		if i := slices.Index(args, want[0]); i < 0 || args[i+1] != want[1] {
			t.Errorf("args %v: want %v", args, want)
		}
	}

	b64 := base64.StdEncoding.EncodeToString(der)
	for _, path := range []string{"/ocsp/county/" + url.PathEscape(b64), "/ocsp/county/" + strings.ReplaceAll(b64, "/", "%2F")} {
		if resp, body := get(t, srv, path); resp.StatusCode != 200 || !strings.HasPrefix(marker(body), "signed:") {
			t.Errorf("GET %s: %d %q", path, resp.StatusCode, body)
		}
	}

	// CA-signed mode.
	if err := os.WriteFile(filepath.Join(pki, "ca", "county", "ocsp.conf"), []byte("signer=ca\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, body := post(t, srv, "/ocsp/county", der); !strings.HasPrefix(marker(body), "signed:county/ca.pem:") {
		t.Errorf("CA-signed mode: %q", body)
	}

	for name, tc := range map[string]struct {
		path string
		body []byte
		want int
	}{
		"unknown CA":        {"/ocsp/nope", der, StatusUnauthorized},
		"invalid CA name":   {"/ocsp/..%2Fca", der, StatusUnauthorized},
		"malformed request": {"/ocsp/county", []byte("garbage"), StatusMalformedRequest},
		"too large":         {"/ocsp/county", make([]byte, MaxRequestSize+1), StatusMalformedRequest},
	} {
		resp, body := post(t, srv, tc.path, tc.body)
		if resp.StatusCode != 200 || !bytes.Equal(body, ErrorResponse(tc.want)) {
			t.Errorf("%s: %d %x, want status %d", name, resp.StatusCode, body, tc.want)
		}
	}
	if resp, body := get(t, srv, "/ocsp/county/%25%25"); !bytes.Equal(body, ErrorResponse(StatusMalformedRequest)) {
		t.Errorf("bad GET: %d %x", resp.StatusCode, body)
	}
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/ocsp/county", bytes.NewReader(der))
	if resp, err := srv.Client().Do(req); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %v %v", resp, err)
	}
}

func TestFaults(t *testing.T) {
	t.Parallel()
	pki := newPKI(t, "county")
	run := &fakeRunner{}
	srv := newResponder(t, pki, run, Config{})
	sha256Req, sha1Req := buildRequest(t, OIDSHA256), buildRequest(t, OIDSHA1)
	index := filepath.Join(pki, "ca", "county", "index.txt")

	setFault(t, pki, "county", "http_status=503\n")
	if resp, _ := post(t, srv, "/ocsp/county", sha256Req); resp.StatusCode != 503 {
		t.Errorf("http_status: %d", resp.StatusCode)
	}
	for name, want := range map[string]int{"unauthorized": 6, "malformedRequest": 1, "tryLater": 3} {
		setFault(t, pki, "county", "status="+name+"\n")
		if _, body := post(t, srv, "/ocsp/county", sha256Req); !bytes.Equal(body, ErrorResponse(want)) {
			t.Errorf("status=%s: %x", name, body)
		}
	}

	setFault(t, pki, "county", "sha1_only=1\n")
	if _, body := post(t, srv, "/ocsp/county", sha256Req); !bytes.Equal(body, ErrorResponse(StatusUnauthorized)) {
		t.Errorf("sha1_only, SHA-256 CertID: %x", body)
	}
	if _, body := post(t, srv, "/ocsp/county", sha1Req); !strings.HasPrefix(marker(body), "signed:") {
		t.Errorf("sha1_only, SHA-1 CertID: %q", body)
	}

	setFault(t, pki, "county", "wrong_signer=1\n")
	if _, body := post(t, srv, "/ocsp/county", sha256Req); !strings.HasPrefix(marker(body), "signed:ocsp/rogue-cert.pem:") {
		t.Errorf("wrong_signer: %q", body)
	}

	setFault(t, pki, "county", "no_nocheck=1\n")
	if _, body := post(t, srv, "/ocsp/county", sha256Req); !strings.HasPrefix(marker(body), "signed:negative-no-nocheck/cert.pem:") {
		t.Errorf("no_nocheck: %q", marker(body))
	}

	setFault(t, pki, "county", "unknown=1\n")
	if _, body := post(t, srv, "/ocsp/county", sha256Req); !strings.HasPrefix(marker(body), "signed:ocsp/cert.pem:") ||
		strings.Contains(marker(body), index) {
		t.Errorf("unknown: %q (want an empty index, not %s)", body, index)
	}

	setFault(t, pki, "county", "stale=1\n")
	before := run.count()
	resp1, first := post(t, srv, "/ocsp/county", sha256Req)
	resp, second := post(t, srv, "/ocsp/county", sha256Req)
	if !bytes.Equal(first, second) || !strings.HasSuffix(marker(first), ":1") || run.count() != before+1 {
		t.Errorf("stale: %q / %q, %d openssl runs", marker(first), marker(second), run.count()-before)
	}
	// The replay carries its own (signed) times, not no-cache.
	if cc := resp.Header.Get("Cache-Control"); !strings.HasPrefix(cc, "max-age=") ||
		resp.Header.Get("Expires") != resp1.Header.Get("Expires") {
		t.Errorf("stale replay headers: %v", resp.Header)
	}

	setFault(t, pki, "county", "delay_ms=300\n")
	start := time.Now()
	post(t, srv, "/ocsp/county", sha256Req)
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Errorf("delay: %v", d)
	}

	// Invalid entries are ignored; a missing file means no fault.
	setFault(t, pki, "county", "status=bogus\nnope=1\n")
	if _, body := post(t, srv, "/ocsp/county", sha256Req); !strings.HasPrefix(marker(body), "signed:") {
		t.Errorf("invalid fault file: %q", body)
	}
	if err := os.Remove(filepath.Join(pki, "ca", "county", "ocsp-fault.conf")); err != nil {
		t.Fatal(err)
	}
	if _, body := post(t, srv, "/ocsp/county", sha256Req); body == nil || !strings.HasSuffix(marker(body), ":60") {
		t.Errorf("cleared: %q", body)
	}
}

func TestBusy(t *testing.T) {
	t.Parallel()
	pki := newPKI(t, "county")
	run := &fakeRunner{block: make(chan struct{})}
	srv := newResponder(t, pki, run, Config{MaxConcurrent: 1, Timeout: 200 * time.Millisecond})
	der := buildRequest(t, OIDSHA256)
	done := make(chan []byte)
	go func() {
		resp, err := srv.Client().Post(srv.URL+"/ocsp/county", "application/ocsp-request", bytes.NewReader(der))
		if err != nil {
			done <- nil
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- b
	}()
	for run.count() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if _, body := post(t, srv, "/ocsp/county", der); !bytes.Equal(body, ErrorResponse(StatusTryLater)) {
		t.Errorf("second request while the slot is taken: %x, want tryLater", body)
	}
	close(run.block)
	if body := <-done; !strings.HasPrefix(marker(body), "signed:") {
		t.Errorf("first request: %q", body)
	}
}

func TestMissingSigner(t *testing.T) {
	t.Parallel()
	pki := newPKI(t, "county")
	if err := os.Remove(filepath.Join(pki, "ca", "county", "ocsp", "cert.pem")); err != nil {
		t.Fatal(err)
	}
	srv := newResponder(t, pki, &fakeRunner{}, Config{})
	if _, body := post(t, srv, "/ocsp/county", buildRequest(t, OIDSHA256)); !bytes.Equal(body, ErrorResponse(StatusInternalError)) {
		t.Errorf("missing responder certificate: %x", body)
	}
}

func TestNewValidates(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	for _, cfg := range []Config{
		{Runner: &fakeRunner{}, Log: log, NMin: 1},
		{PKI: "x", Log: log, NMin: 1},
		{PKI: "x", Runner: &fakeRunner{}, Log: log, NMin: 0},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

// TestCachingHeaders checks the headers of RFC 9919 sections 6 and 7.2 with a
// fixed clock: Last-Modified = thisUpdate, Expires = nextUpdate, max-age
// ending before nextUpdate, ETag = hex SHA-256 of the response.
func TestCachingHeaders(t *testing.T) {
	t.Parallel()
	this := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	der := buildRequest(t, OIDSHA256)
	for _, tc := range []struct {
		name   string
		now    time.Time
		maxAge string
	}{
		{"just signed", this.Add(500 * time.Millisecond), "3598"},
		{"a second before nextUpdate", this.Add(59*time.Minute + 59*time.Second), "0"},
		{"just before nextUpdate", this.Add(59*time.Minute + 59*time.Second + 600*time.Millisecond), "0"},
		{"past nextUpdate", this.Add(2 * time.Hour), "0"},
	} {
		pki := newPKI(t, "county")
		srv := newResponder(t, pki, &fakeRunner{now: this}, Config{Now: func() time.Time { return tc.now }})
		resp, body := post(t, srv, "/ocsp/county", der)
		sum := sha256.Sum256(body)
		want := map[string]string{
			"Cache-Control": "max-age=" + tc.maxAge + ", public, no-transform, must-revalidate",
			"Last-Modified": "Fri, 30 Oct 2026 12:00:00 GMT",
			"Expires":       "Fri, 30 Oct 2026 13:00:00 GMT",
			"ETag":          `"` + hex.EncodeToString(sum[:]) + `"`,
		}
		for k, v := range want {
			if got := resp.Header.Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", tc.name, k, got, v)
			}
		}
	}

	// Error responses are not authoritative: no-cache, no validators.
	pki := newPKI(t, "county")
	srv := newResponder(t, pki, &fakeRunner{}, Config{})
	resp, _ := post(t, srv, "/ocsp/county", []byte("garbage"))
	if resp.Header.Get("Cache-Control") != "no-cache" || resp.Header.Get("ETag") != "" || resp.Header.Get("Expires") != "" {
		t.Errorf("error response headers: %v", resp.Header)
	}
}

// TestUnreadableSignedResponse: a signed response whose times cannot be read
// is not passed on.
func TestUnreadableSignedResponse(t *testing.T) {
	t.Parallel()
	pki := newPKI(t, "county")
	srv := newResponder(t, pki, &fakeRunner{garbage: true}, Config{})
	if _, body := post(t, srv, "/ocsp/county", buildRequest(t, OIDSHA256)); !bytes.Equal(body, ErrorResponse(StatusInternalError)) {
		t.Errorf("unreadable response: %x, want internalError", body)
	}
}
