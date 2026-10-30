package ocsp

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner stands in for openssl: it records the arguments and writes
// "signed:<signer>:<index>" to the -respout file.
type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	block chan struct{} // if set, Run waits for it (ignoring ctx, like a stuck process)
}

func (f *fakeRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, args)
	f.mu.Unlock()
	if f.block != nil {
		<-f.block
	}
	arg := func(name string) string { return args[slices.Index(args, name)+1] }
	out := "signed:" + filepath.Base(arg("-rsigner")) + ":" + arg("-index") + ":" + arg("-nmin")
	return nil, os.WriteFile(arg("-respout"), []byte(out), 0o600)
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
		for _, f := range []string{"ca.conf", "ca.pem", "ca.key", "index.txt", "ocsp/cert.pem", "ocsp/key.pem", "ocsp/rogue-cert.pem", "ocsp/rogue-key.pem"} {
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
	if resp.StatusCode != 200 || string(body) != "signed:cert.pem:"+index+":60" {
		t.Fatalf("POST: %d %q", resp.StatusCode, body)
	}
	if ct, cc := resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control"); ct != "application/ocsp-response" ||
		cc != "max-age=3600, public, no-transform, must-revalidate" || resp.Header.Get("Expires") == "" {
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
		if resp, body := get(t, srv, path); resp.StatusCode != 200 || !strings.HasPrefix(string(body), "signed:") {
			t.Errorf("GET %s: %d %q", path, resp.StatusCode, body)
		}
	}

	// CA-signed mode.
	if err := os.WriteFile(filepath.Join(pki, "ca", "county", "ocsp.conf"), []byte("signer=ca\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, body := post(t, srv, "/ocsp/county", der); !strings.HasPrefix(string(body), "signed:ca.pem:") {
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
	if _, body := post(t, srv, "/ocsp/county", sha1Req); !strings.HasPrefix(string(body), "signed:") {
		t.Errorf("sha1_only, SHA-1 CertID: %q", body)
	}

	setFault(t, pki, "county", "wrong_signer=1\n")
	if _, body := post(t, srv, "/ocsp/county", sha256Req); !strings.HasPrefix(string(body), "signed:rogue-cert.pem:") {
		t.Errorf("wrong_signer: %q", body)
	}

	setFault(t, pki, "county", "unknown=1\n")
	if _, body := post(t, srv, "/ocsp/county", sha256Req); !strings.HasPrefix(string(body), "signed:cert.pem:") ||
		strings.Contains(string(body), index) {
		t.Errorf("unknown: %q (want an empty index, not %s)", body, index)
	}

	setFault(t, pki, "county", "stale=1\n")
	before := run.count()
	_, first := post(t, srv, "/ocsp/county", sha256Req)
	resp, second := post(t, srv, "/ocsp/county", sha256Req)
	if !bytes.Equal(first, second) || !strings.HasSuffix(string(first), ":1") || run.count() != before+1 {
		t.Errorf("stale: %q / %q, %d openssl runs", first, second, run.count()-before)
	}
	if resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("stale Cache-Control %q", resp.Header.Get("Cache-Control"))
	}

	setFault(t, pki, "county", "delay_ms=300\n")
	start := time.Now()
	post(t, srv, "/ocsp/county", sha256Req)
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Errorf("delay: %v", d)
	}

	// Invalid entries are ignored; a missing file means no fault.
	setFault(t, pki, "county", "status=bogus\nnope=1\n")
	if _, body := post(t, srv, "/ocsp/county", sha256Req); !strings.HasPrefix(string(body), "signed:") {
		t.Errorf("invalid fault file: %q", body)
	}
	if err := os.Remove(filepath.Join(pki, "ca", "county", "ocsp-fault.conf")); err != nil {
		t.Fatal(err)
	}
	if _, body := post(t, srv, "/ocsp/county", sha256Req); body == nil || !strings.HasSuffix(string(body), ":60") {
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
	if body := <-done; !strings.HasPrefix(string(body), "signed:") {
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
