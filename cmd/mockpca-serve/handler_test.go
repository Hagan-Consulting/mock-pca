package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hagan-consulting/mock-pca/internal/ocsp"
)

func newTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	www := filepath.Join(dir, "www")
	for _, d := range []string{"certs", "crl"} {
		if err := os.MkdirAll(filepath.Join(www, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(www, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("certs/pca.cer", "cert-bytes")
	write("crl/county.crl", "crl-bytes")
	write("crl/.hidden.crl", "hidden")
	if err := os.WriteFile(filepath.Join(dir, "secret.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(dir, "secret.key"), filepath.Join(www, "crl", "escape.crl")); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(www)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	// The OCSP responder (internal/ocsp, tested there) is replaced by a stub
	// that shows the routing.
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	srv := httptest.NewServer(newHandler(root, stub, slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	return srv, www
}

func TestHandler(t *testing.T) {
	t.Parallel()
	srv, www := newTestServer(t)
	tests := []struct {
		method, path string
		status       int
		body, ctype  string
	}{
		{"GET", "/certs/pca.cer", 200, "cert-bytes", "application/pkix-cert"},
		{"HEAD", "/certs/pca.cer", 200, "", "application/pkix-cert"},
		{"GET", "/crl/county.crl", 200, "crl-bytes", "application/pkix-crl"},
		{"GET", "/crl/missing.crl", 404, "", ""},
		{"GET", "/crl/pca.cer", 404, "", ""},
		{"GET", "/certs/county.crl", 404, "", ""},
		{"GET", "/crl/.hidden.crl", 404, "", ""},
		{"GET", "/crl/..%2fsecret.key", 404, "", ""},
		{"GET", "/crl/escape.crl", 404, "", ""},
		{"GET", "/", 404, "", ""},
		{"POST", "/crl/county.crl", 405, "", ""},
		{"GET", "/ocsp/county/MAo%3D", http.StatusTeapot, "", ""},
		{"POST", "/ocsp/county", http.StatusTeapot, "", ""},
	}
	for _, tc := range tests {
		req, err := http.NewRequest(tc.method, srv.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Errorf("%s %s: status %d, want %d", tc.method, tc.path, resp.StatusCode, tc.status)
			continue
		}
		if tc.status != 200 {
			continue
		}
		if string(body) != tc.body {
			t.Errorf("%s %s: body %q, want %q", tc.method, tc.path, body, tc.body)
		}
		if got := resp.Header.Get("Content-Type"); got != tc.ctype {
			t.Errorf("%s %s: Content-Type %q, want %q", tc.method, tc.path, got, tc.ctype)
		}
	}

	// A republished CRL is served without restarting.
	if err := os.WriteFile(filepath.Join(www, "crl", "county.crl"), []byte("new-crl"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Get(srv.URL + "/crl/county.crl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); string(b) != "new-crl" {
		t.Errorf("after republishing: body %q", b)
	}
}

// TestRevalidation: a CRL republished within the same second as a client's
// fetch must not be answered 304 (http.ServeContent compares
// If-Modified-Since in whole seconds); revalidation uses the ETag.
func TestRevalidation(t *testing.T) {
	t.Parallel()
	srv, www := newTestServer(t)
	url := srv.URL + "/crl/county.crl"
	get := func(hdr map[string]string) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	first, _ := get(nil)
	etag, lastMod := first.Header.Get("ETag"), first.Header.Get("Last-Modified")
	if len(etag) != 66 || lastMod == "" {
		t.Fatalf("ETag %q, Last-Modified %q", etag, lastMod)
	}
	if resp, _ := get(map[string]string{"If-None-Match": etag}); resp.StatusCode != http.StatusNotModified {
		t.Errorf("If-None-Match with the current ETag: status %d, want 304", resp.StatusCode)
	}

	// Republish with the same modification time (same second).
	path := filepath.Join(www, "crl", "county.crl")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("republished"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	for _, hdr := range []map[string]string{
		{"If-None-Match": etag},
		{"If-Modified-Since": lastMod},
		{"If-None-Match": etag, "If-Modified-Since": lastMod},
	} {
		resp, body := get(hdr)
		if resp.StatusCode != http.StatusOK || body != "republished" {
			t.Errorf("%v after republishing: status %d, body %q; want 200 with the new CRL", hdr, resp.StatusCode, body)
		}
		if resp.Header.Get("ETag") == etag {
			t.Errorf("%v: ETag unchanged after republishing", hdr)
		}
	}
}

// noRedirect is a client that reports redirects instead of following them.
func noRedirect(srv *httptest.Server) *http.Client {
	c := *srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// TestOCSPBypassesPathCleaning: an OCSP GET with "//" reaches the responder
// unchanged, instead of being redirected by the ServeMux.
func TestOCSPBypassesPathCleaning(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	var seen string
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.EscapedPath()
		w.WriteHeader(http.StatusTeapot)
	})
	srv := httptest.NewServer(newHandler(root, stub, slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	resp, err := noRedirect(srv).Get(srv.URL + "/ocsp/county/MAo//MAo=")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot || seen != "/ocsp/county/MAo//MAo=" {
		t.Errorf("status %d, responder saw %q", resp.StatusCode, seen)
	}
}

// failRunner fails every openssl run: the strict GET checks answer before
// anything is signed.
type failRunner struct{}

func (failRunner) Run(context.Context, ...string) ([]byte, error) {
	return nil, errors.New("no openssl")
}

// TestStrictGET goes through newHandler and the real responder: an
// unescaped '/' or "//" and missing padding are malformedRequest, never a
// redirect.
func TestStrictGET(t *testing.T) {
	t.Parallel()
	pki := t.TempDir()
	for _, d := range []string{"www", "ca/county"} {
		if err := os.MkdirAll(filepath.Join(pki, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(pki, "ca/county/ca.conf"), []byte("profile=ica\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Join(pki, "www"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	log := slog.New(slog.DiscardHandler)
	responder, err := ocsp.New(ocsp.Config{PKI: pki, NMin: 60, Runner: failRunner{}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(root, responder, log))
	t.Cleanup(srv.Close)
	malformed := ocsp.ErrorResponse(ocsp.StatusMalformedRequest)
	for _, path := range []string{"/ocsp/county/MAo/MAo=", "/ocsp/county/MAo//MAo=", "/ocsp/county/MAo"} {
		resp, err := noRedirect(srv).Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !bytes.Equal(body, malformed) {
			t.Errorf("GET %s: status %d, body %x; want malformedRequest", path, resp.StatusCode, body)
		}
	}
}

func TestRunUsage(t *testing.T) {
	t.Parallel()
	if err := run(nil, io.Discard); err == nil {
		t.Error("run without -pki succeeded")
	}
	if err := run([]string{"-pki", filepath.Join(t.TempDir(), "missing")}, io.Discard); err == nil {
		t.Error("run with a missing PKI succeeded")
	}
	pki := t.TempDir()
	if err := os.Mkdir(filepath.Join(pki, "www"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-pki", pki, "-nmin", "0"}, io.Discard); err == nil || !strings.Contains(err.Error(), "nmin") {
		t.Errorf("run with -nmin 0: %v", err)
	}
}
