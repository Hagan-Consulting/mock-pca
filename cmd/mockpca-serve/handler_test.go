package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
	srv := httptest.NewServer(newHandler(root, slog.New(slog.DiscardHandler)))
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
		{"GET", "/ocsp/county", 501, "", ""},
		{"POST", "/ocsp/county", 501, "", ""},
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

func TestRunUsage(t *testing.T) {
	t.Parallel()
	if err := run(nil, io.Discard); err == nil {
		t.Error("run without -root succeeded")
	}
	if err := run([]string{"-root", filepath.Join(t.TempDir(), "missing")}, io.Discard); err == nil {
		t.Error("run with a missing root succeeded")
	}
}
