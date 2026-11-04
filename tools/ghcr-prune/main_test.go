// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testToken = "ghs_test-token"
	testActor = "ci-bot"
	bearer    = "registry-bearer"
)

// fakeGHCR serves the GitHub packages API and the registry for one package.
type fakeGHCR struct {
	t         *testing.T
	mu        sync.Mutex
	versions  []map[string]any
	manifests map[string][]byte // digest -> body
	deleted   []int64
	failGet   bool
	realm     string // overrides the token realm when set
	srv       *httptest.Server
}

func newFake(t *testing.T) *fakeGHCR {
	f := &fakeGHCR{t: t, manifests: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orgs/test-org/packages/container/test-pkg/versions", f.list)
	mux.HandleFunc("DELETE /orgs/test-org/packages/container/test-pkg/versions/{id}", f.del)
	mux.HandleFunc("GET /token", f.token)
	mux.HandleFunc("GET /v2/test-org/test-pkg/manifests/{digest}", f.manifest)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// add stores a manifest body and a package version for it.
func (f *fakeGHCR) add(id int64, body string, created time.Time, tags ...string) string {
	s := sha256.Sum256([]byte(body))
	dg := "sha256:" + hex.EncodeToString(s[:])
	f.manifests[dg] = []byte(body)
	if tags == nil {
		tags = []string{}
	}
	f.versions = append(f.versions, map[string]any{
		"id": id, "name": dg, "created_at": created.Format(time.RFC3339),
		"metadata": map[string]any{"package_type": "container", "container": map[string]any{"tags": tags}},
	})
	return dg
}

func (f *fakeGHCR) api(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("X-GitHub-Api-Version") != apiVersion {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (f *fakeGHCR) list(w http.ResponseWriter, r *http.Request) {
	if !f.api(w, r) {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 || per < 1 || r.URL.Query().Get("state") != "active" {
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}
	lo, hi := min((page-1)*per, len(f.versions)), min(page*per, len(f.versions))
	_ = json.NewEncoder(w).Encode(f.versions[lo:hi])
}

func (f *fakeGHCR) del(w http.ResponseWriter, r *http.Request) {
	if !f.api(w, r) {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	f.mu.Lock()
	f.deleted = append(f.deleted, id)
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeGHCR) token(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || u != testActor || p != testToken ||
		r.URL.Query().Get("scope") != "repository:test-org/test-pkg:pull" || r.URL.Query().Get("service") != "test-registry" {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"token": bearer})
}

func (f *fakeGHCR) manifest(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+bearer {
		realm := f.srv.URL + "/token"
		if f.realm != "" {
			realm = f.realm
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="test-registry",scope="repository:test-org/test-pkg:pull"`, realm))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, ok := f.manifests[r.PathValue("digest")]
	if !ok || f.failGet {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ociManifest)
	_, _ = w.Write(body)
}

func (f *fakeGHCR) args(extra ...string) []string {
	return append([]string{"-org", "test-org", "-package", "test-pkg", "-api-url", f.srv.URL, "-registry-url", f.srv.URL}, extra...)
}

func env(k string) string {
	return map[string]string{"GITHUB_TOKEN": testToken, "GITHUB_ACTOR": testActor}[k]
}

func index(entries ...string) string {
	var ms []string
	for _, e := range entries {
		ms = append(ms, fmt.Sprintf(`{"mediaType":%q,"digest":%q,"size":1}`, ociManifest, e))
	}
	return fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[%s]}`, ociIndex, strings.Join(ms, ","))
}

func plainManifest(name, subject string) string {
	s := ""
	if subject != "" {
		s = fmt.Sprintf(`,"subject":{"mediaType":%q,"digest":%q,"size":1}`, ociIndex, subject)
	}
	return fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"annotations":{"name":%q}%s}`, ociManifest, name, s)
}

// populate creates: a release index with two entries and an attestation, an
// expired sha-* index with one entry, and an unneeded untagged manifest.
func populate(f *fakeGHCR) {
	a := f.add(11, plainManifest("rel-amd64", ""), ago(40))
	b := f.add(12, plainManifest("rel-arm64", ""), ago(40))
	rel := f.add(10, index(a, b), ago(40), "0.1.1", "0.1", "latest", "sha-1234567")
	f.add(13, plainManifest("rel-attestation", rel), ago(40))
	c := f.add(21, plainManifest("old-amd64", ""), ago(20))
	f.add(20, index(c), ago(20), "sha-89abcde")
	f.add(30, plainManifest("leftover", ""), ago(2))
}

func TestRunDeletes(t *testing.T) {
	t.Parallel()
	f := newFake(t)
	populate(f)
	var log bytes.Buffer
	if err := run(context.Background(), f.args(), env, &log, now); err != nil {
		t.Fatalf("run: %v\n%s", err, &log)
	}
	// Tagged first, then untagged indexes, then other untagged versions
	// (oldest first).
	if want := []int64{20, 21, 30}; !slices.Equal(f.deleted, want) {
		t.Errorf("deleted %v, want %v\n%s", f.deleted, want, &log)
	}
	for _, s := range []string{"action=keep", "reason=\"" + whyReferrer + "\"", "delete=3", "deleted=3"} {
		if !strings.Contains(log.String(), s) {
			t.Errorf("log lacks %q", s)
		}
	}
	if strings.Contains(log.String(), testToken) || strings.Contains(log.String(), bearer) {
		t.Error("log contains a token")
	}
}

func TestRunPaginates(t *testing.T) {
	t.Parallel()
	f := newFake(t)
	for i := range perPage + 5 {
		f.add(int64(1000+i), plainManifest(fmt.Sprint("m", i), ""), ago(1), "edge"+strconv.Itoa(i))
	}
	f.add(5000, plainManifest("leftover", ""), ago(1))
	var log bytes.Buffer
	if err := run(context.Background(), f.args(), env, &log, now); err != nil {
		t.Fatalf("run: %v\n%s", err, &log)
	}
	if !slices.Equal(f.deleted, []int64{5000}) {
		t.Errorf("deleted %v, want [5000]", f.deleted)
	}
}

func TestRunDeletesNothing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		extra   []string
		setup   func(*fakeGHCR)
		wantErr error // nil: run succeeds
		anyErr  bool
	}{
		{name: "dry run", extra: []string{"-dry-run"}},
		{name: "too many deletions", extra: []string{"-max-deletions", "2"}, wantErr: errTooManyDeletions},
		{name: "manifest unavailable", setup: func(f *fakeGHCR) { f.failGet = true }, anyErr: true},
		{name: "token realm on another host", setup: func(f *fakeGHCR) { f.realm = "https://evil.test/token" }, anyErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFake(t)
			populate(f)
			if tc.setup != nil {
				tc.setup(f)
			}
			var log bytes.Buffer
			err := run(context.Background(), f.args(tc.extra...), env, &log, now)
			switch {
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Errorf("error %v, want %v", err, tc.wantErr)
			case tc.anyErr && err == nil:
				t.Error("no error")
			case tc.wantErr == nil && !tc.anyErr && err != nil:
				t.Errorf("run: %v", err)
			}
			if len(f.deleted) != 0 {
				t.Errorf("deleted %v", f.deleted)
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	t.Parallel()
	ok := []string{"-org", "hagan-consulting", "-package", "mock-pca"}
	tests := []struct {
		name string
		args []string
		env  func(string) string
		ok   bool
	}{
		{"defaults", ok, env, true},
		{"missing token", ok, func(string) string { return "" }, false},
		{"upper case org", []string{"-org", "Hagan-Consulting", "-package", "mock-pca"}, env, false},
		{"slash in package", []string{"-org", "o", "-package", "a/b"}, env, false},
		{"plain http", append(ok, "-api-url", "http://api.example.test"), env, false},
		{"loopback http", append(ok, "-api-url", "http://127.0.0.1:1"), env, true},
		{"url with credentials", append(ok, "-registry-url", "https://u:p@ghcr.io"), env, false},
		{"negative max", append(ok, "-max-deletions", "-1"), env, false},
		{"zero retention", append(ok, "-sha-retention", "0s"), env, false},
		{"extra argument", append(ok, "x"), env, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseConfig(tc.args, tc.env, &bytes.Buffer{})
			if (err == nil) != tc.ok {
				t.Errorf("parseConfig(%q) error = %v, want ok=%v", tc.args, err, tc.ok)
			}
		})
	}
}
