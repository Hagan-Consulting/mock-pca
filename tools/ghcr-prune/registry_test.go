// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManifestDigestMismatch(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ociManifest)
		_, _ = w.Write([]byte(plainManifest("not what was asked for", "")))
	}))
	t.Cleanup(srv.Close)
	r := &registry{base: srv.URL, repo: "o/p", hc: srv.Client()}
	_, err := r.manifest(context.Background(), d("something else"))
	if err == nil || !strings.Contains(err.Error(), "content has digest") {
		t.Fatalf("error %v, want a digest mismatch", err)
	}
}

func TestParseManifest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body, ct string
		want           manifest
		ok             bool
	}{
		{name: "oci index", body: index(d("a"), d("b")), ok: true,
			want: manifest{Index: true, Entries: []entry{{Digest: d("a")}, {Digest: d("b")}}}},
		{name: "docker list by content type", ct: dockerList, ok: true,
			body: `{"schemaVersion":2,"manifests":[{"mediaType":"` + dockerList + `","digest":"` + d("x") + `"}]}`,
			want: manifest{Index: true, Entries: []entry{{Digest: d("x"), Index: true}}}},
		{name: "referrer", body: plainManifest("att", d("img")), ok: true, want: manifest{Subject: d("img")}},
		{name: "docker manifest", ct: dockerManifest, body: `{"schemaVersion":2}`, ok: true},
		{name: "unknown type", body: `{"schemaVersion":2,"mediaType":"text/plain"}`},
		{name: "bad entry digest", body: `{"mediaType":"` + ociIndex + `","manifests":[{"digest":"sha256:x"}]}`},
		{name: "bad subject digest", body: `{"mediaType":"` + ociManifest + `","subject":{"digest":"md5:1"}}`},
		{name: "manifest with entries", body: `{"mediaType":"` + ociManifest + `","manifests":[]}`},
		{name: "not json", body: `<html>`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseManifest([]byte(tc.body), tc.ct)
			if (err == nil) != tc.ok {
				t.Fatalf("error = %v, want ok=%v", err, tc.ok)
			}
			if !tc.ok {
				return
			}
			if got.Index != tc.want.Index || got.Subject != tc.want.Subject || len(got.Entries) != len(tc.want.Entries) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range got.Entries {
				if got.Entries[i] != tc.want.Entries[i] {
					t.Errorf("entry %d: %+v, want %+v", i, got.Entries[i], tc.want.Entries[i])
				}
			}
		})
	}
}

func TestParseBearerChallenge(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in    string
		realm string
		ok    bool
	}{
		{`Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:o/p:pull"`, "https://ghcr.io/token", true},
		{`bearer realm="https://r/token"`, "https://r/token", true},
		{`Basic realm="x"`, "", false},
		{`Bearer realm=unquoted`, "", false},
		{`Bearer realm="a\"b"`, "", false},
		{`Bearer realm="a" service="b"`, "", false},
	}
	for _, tc := range tests {
		p, ok := parseBearerChallenge(tc.in)
		if ok != tc.ok || (ok && p["realm"] != tc.realm) {
			t.Errorf("parseBearerChallenge(%q) = %v, %v", tc.in, p, ok)
		}
	}
}
