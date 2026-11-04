// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// d returns a stable fake digest for a short name.
func d(name string) string {
	s := sha256.Sum256([]byte(name))
	return "sha256:" + hex.EncodeToString(s[:])
}

type fakeSource map[string]manifest

func (f fakeSource) manifest(_ context.Context, dg string) (manifest, error) {
	m, ok := f[dg]
	if !ok {
		return manifest{}, fmt.Errorf("no manifest %s", dg)
	}
	return m, nil
}

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func ago(days int) time.Time { return now.Add(-time.Duration(days) * 24 * time.Hour) }

// image returns versions and manifests for a multi-arch index named n with
// two platform manifests and two attestation manifests (BuildKit layout).
func image(n string, id int64, created time.Time, tags ...string) ([]pkgVersion, fakeSource) {
	children := []string{n + "/amd64", n + "/arm64", n + "/att-amd64", n + "/att-arm64"}
	vs := []pkgVersion{{ID: id, Digest: d(n), Tags: tags, Created: created}}
	src := fakeSource{}
	idx := manifest{Index: true}
	for i, c := range children {
		vs = append(vs, pkgVersion{ID: id + int64(i) + 1, Digest: d(c), Created: created})
		src[d(c)] = manifest{}
		idx.Entries = append(idx.Entries, entry{Digest: d(c)})
	}
	src[d(n)] = idx
	return vs, src
}

func merge(parts ...any) ([]pkgVersion, fakeSource) {
	var vs []pkgVersion
	src := fakeSource{}
	for i := 0; i < len(parts); i += 2 {
		vs = append(vs, parts[i].([]pkgVersion)...)
		for k, v := range parts[i+1].(fakeSource) {
			src[k] = v
		}
	}
	return vs, src
}

func decisions(steps []step) map[string]string {
	out := map[string]string{}
	for _, s := range steps {
		out[s.V.Digest] = s.action() + ": " + s.Reason
	}
	return out
}

func TestMakePlan(t *testing.T) {
	t.Parallel()
	const retention = 14 * 24 * time.Hour

	release, releaseSrc := image("release", 100, ago(60), "0.1.1", "0.1", "latest", "sha-1111111")
	edge, edgeSrc := image("edge", 200, ago(30), "edge", "sha-2222222")
	recent, recentSrc := image("recent", 300, ago(13), "sha-3333333")
	expired, expiredSrc := image("expired", 400, ago(15), "sha-4444444")
	orphan, orphanSrc := image("orphan", 500, ago(1)) // index untagged: its tag moved
	att := pkgVersion{ID: 600, Digest: d("attestation"), Created: ago(60)}
	attOrphan := pkgVersion{ID: 601, Digest: d("attestation-orphan"), Created: ago(15)}
	perArch := pkgVersion{ID: 700, Digest: d("old-per-arch"), Tags: []string{"0.1.0-amd64"}, Created: ago(70)}

	vs, src := merge(release, releaseSrc, edge, edgeSrc, recent, recentSrc, expired, expiredSrc, orphan, orphanSrc)
	vs = append(vs, att, attOrphan, perArch)
	src[d("attestation")] = manifest{Subject: d("release")}
	src[d("attestation-orphan")] = manifest{Subject: d("expired")}
	src[d("old-per-arch")] = manifest{}

	steps, err := makePlan(context.Background(), vs, now, retention, src)
	if err != nil {
		t.Fatal(err)
	}
	got := decisions(steps)
	want := map[string]string{
		d("release"):            "keep: " + whyNamedTag,
		d("edge"):               "keep: " + whyNamedTag,
		d("recent"):             "keep: " + whyShaRecent,
		d("expired"):            "delete: " + whyShaExpired,
		d("orphan"):             "delete: " + whyUnneeded,
		d("attestation"):        "keep: " + whyReferrer,
		d("attestation-orphan"): "delete: " + whyUnneeded,
		d("old-per-arch"):       "keep: " + whyNamedTag,
	}
	for _, n := range []string{"release", "edge", "recent"} {
		for _, c := range []string{"/amd64", "/arm64", "/att-amd64", "/att-arm64"} {
			want[d(n+c)] = "keep: " + whyEntry
		}
	}
	for _, n := range []string{"expired", "orphan"} {
		for _, c := range []string{"/amd64", "/arm64", "/att-amd64", "/att-arm64"} {
			want[d(n+c)] = "delete: " + whyUnneeded
		}
	}
	if len(got) != len(want) {
		t.Errorf("plan has %d steps, want %d", len(got), len(want))
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %q, want %q", k, got[k], w)
		}
	}

	// Order: kept, then tagged deletions, then untagged indexes, then the rest.
	var deleted []string
	for _, s := range steps {
		if s.Delete {
			deleted = append(deleted, s.V.Digest)
		}
	}
	if deleted[0] != d("expired") || deleted[1] != d("orphan") {
		t.Errorf("deletion order starts %v, want expired index then orphan index", deleted[:2])
	}
	firstDelete := slices.IndexFunc(steps, func(s step) bool { return s.Delete })
	if slices.ContainsFunc(steps[firstDelete:], func(s step) bool { return !s.Delete }) {
		t.Error("a kept version is listed after a deletion")
	}
}

func TestMakePlanSharedEntries(t *testing.T) {
	t.Parallel()
	// An expired index and a kept one listing the same platform manifest
	// (the same build tagged twice): the shared manifest stays.
	vs := []pkgVersion{
		{ID: 1, Digest: d("old"), Tags: []string{"sha-aaaaaaa"}, Created: ago(20)},
		{ID: 2, Digest: d("new"), Tags: []string{"edge"}, Created: ago(1)},
		{ID: 3, Digest: d("shared"), Created: ago(20)},
		{ID: 4, Digest: d("only-old"), Created: ago(20)},
	}
	src := fakeSource{
		d("old"):      {Index: true, Entries: []entry{{Digest: d("shared")}, {Digest: d("only-old")}}},
		d("new"):      {Index: true, Entries: []entry{{Digest: d("shared")}}},
		d("shared"):   {},
		d("only-old"): {},
	}
	steps, err := makePlan(context.Background(), vs, now, 14*24*time.Hour, src)
	if err != nil {
		t.Fatal(err)
	}
	got := decisions(steps)
	for dg, w := range map[string]string{d("old"): "delete", d("new"): "keep", d("shared"): "keep", d("only-old"): "delete"} {
		if !strings.HasPrefix(got[dg], w+":") {
			t.Errorf("%s: %q, want %s", dg, got[dg], w)
		}
	}
}

func TestMakePlanReferrerChain(t *testing.T) {
	t.Parallel()
	// A signature on an attestation on a kept image: both stay.
	vs := []pkgVersion{
		{ID: 1, Digest: d("img"), Tags: []string{"latest"}, Created: ago(1)},
		{ID: 2, Digest: d("sig"), Created: ago(1)},
		{ID: 3, Digest: d("att"), Created: ago(1)},
	}
	src := fakeSource{
		d("img"): {},
		d("att"): {Subject: d("img")},
		d("sig"): {Subject: d("att")},
	}
	steps, err := makePlan(context.Background(), vs, now, time.Hour, src)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if s.Delete {
			t.Errorf("%s deleted (%s)", s.V.Digest, s.Reason)
		}
	}
}

func TestMakePlanErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		vs   []pkgVersion
		src  fakeSource
		want error
	}{
		{
			name: "nested index",
			vs:   []pkgVersion{{ID: 1, Digest: d("a"), Tags: []string{"latest"}, Created: ago(1)}},
			src:  fakeSource{d("a"): {Index: true, Entries: []entry{{Digest: d("b"), Index: true}}}},
			want: errNestedIndex,
		},
		{
			name: "index referrer of a kept image",
			vs: []pkgVersion{
				{ID: 1, Digest: d("a"), Tags: []string{"latest"}, Created: ago(1)},
				{ID: 2, Digest: d("b"), Created: ago(1)},
			},
			src:  fakeSource{d("a"): {}, d("b"): {Index: true, Subject: d("a")}},
			want: errNestedIndex,
		},
		{
			name: "manifest missing",
			vs: []pkgVersion{
				{ID: 1, Digest: d("a"), Tags: []string{"latest"}, Created: ago(1)},
				{ID: 2, Digest: d("b"), Created: ago(1)},
			},
			src: fakeSource{d("a"): {}},
		},
		{
			name: "duplicate digest",
			vs: []pkgVersion{
				{ID: 1, Digest: d("a"), Created: ago(1)},
				{ID: 2, Digest: d("a"), Created: ago(1)},
			},
			src: fakeSource{d("a"): {}},
		},
		{
			name: "name is not a digest",
			vs:   []pkgVersion{{ID: 1, Digest: "latest", Created: ago(1)}},
			src:  fakeSource{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := makePlan(context.Background(), tc.vs, now, time.Hour, tc.src)
			if err == nil {
				t.Fatal("no error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error %v, want %v", err, tc.want)
			}
		})
	}
}

func TestOnlyShaTags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tags []string
		want bool
	}{
		{[]string{"sha-0123abc"}, true},
		{[]string{"sha-0123abc", "sha-" + strings.Repeat("a", 40)}, true},
		{[]string{"sha-0123abc", "edge"}, false},
		{[]string{"sha-0123ab"}, false},  // too short
		{[]string{"sha-0123ABC"}, false}, // upper case
		{[]string{"sha-0123abc-amd64"}, false},
		{[]string{"0.1.1"}, false},
	}
	for _, tc := range tests {
		if got := onlyShaTags(tc.tags); got != tc.want {
			t.Errorf("onlyShaTags(%q) = %v, want %v", tc.tags, got, tc.want)
		}
	}
}
