// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// errNestedIndex reports an image index that a kept image needs and whose
// own entries would therefore also need protecting; the policy does not
// cover that, so planning stops.
var errNestedIndex = errors.New("nested image index")

var (
	// shaTag matches the tags docker/metadata-action type=sha gives every
	// published image.
	shaTag = regexp.MustCompile(`^sha-[0-9a-f]{7,40}$`)
	digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Reasons logged with each step of a plan.
const (
	whyNamedTag   = "tagged other than sha-*"
	whyShaRecent  = "only sha-* tags, within retention"
	whyShaExpired = "only sha-* tags, retention expired"
	whyEntry      = "entry of a kept image index"
	whyReferrer   = "referrer of a kept manifest"
	whyUnneeded   = "untagged and not needed by a kept version"
)

// pkgVersion is one version of the container package, i.e. one manifest or
// image index in the registry.
type pkgVersion struct {
	ID      int64
	Digest  string
	Tags    []string
	Created time.Time
}

// manifest is what the planner needs from a manifest or image index.
type manifest struct {
	Index   bool    // an image index (OCI) or manifest list (Docker)
	Entries []entry // the index's manifests
	Subject string  // OCI subject digest, "" if none
}

type entry struct {
	Digest string
	Index  bool
}

// manifestSource fetches a verified manifest by digest.
type manifestSource interface {
	manifest(ctx context.Context, digest string) (manifest, error)
}

// step is the decision for one version.
type step struct {
	V      pkgVersion
	Delete bool
	Reason string
	index  bool // known to be an image index; used to order deletions
}

func (s step) action() string {
	if s.Delete {
		return "delete"
	}
	return "keep"
}

// makePlan decides for every version whether it is kept or deleted (see the
// package documentation for the policy). Kept versions come first, then the
// deletions in the order they should run: tagged versions, then untagged
// image indexes, then the remaining untagged versions, oldest first within
// each group. Deleting an index before the manifests it lists means an
// interrupted run never leaves a tagged image pointing at deleted manifests.
func makePlan(ctx context.Context, versions []pkgVersion, now time.Time, retention time.Duration, src manifestSource) ([]step, error) {
	steps := make([]step, len(versions))
	byDigest := make(map[string]int, len(versions))
	for i, v := range versions {
		if !digest.MatchString(v.Digest) {
			return nil, fmt.Errorf("version %d: unexpected name %q (want a sha256 digest)", v.ID, v.Digest)
		}
		if _, dup := byDigest[v.Digest]; dup {
			return nil, fmt.Errorf("two versions for digest %s", v.Digest)
		}
		byDigest[v.Digest] = i
		steps[i].V = v
	}

	// needed holds every digest a kept version depends on, kept versions
	// included; queue holds kept versions whose manifests are not read yet.
	needed := map[string]bool{}
	var queue []int
	keep := func(i int, why string) {
		steps[i].Delete, steps[i].Reason = false, why
		if !needed[steps[i].V.Digest] {
			needed[steps[i].V.Digest] = true
			queue = append(queue, i)
		}
	}
	for i, v := range versions {
		switch {
		case len(v.Tags) == 0:
			steps[i].Delete, steps[i].Reason = true, whyUnneeded // unless needed below
		case !onlyShaTags(v.Tags):
			keep(i, whyNamedTag)
		case now.Sub(v.Created) < retention:
			keep(i, whyShaRecent)
		default:
			steps[i].Delete, steps[i].Reason = true, whyShaExpired // unless needed below
		}
	}

	// Read every version's manifest once: indexes protect their entries,
	// referrers are protected by their subject. Repeat until nothing new is
	// needed, since an entry or referrer can itself have referrers.
	manifests := make([]*manifest, len(versions))
	read := func(i int) (*manifest, error) {
		if manifests[i] == nil {
			m, err := src.manifest(ctx, steps[i].V.Digest)
			if err != nil {
				return nil, err
			}
			manifests[i] = &m
			steps[i].index = m.Index
		}
		return manifests[i], nil
	}
	for {
		for len(queue) > 0 {
			i := queue[0]
			queue = queue[1:]
			m, err := read(i)
			if err != nil {
				return nil, err
			}
			for _, e := range m.Entries {
				if e.Index {
					return nil, fmt.Errorf("%w: %s lists the index %s", errNestedIndex, steps[i].V.Digest, e.Digest)
				}
				needed[e.Digest] = true
				if j, ok := byDigest[e.Digest]; ok && steps[j].Delete {
					keep(j, whyEntry)
				}
			}
		}
		added := false
		for i := range steps {
			if !steps[i].Delete || len(steps[i].V.Tags) != 0 {
				continue
			}
			m, err := read(i)
			if err != nil {
				return nil, err
			}
			if m.Subject == "" || !needed[m.Subject] {
				continue
			}
			if m.Index {
				return nil, fmt.Errorf("%w: %s is an index and a referrer of %s", errNestedIndex, steps[i].V.Digest, m.Subject)
			}
			keep(i, whyReferrer)
			added = true
		}
		if !added && len(queue) == 0 {
			break
		}
	}

	slices.SortStableFunc(steps, func(a, b step) int {
		return cmp.Or(
			cmp.Compare(order(a), order(b)),
			a.V.Created.Compare(b.V.Created),
			cmp.Compare(a.V.ID, b.V.ID),
		)
	})
	return steps, nil
}

func order(s step) int {
	switch {
	case !s.Delete:
		return 0
	case len(s.V.Tags) != 0:
		return 1
	case s.index:
		return 2
	}
	return 3
}

func onlyShaTags(tags []string) bool {
	for _, t := range tags {
		if !shaTag.MatchString(t) {
			return false
		}
	}
	return true
}
