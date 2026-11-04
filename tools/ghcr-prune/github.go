// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	// apiVersion is the GitHub REST API version this client was written
	// against (docs.github.com/en/rest/packages/packages).
	apiVersion = "2026-03-10"
	perPage    = 100
	maxPages   = 50 // 5,000 versions; more means something is wrong
)

// githubAPI lists and deletes the versions of an organization's container
// package through the GitHub REST API.
type githubAPI struct {
	base, org, pkg, token string
	hc                    *http.Client
}

func (g *githubAPI) versionsURL() string {
	return g.base + "/orgs/" + url.PathEscape(g.org) + "/packages/container/" + url.PathEscape(g.pkg) + "/versions"
}

func (g *githubAPI) do(ctx context.Context, method, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", "mock-pca-ghcr-prune")
	resp, err := g.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api: %w", err)
	}
	return resp, nil
}

// listVersions returns every active version of the package.
func (g *githubAPI) listVersions(ctx context.Context) ([]pkgVersion, error) {
	var all []pkgVersion
	for page := 1; ; page++ {
		if page > maxPages {
			return nil, fmt.Errorf("listing versions: more than %d pages", maxPages)
		}
		u := g.versionsURL() + "?state=active&per_page=" + strconv.Itoa(perPage) + "&page=" + strconv.Itoa(page)
		got, err := g.listPage(ctx, u)
		if err != nil {
			return nil, err
		}
		all = append(all, got...)
		if len(got) < perPage {
			return all, nil
		}
	}
}

func (g *githubAPI) listPage(ctx context.Context, u string) ([]pkgVersion, error) {
	resp, err := g.do(ctx, http.MethodGet, u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listing versions: %s", resp.Status)
	}
	var raw []struct {
		ID        int64     `json:"id"`
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
		Metadata  struct {
			PackageType string `json:"package_type"`
			Container   *struct {
				Tags []string `json:"tags"`
			} `json:"container"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("listing versions: %w", err)
	}
	out := make([]pkgVersion, 0, len(raw))
	for _, r := range raw {
		if r.ID <= 0 || r.CreatedAt.IsZero() || r.Metadata.PackageType != "container" || r.Metadata.Container == nil {
			return nil, fmt.Errorf("listing versions: incomplete entry for version %d (%q)", r.ID, r.Name)
		}
		out = append(out, pkgVersion{ID: r.ID, Digest: r.Name, Tags: r.Metadata.Container.Tags, Created: r.CreatedAt})
	}
	return out, nil
}

func (g *githubAPI) deleteVersion(ctx context.Context, id int64) error {
	resp, err := g.do(ctx, http.MethodDelete, g.versionsURL()+"/"+strconv.FormatInt(id, 10))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("deleting version %d: %s", id, resp.Status)
	}
	return nil
}
