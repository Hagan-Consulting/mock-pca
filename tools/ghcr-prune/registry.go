// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// Manifest media types (OCI image spec, Docker image manifest v2).
const (
	ociIndex       = "application/vnd.oci.image.index.v1+json"
	ociManifest    = "application/vnd.oci.image.manifest.v1+json"
	dockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
)

// maxManifest bounds a manifest body (the distribution spec suggests
// registries accept at least 4 MiB).
const maxManifest = 4 << 20

// registry reads manifests from an OCI distribution registry, authenticating
// with the bearer token flow the registry announces on a 401.
type registry struct {
	base, repo     string
	user, password string
	hc             *http.Client
	bearer         string
}

func (r *registry) manifest(ctx context.Context, dgst string) (manifest, error) {
	if !digest.MatchString(dgst) {
		return manifest{}, fmt.Errorf("manifest: bad digest %q", dgst)
	}
	u := r.base + "/v2/" + r.repo + "/manifests/" + dgst
	resp, err := r.get(ctx, u)
	if err != nil {
		return manifest{}, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		if err := r.login(ctx, challenge); err != nil {
			return manifest{}, err
		}
		if resp, err = r.get(ctx, u); err != nil {
			return manifest{}, err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return manifest{}, fmt.Errorf("manifest %s: %s", dgst, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifest+1))
	if err != nil {
		return manifest{}, fmt.Errorf("manifest %s: %w", dgst, err)
	}
	if len(body) > maxManifest {
		return manifest{}, fmt.Errorf("manifest %s: larger than %d bytes", dgst, maxManifest)
	}
	sum := sha256.Sum256(body)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != dgst {
		return manifest{}, fmt.Errorf("manifest %s: content has digest %s", dgst, got)
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return parseManifest(body, ct)
}

func parseManifest(body []byte, contentType string) (manifest, error) {
	var raw struct {
		MediaType string `json:"mediaType"`
		Manifests []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"manifests"`
		Subject *struct {
			Digest string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return manifest{}, fmt.Errorf("parsing manifest: %w", err)
	}
	mt := raw.MediaType
	if mt == "" {
		mt = contentType
	}
	var m manifest
	switch mt {
	case ociIndex, dockerList:
		m.Index = true
	case ociManifest, dockerManifest:
		if raw.Manifests != nil {
			return manifest{}, fmt.Errorf("parsing manifest: %s with a manifests list", mt)
		}
	default:
		return manifest{}, fmt.Errorf("parsing manifest: unsupported media type %q", mt)
	}
	for _, e := range raw.Manifests {
		if !digest.MatchString(e.Digest) {
			return manifest{}, fmt.Errorf("parsing manifest: bad entry digest %q", e.Digest)
		}
		m.Entries = append(m.Entries, entry{Digest: e.Digest, Index: e.MediaType == ociIndex || e.MediaType == dockerList})
	}
	if raw.Subject != nil {
		if !digest.MatchString(raw.Subject.Digest) {
			return manifest{}, fmt.Errorf("parsing manifest: bad subject digest %q", raw.Subject.Digest)
		}
		m.Subject = raw.Subject.Digest
	}
	return m, nil
}

func (r *registry) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", strings.Join([]string{ociIndex, ociManifest, dockerList, dockerManifest}, ", "))
	if r.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	resp, err := r.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	return resp, nil
}

// login answers a "Bearer realm=...,service=...,scope=..." challenge. The
// credentials are only sent to a realm on the registry's own host.
func (r *registry) login(ctx context.Context, challenge string) error {
	if r.bearer != "" {
		return errors.New("registry: token refused")
	}
	params, ok := parseBearerChallenge(challenge)
	if !ok || params["realm"] == "" {
		return fmt.Errorf("registry: unsupported challenge %q", challenge)
	}
	realm, err := url.Parse(params["realm"])
	base, _ := url.Parse(r.base)
	if err != nil || realm.Scheme != base.Scheme || realm.Host != base.Host || realm.User != nil {
		return fmt.Errorf("registry: token realm %q is not on %s", params["realm"], r.base)
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", "repository:"+r.repo+":pull")
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(r.user, r.password)
	resp, err := r.hc.Do(req)
	if err != nil {
		return fmt.Errorf("registry token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry token: %s", resp.Status)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return fmt.Errorf("registry token: %w", err)
	}
	r.bearer = tok.Token
	if r.bearer == "" {
		r.bearer = tok.AccessToken
	}
	if r.bearer == "" {
		return errors.New("registry token: empty token")
	}
	return nil
}

// parseBearerChallenge parses `Bearer k="v",k2="v2"` (RFC 6750 section 3).
// Values are quoted strings without escapes, as registries send them.
func parseBearerChallenge(h string) (map[string]string, bool) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, false
	}
	params := map[string]string{}
	rest = strings.TrimSpace(rest)
	for rest != "" {
		k, after, ok := strings.Cut(rest, "=")
		if !ok || !strings.HasPrefix(after, `"`) {
			return nil, false
		}
		v, tail, ok := strings.Cut(after[1:], `"`)
		if !ok || strings.Contains(v, `\`) {
			return nil, false
		}
		params[strings.ToLower(strings.TrimSpace(k))] = v
		rest = strings.TrimSpace(tail)
		if rest != "" {
			if !strings.HasPrefix(rest, ",") {
				return nil, false
			}
			rest = strings.TrimSpace(rest[1:])
		}
	}
	return params, true
}
