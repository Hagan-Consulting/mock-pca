// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

// Command ghcr-prune applies the image retention policy to a container
// package on the GitHub Container Registry. CI runs it at the end of every
// image publish; it is not part of the container image.
//
// Policy (docs/DESIGN.md, "Container image publishing"):
//
//   - a version with any tag that is not sha-<commit> (X.Y.Z, X.Y, latest,
//     edge) is kept;
//   - a version tagged only sha-<commit> is kept for -sha-retention after it
//     was pushed, then deleted;
//   - an untagged version is kept only while a kept version needs it: as an
//     entry of a kept image index (platform images, BuildKit attestation
//     manifests) or as a referrer (OCI subject) of a kept manifest, such as a
//     pushed build provenance attestation. Every other untagged version is
//     deleted.
//
// Nothing is deleted until the whole plan has been worked out; any error
// while planning, or a plan with more than -max-deletions deletions, ends
// the run with nothing deleted. The token is read from GITHUB_TOKEN and the
// registry user name from GITHUB_ACTOR (never from flags); deleting needs
// the Admin role on the package.
//
// Usage:
//
//	ghcr-prune -org ORG -package NAME [-dry-run] [-sha-retention 336h] [-max-deletions 100]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"
)

// errTooManyDeletions reports a plan that exceeds -max-deletions.
var errTooManyDeletions = errors.New("plan exceeds -max-deletions")

// ghName matches GitHub organization and container package names as used
// here (lower case, as GHCR requires).
var ghName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?$`)

type config struct {
	org, pkg     string
	apiURL       string
	registryURL  string
	retention    time.Duration
	maxDeletions int
	dryRun       bool
	timeout      time.Duration
	token, actor string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Getenv, os.Stderr, time.Now())
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ghcr-prune:", err)
		if errors.Is(err, flag.ErrHelp) || errors.Is(err, errUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

var errUsage = errors.New("usage: ghcr-prune -org ORG -package NAME [-dry-run] [-sha-retention DURATION] [-max-deletions N]")

func parseConfig(args []string, getenv func(string) string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("ghcr-prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.org, "org", "", "GitHub organization that owns the package (required, lower case)")
	fs.StringVar(&c.pkg, "package", "", "container package name (required, lower case)")
	fs.StringVar(&c.apiURL, "api-url", "https://api.github.com", "GitHub REST API base URL")
	fs.StringVar(&c.registryURL, "registry-url", "https://ghcr.io", "container registry base URL")
	fs.DurationVar(&c.retention, "sha-retention", 14*24*time.Hour, "keep versions tagged only sha-* for at least this long")
	fs.IntVar(&c.maxDeletions, "max-deletions", 100, "delete nothing if the plan has more deletions than this")
	fs.BoolVar(&c.dryRun, "dry-run", false, "log the plan and delete nothing")
	fs.DurationVar(&c.timeout, "timeout", 10*time.Minute, "deadline for the whole run")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0, !ghName.MatchString(c.org), !ghName.MatchString(c.pkg),
		c.retention <= 0, c.maxDeletions < 0, c.timeout <= 0:
		return c, errUsage
	}
	for _, u := range []string{c.apiURL, c.registryURL} {
		p, err := url.Parse(u)
		if err != nil || p.Host == "" || p.User != nil || p.RawQuery != "" || p.Fragment != "" ||
			(p.Scheme != "https" && !(p.Scheme == "http" && isLoopback(p.Hostname()))) {
			return c, fmt.Errorf("%w (%q must be an https URL)", errUsage, u)
		}
	}
	c.token, c.actor = getenv("GITHUB_TOKEN"), getenv("GITHUB_ACTOR")
	if c.token == "" || c.actor == "" {
		return c, errors.New("GITHUB_TOKEN and GITHUB_ACTOR must be set")
	}
	return c, nil
}

func run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, now time.Time) error {
	c, err := parseConfig(args, getenv, stderr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	log := slog.New(slog.NewTextHandler(stderr, nil))
	hc := &http.Client{
		Timeout: 30 * time.Second,
		// Never follow a redirect with the token attached somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	gh := &githubAPI{base: c.apiURL, org: c.org, pkg: c.pkg, token: c.token, hc: hc}
	reg := &registry{base: c.registryURL, repo: c.org + "/" + c.pkg, user: c.actor, password: c.token, hc: hc}

	versions, err := gh.listVersions(ctx)
	if err != nil {
		return err
	}
	p, err := makePlan(ctx, versions, now, c.retention, reg)
	if err != nil {
		return fmt.Errorf("planning (nothing deleted): %w", err)
	}
	dels := 0
	for _, s := range p {
		log.Info("plan", "action", s.action(), "reason", s.Reason, "version_id", s.V.ID,
			"digest", s.V.Digest, "tags", s.V.Tags, "created", s.V.Created.UTC().Format(time.RFC3339))
		if s.Delete {
			dels++
		}
	}
	log.Info("plan summary", "versions", len(p), "keep", len(p)-dels, "delete", dels, "dry_run", c.dryRun)
	if dels > c.maxDeletions {
		return fmt.Errorf("%w: %d > %d, nothing deleted", errTooManyDeletions, dels, c.maxDeletions)
	}
	if c.dryRun || dels == 0 {
		return nil
	}
	done := 0
	for _, s := range p {
		if !s.Delete {
			continue
		}
		if err := gh.deleteVersion(ctx, s.V.ID); err != nil {
			return fmt.Errorf("deleted %d of %d versions, then: %w", done, dels, err)
		}
		done++
		log.Info("deleted", "version_id", s.V.ID, "digest", s.V.Digest, "tags", s.V.Tags)
	}
	log.Info("done", "deleted", done)
	return nil
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}
