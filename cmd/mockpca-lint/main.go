// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

// Command mockpca-lint checks certificates against the certificate profiles
// of the NG9-1-1 PKI Certificate Policy v1.3.
//
// Usage:
//
//	mockpca-lint [-profile auto|pca|ica|agency|agent|element|service|signing]
//	             [-issuer FILE] [-root FILE] [-strict] [-q] FILE...
//
// Each FILE holds a certificate (PEM or DER). When a PEM file holds more than
// one certificate (a full chain), the second one is the issuer unless
// -issuer is given. Exit status: 0 conforming (warnings allowed unless
// -strict), 1 findings, 2 usage or read errors.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/hagan-consulting/mock-pca/internal/lint"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mockpca-lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "auto", "certificate profile, or auto to detect it from the Quad ID")
	issuerFile := fs.String("issuer", "", "issuing CA certificate (enables signature, AKI, name and validity nesting checks)")
	rootFile := fs.String("root", "", "PCA certificate (accepts NIOC Agency Certificates owned by the PCA's iD)")
	strict := fs.Bool("strict", false, "treat warnings as failures")
	quiet := fs.Bool("q", false, "print findings only, no OK lines")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: mockpca-lint [flags] FILE...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	var p lint.Profile
	if *profile != "auto" {
		var err error
		if p, err = lint.ParseProfile(*profile); err != nil {
			fmt.Fprintln(stderr, "mockpca-lint:", err)
			return 2
		}
	}
	var issuer *x509.Certificate
	if *issuerFile != "" {
		certs, err := readCerts(*issuerFile)
		if err != nil {
			fmt.Fprintln(stderr, "mockpca-lint:", err)
			return 2
		}
		issuer = certs[0]
	}
	var root *x509.Certificate
	if *rootFile != "" {
		certs, err := readCerts(*rootFile)
		if err != nil {
			fmt.Fprintln(stderr, "mockpca-lint:", err)
			return 2
		}
		root = certs[0]
	}
	status := 0
	for _, name := range fs.Args() {
		certs, err := readCerts(name)
		if err != nil {
			fmt.Fprintln(stderr, "mockpca-lint:", err)
			return 2
		}
		iss := issuer
		if iss == nil && len(certs) > 1 {
			iss = certs[1]
		}
		prof := p
		if prof == "" {
			if prof, err = lint.Detect(certs[0]); err != nil {
				fmt.Fprintf(stdout, "%s: ERROR cannot detect the profile: %v\n", name, err)
				status = 1
				continue
			}
		}
		findings := lint.Check(certs[0], prof, lint.Options{Issuer: iss, Root: root})
		for _, f := range findings {
			fmt.Fprintf(stdout, "%s: %s: %s\n", name, prof, f)
			if f.Severity == lint.Error || *strict {
				status = 1
			}
		}
		if len(findings) == 0 && !*quiet {
			fmt.Fprintf(stdout, "%s: %s: OK\n", name, prof)
		}
	}
	return status
}

// readCerts reads the certificates of a PEM file (in order), or a single DER
// certificate.
func readCerts(name string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, errors.Join(errors.New("no PEM certificate and not a DER certificate"), err))
		}
		certs = append(certs, c)
	}
	return certs, nil
}
