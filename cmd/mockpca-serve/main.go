// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

// Command mockpca-serve publishes a mock PCA's CA certificates and CRLs and
// answers OCSP requests over HTTP, at the caIssuers, cRLDistributionPoints
// and OCSP URLs that bin/mockpca puts into certificates:
//
//	GET  /certs/<ca>.cer         DER CA certificate (application/pkix-cert)
//	GET  /crl/<ca>.crl           DER CRL (application/pkix-crl)
//	GET  /ocsp/<ca>/<request>    OCSP (RFC 6960 A.1, RFC 5019, RFC 9919)
//	POST /ocsp/<ca>              OCSP (application/ocsp-request)
//
// Files are read from the PKI's www directory on every request, so CRLs
// republished by `mockpca revoke` or `mockpca crl` are visible immediately;
// OCSP responses are signed by OpenSSL from the CA's current database on
// every request (internal/ocsp).
//
// Usage:
//
//	mockpca-serve -pki PKI [-listen 127.0.0.1:8080] [-openssl PATH] [-nmin 60]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hagan-consulting/mock-pca/internal/ocsp"
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "mockpca-serve:", err)
		os.Exit(1)
	}
}

func run(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("mockpca-serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pki := fs.String("pki", "", "mockpca PKI directory (serves its www/ and answers OCSP for its ca/)")
	listen := fs.String("listen", "127.0.0.1:8080", "listen address")
	opensslPath := fs.String("openssl", "openssl", "OpenSSL 3 binary that signs OCSP responses")
	nmin := fs.Int("nmin", 60, "OCSP nextUpdate in minutes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pki == "" || fs.NArg() > 0 {
		return errors.New("usage: mockpca-serve -pki DIR [-listen ADDR] [-openssl PATH] [-nmin N]")
	}
	pkiDir, err := filepath.Abs(*pki)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Join(pkiDir, "www"))
	if err != nil {
		return err
	}
	defer root.Close()

	log := slog.New(slog.NewTextHandler(stderr, nil))
	responder, err := ocsp.New(ocsp.Config{
		PKI:    pkiDir,
		NMin:   *nmin,
		Runner: ocsp.ExecRunner{Path: *opensslPath},
		Log:    log,
	})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           newHandler(root, responder, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Covers an injected OCSP delay (at most 25 s) plus one openssl run.
		WriteTimeout:   45 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 << 10,
		ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("serving", "pki", pkiDir, "listen", *listen)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}
