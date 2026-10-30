// Command mockpca-serve publishes a mock PCA's CA certificates and CRLs over
// HTTP, at the caIssuers and cRLDistributionPoints URLs that bin/mockpca
// puts into certificates:
//
//	GET /certs/<ca>.cer   DER CA certificate (application/pkix-cert)
//	GET /crl/<ca>.crl     DER CRL (application/pkix-crl)
//	    /ocsp/<ca>        501 Not Implemented (OCSP is a planned feature)
//
// Files are read from the PKI's www directory on every request, so CRLs
// republished by `mockpca revoke` or `mockpca crl` are visible immediately.
//
// Usage:
//
//	mockpca-serve -root PKI/www [-listen 127.0.0.1:8080]
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
	"syscall"
	"time"
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
	rootDir := fs.String("root", "", "directory to serve (the PKI's www directory)")
	listen := fs.String("listen", "127.0.0.1:8080", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootDir == "" || fs.NArg() > 0 {
		return errors.New("usage: mockpca-serve -root DIR [-listen ADDR]")
	}
	root, err := os.OpenRoot(*rootDir)
	if err != nil {
		return err
	}
	defer root.Close()

	log := slog.New(slog.NewTextHandler(stderr, nil))
	srv := &http.Server{
		Addr:              *listen,
		Handler:           newHandler(root, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("serving", "root", *rootDir, "listen", *listen)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}
