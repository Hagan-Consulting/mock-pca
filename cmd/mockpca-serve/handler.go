package main

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"time"
)

// fileName matches the names bin/mockpca publishes: <ca-name>.cer and
// <ca-name>.crl. Anything else (paths, dot files) is not served.
var fileName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}\.(cer|crl)$`)

func newHandler(root *os.Root, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /certs/{file}", serveFile(root, log, "certs", ".cer", "application/pkix-cert"))
	mux.Handle("GET /crl/{file}", serveFile(root, log, "crl", ".crl", "application/pkix-crl"))
	mux.HandleFunc("/ocsp/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "OCSP is not implemented yet by mockpca-serve", http.StatusNotImplemented)
	})
	return logRequests(mux, log)
}

func serveFile(root *os.Root, log *slog.Logger, dir, ext, contentType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("file")
		if !fileName.MatchString(name) || name[len(name)-len(ext):] != ext {
			http.NotFound(w, r)
			return
		}
		f, err := root.Open(dir + "/" + name)
		if err != nil {
			// Includes paths escaping the root through symbolic links.
			if !errors.Is(err, fs.ErrNotExist) {
				log.Warn("cannot open file", "path", r.URL.Path, "err", err)
			}
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		// Clients may cache, but must revalidate: CRLs change on revocation.
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, name, st.ModTime(), f)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func logRequests(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"remote", r.RemoteAddr, "duration", time.Since(start))
	})
}
