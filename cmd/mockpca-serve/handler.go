package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
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

// newHandler serves www/ through root and passes /ocsp/ to the responder.
func newHandler(root *os.Root, ocspResponder http.Handler, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /certs/{file}", serveFile(root, log, "certs", ".cer", "application/pkix-cert"))
	mux.Handle("GET /crl/{file}", serveFile(root, log, "crl", ".crl", "application/pkix-crl"))
	mux.Handle("/ocsp/", ocspResponder)
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
		// The files are small (certificates, CRLs): read them whole and use a
		// hash of the content as a strong ETag. Revalidation goes through
		// If-None-Match only: http.ServeContent compares If-Modified-Since in
		// whole seconds, so a CRL republished within the same second as a
		// client's fetch would be answered 304 with the stale CRL. Passing a
		// zero modification time disables that comparison; Last-Modified is
		// still sent for information.
		const maxSize = 10 << 20
		body, err := io.ReadAll(io.LimitReader(f, maxSize+1))
		if err != nil || len(body) > maxSize {
			http.Error(w, "cannot read file", http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(body)
		h := w.Header()
		h.Set("Content-Type", contentType)
		// Clients may cache, but must revalidate: CRLs change on revocation.
		h.Set("Cache-Control", "no-cache")
		h.Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
		h.Set("Last-Modified", st.ModTime().UTC().Format(http.TimeFormat))
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
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
