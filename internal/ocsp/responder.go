// Copyright 2026 Hagan Consulting Inc.
// SPDX-License-Identifier: Apache-2.0

package ocsp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runner runs openssl with the given arguments.
type Runner interface {
	Run(ctx context.Context, args ...string) (output []byte, err error)
}

// ExecRunner runs the openssl binary at Path, with OPENSSL_CONF=/dev/null so
// that no system configuration changes the result.
type ExecRunner struct{ Path string }

// Run implements Runner.
func (e ExecRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, e.Path, args...)
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null")
	return cmd.CombinedOutput()
}

// Config of a Responder.
type Config struct {
	// PKI is the mockpca PKI directory (with ca/<name>/).
	PKI string
	// NMin is the nextUpdate distance in minutes (openssl -nmin, ≥ 1).
	NMin int
	// Runner runs openssl.
	Runner Runner
	// MaxConcurrent bounds the openssl processes running at once.
	MaxConcurrent int
	// Timeout bounds waiting for a slot plus one openssl run.
	Timeout time.Duration
	Log     *slog.Logger
	// Now is the clock (time.Now if nil).
	Now func() time.Time
}

// Responder answers OCSP requests for every CA of a PKI at /ocsp/<ca>.
type Responder struct {
	cfg Config
	sem chan struct{}

	mu    sync.Mutex
	stale map[string][]byte // replayed responses (stale fault)
}

// maxStale bounds the replay cache.
const maxStale = 1024

// New returns a Responder.
func New(cfg Config) (*Responder, error) {
	if cfg.PKI == "" || cfg.Runner == nil || cfg.Log == nil {
		return nil, errors.New("ocsp: PKI, Runner and Log are required")
	}
	if cfg.NMin < 1 {
		return nil, fmt.Errorf("ocsp: nmin %d, need at least 1", cfg.NMin)
	}
	if cfg.MaxConcurrent < 1 {
		cfg.MaxConcurrent = 4
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Responder{cfg: cfg, sem: make(chan struct{}, cfg.MaxConcurrent), stale: map[string][]byte{}}, nil
}

// caName matches the CA directory names bin/mockpca creates.
var caName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ServeHTTP answers GET /ocsp/<ca>/<url-encoded base64 request> and
// POST /ocsp/<ca> (RFC 6960 A.1). Problems with a request are answered
// with an unsigned OCSP error response, never with a crash.
func (rs *Responder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path, ok := strings.CutPrefix(r.URL.EscapedPath(), "/ocsp/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	ca, rest, _ := strings.Cut(path, "/")
	if !caName.MatchString(ca) {
		rs.error(w, StatusUnauthorized, "unknown CA name", "path", r.URL.Path)
		return
	}
	caDir := filepath.Join(rs.cfg.PKI, "ca", ca)
	if _, err := os.Stat(filepath.Join(caDir, "ca.conf")); err != nil {
		// Not a CA of this PKI: this responder is not authoritative.
		rs.error(w, StatusUnauthorized, "unknown CA", "ca", ca)
		return
	}
	if r.Method == http.MethodPost {
		rest = ""
	}
	der, ids, err := ReadRequest(r, rest)
	if err != nil {
		rs.error(w, StatusMalformedRequest, "malformed request", "ca", ca, "err", err)
		return
	}
	f, err := readFaults(filepath.Join(caDir, "ocsp-fault.conf"))
	if err != nil {
		rs.cfg.Log.Warn("ocsp fault file", "ca", ca, "err", err)
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-r.Context().Done():
			return
		}
	}
	switch {
	case f.httpStatus != 0:
		w.WriteHeader(f.httpStatus)
		return
	case f.status != 0:
		rs.writeError(w, ErrorResponse(f.status))
		return
	case f.sha1Only && !allSHA1(ids):
		rs.error(w, StatusUnauthorized, "sha1-only fault: SHA-256 CertID", "ca", ca)
		return
	}
	var key string
	nmin := rs.cfg.NMin
	if f.stale {
		sum := sha256.Sum256(der)
		key = ca + "/" + hex.EncodeToString(sum[:])
		rs.mu.Lock()
		cached, ok := rs.stale[key]
		rs.mu.Unlock()
		if ok {
			rs.writeSigned(w, cached, ca)
			return
		}
		nmin = 1 // the replayed response is past its nextUpdate after a minute
	}
	resp, err := rs.sign(r.Context(), caDir, der, f, nmin)
	if err != nil {
		status := StatusInternalError
		if errors.Is(err, errBusy) {
			status = StatusTryLater
		}
		rs.error(w, status, "signing failed", "ca", ca, "err", err)
		return
	}
	if f.stale {
		rs.mu.Lock()
		if len(rs.stale) >= maxStale {
			clear(rs.stale)
		}
		rs.stale[key] = resp
		rs.mu.Unlock()
	}
	rs.writeSigned(w, resp, ca)
}

func allSHA1(ids []CertID) bool {
	for _, id := range ids {
		if !id.HashAlgorithm.Equal(OIDSHA1) {
			return false
		}
	}
	return true
}

var errBusy = errors.New("no free openssl slot")

// sign has OpenSSL answer the request: index re-read on every run, signer
// per the CA's ocsp.conf (delegated responder or the CA itself) unless a
// fault replaces it.
func (rs *Responder) sign(ctx context.Context, caDir string, der []byte, f faults, nmin int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, rs.cfg.Timeout)
	defer cancel()
	select {
	case rs.sem <- struct{}{}:
		defer func() { <-rs.sem }()
	case <-ctx.Done():
		return nil, errBusy
	}
	tmp, err := os.MkdirTemp("", "mockpca-ocsp-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	reqFile, respFile := filepath.Join(tmp, "req.der"), filepath.Join(tmp, "resp.der")
	if err := os.WriteFile(reqFile, der, 0o600); err != nil {
		return nil, err
	}
	index := filepath.Join(caDir, "index.txt")
	if f.unknown {
		// An empty database: every serial is unknown, the response is still
		// properly signed.
		index = filepath.Join(tmp, "index.txt")
		if err := os.WriteFile(index, nil, 0o600); err != nil {
			return nil, err
		}
	}
	signer, key, err := signerFiles(caDir, f)
	if err != nil {
		return nil, err
	}
	out, err := rs.cfg.Runner.Run(ctx, "ocsp",
		"-index", index,
		"-CA", filepath.Join(caDir, "ca.pem"),
		"-rsigner", signer, "-rkey", key, "-rmd", "sha256",
		"-nmin", strconv.Itoa(nmin),
		"-reqin", reqFile, "-respout", respFile)
	if err != nil {
		return nil, fmt.Errorf("openssl ocsp: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return os.ReadFile(respFile)
}

// signerFiles returns the signing certificate and key of a CA's responder,
// or the negative fixture a fault asks for.
func signerFiles(caDir string, f faults) (cert, key string, err error) {
	ocspDir := filepath.Join(caDir, "ocsp")
	switch {
	case f.wrongSigner:
		cert, key = filepath.Join(ocspDir, "rogue-cert.pem"), filepath.Join(ocspDir, "rogue-key.pem")
	case f.noNoCheck:
		// Issued by the CA, but without id-pkix-ocsp-nocheck (made by
		// `mockpca ocsp-fault --no-nocheck`).
		d := filepath.Join(ocspDir, "negative-no-nocheck")
		cert, key = filepath.Join(d, "cert.pem"), filepath.Join(d, "key.pem")
	default:
		mode, err := readKV(filepath.Join(caDir, "ocsp.conf"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", "", err
		}
		switch mode["signer"] {
		case "", "delegated":
			cert, key = filepath.Join(ocspDir, "cert.pem"), filepath.Join(ocspDir, "key.pem")
		case "ca":
			cert, key = filepath.Join(caDir, "ca.pem"), filepath.Join(caDir, "ca.key")
		default:
			return "", "", fmt.Errorf("ocsp.conf: unknown signer %q", mode["signer"])
		}
	}
	for _, p := range []string{cert, key} {
		if _, err := os.Stat(p); err != nil {
			return "", "", fmt.Errorf("signer: %w", err)
		}
	}
	return cert, key, nil
}

// writeSigned sends a signed response with the caching headers of RFC 9919
// sections 6 and 7.2 (RFC 5019 5, 6.2), taken from the response itself:
// Last-Modified is its thisUpdate, Expires its nextUpdate, max-age ends
// before nextUpdate (0 once it has passed, as for a replayed stale
// response), and the ETag is the hex SHA-256 of the response. Authoritative
// responses never carry no-cache. A response whose times cannot be read is
// not sent: the client gets internalError.
func (rs *Responder) writeSigned(w http.ResponseWriter, resp []byte, ca string) {
	thisUpdate, nextUpdate, err := validity(resp)
	if err != nil {
		rs.error(w, StatusInternalError, "signed response unreadable", "ca", ca, "err", err)
		return
	}
	maxAge := int64(nextUpdate.Sub(rs.cfg.Now())/time.Second) - 1
	if maxAge < 0 {
		maxAge = 0
	}
	sum := sha256.Sum256(resp)
	h := w.Header()
	h.Set("Cache-Control", fmt.Sprintf("max-age=%d, public, no-transform, must-revalidate", maxAge))
	h.Set("Last-Modified", thisUpdate.UTC().Format(http.TimeFormat))
	h.Set("Expires", nextUpdate.UTC().Format(http.TimeFormat))
	h.Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	send(w, resp)
}

// writeError sends an unsigned error response; it is not authoritative and
// must not be cached.
func (rs *Responder) writeError(w http.ResponseWriter, resp []byte) {
	w.Header().Set("Cache-Control", "no-cache")
	send(w, resp)
}

func send(w http.ResponseWriter, resp []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/ocsp-response")
	h.Set("Content-Length", strconv.Itoa(len(resp)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func (rs *Responder) error(w http.ResponseWriter, status int, msg string, args ...any) {
	level := slog.LevelInfo
	if status == StatusInternalError {
		level = slog.LevelWarn
	}
	rs.cfg.Log.Log(context.Background(), level, "ocsp: "+msg, append(args, "response_status", status)...)
	rs.writeError(w, ErrorResponse(status))
}

// faults is the fault injection configured for a CA (ocsp-fault.conf, set
// by `mockpca ocsp-fault`; never by request input).
type faults struct {
	httpStatus  int
	delay       time.Duration
	status      int
	sha1Only    bool
	stale       bool
	wrongSigner bool
	noNoCheck   bool
	unknown     bool
}

var faultStatuses = map[string]int{
	"malformedRequest": StatusMalformedRequest,
	"internalError":    StatusInternalError,
	"tryLater":         StatusTryLater,
	"unauthorized":     StatusUnauthorized,
}

// maxDelay stays below the server's write timeout.
const maxDelay = 25 * time.Second

// readFaults reads a fault file; a missing file means no faults. Invalid
// entries are reported and ignored.
func readFaults(path string) (faults, error) {
	var f faults
	kv, err := readKV(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	var bad []string
	for k, v := range kv {
		switch k {
		case "http_status":
			n, err := strconv.Atoi(v)
			if err != nil || n < 100 || n > 599 {
				bad = append(bad, k)
				continue
			}
			f.httpStatus = n
		case "delay_ms":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || time.Duration(n)*time.Millisecond > maxDelay {
				bad = append(bad, k)
				continue
			}
			f.delay = time.Duration(n) * time.Millisecond
		case "status":
			s, ok := faultStatuses[v]
			if !ok {
				bad = append(bad, k)
				continue
			}
			f.status = s
		case "sha1_only":
			f.sha1Only = v == "1"
		case "stale":
			f.stale = v == "1"
		case "wrong_signer":
			f.wrongSigner = v == "1"
		case "no_nocheck":
			f.noNoCheck = v == "1"
		case "unknown":
			f.unknown = v == "1"
		default:
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		return f, fmt.Errorf("%s: ignored invalid entries %v", path, bad)
	}
	return f, nil
}

// readKV reads a key=value file as written by bin/mockpca.
func readKV(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	kv := map[string]string{}
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		kv[k] = v
	}
	return kv, sc.Err()
}
