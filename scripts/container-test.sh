#!/usr/bin/env bash
# Copyright 2026 Hagan Consulting Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Container image smoke test. Builds the image from the Dockerfile (or uses
# the image given as the first argument), then, with the PKI on a named
# volume: runs examples/demo.sh in one container, serves the PKI from a second
# and revokes from a third, and checks from the host that the image runs as
# a non-root user without a Go toolchain, that CA certificates, CRLs and OCSP
# are served at the URLs in the certificates, that a revocation is visible
# at once, and that the server stops cleanly. The CP checks themselves are
# covered by scripts/e2e.sh.
#
# Needs docker (DOCKER selects another compatible CLI), OpenSSL 3 and curl.
# CONTAINER_TEST_PORT selects the host port (default 18081).
set -euo pipefail

cd "$(dirname "$0")/.."
DOCKER="${DOCKER:-docker}"
PORT="${CONTAINER_TEST_PORT:-18081}"
URL="http://127.0.0.1:$PORT"
IMAGE="${1:-}"
NAME="mockpca-container-test-$$"
VOL="$NAME"
WORK="$(mktemp -d)"
cleanup() {
	"$DOCKER" rm -f "$NAME" >/dev/null 2>&1 || true
	"$DOCKER" volume rm "$VOL" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT
export OPENSSL_CONF=/dev/null

step() { echo "==> $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
# m ARGS: run mockpca in a fresh container on the test volume.
m() { "$DOCKER" run --rm -v "$VOL:/pki" "$IMAGE" "$@"; }
# get PATH: copy a file out of the PKI volume to $WORK/<basename>.
get() { "$DOCKER" run --rm -v "$VOL:/pki" --entrypoint cat "$IMAGE" "/pki/$1" >"$WORK/${1//\//_}"; }

if [[ -z $IMAGE ]]; then
	IMAGE=mock-pca:test
	step "build $IMAGE"
	"$DOCKER" build -q -t "$IMAGE" . >/dev/null
fi

step "image runs as a non-root user, without Go"
uid="$("$DOCKER" run --rm --entrypoint id "$IMAGE" -u)"
[[ $uid != 0 ]] || fail "the image runs as root"
if "$DOCKER" run --rm --entrypoint sh "$IMAGE" -c 'command -v go' >/dev/null; then
	fail "the image contains a Go toolchain"
fi
m help | grep -q 'NOT FOR PRODUCTION' || fail "mockpca help"

step "sample hierarchy (examples/demo.sh) on a volume"
"$DOCKER" volume create "$VOL" >/dev/null
"$DOCKER" run --rm -v "$VOL:/pki" -e BASE_URL="$URL" --entrypoint /opt/mockpca/examples/demo.sh "$IMAGE" \
	>/dev/null 2>"$WORK/demo.log" || {
	cat "$WORK/demo.log" >&2
	fail "examples/demo.sh"
}
m verify --ee bcf >/dev/null 2>&1 || fail "verify --ee bcf"
m lint -root /pki/trust/pca.pem /pki/ee/bcf/fullchain.pem >/dev/null || fail "lint (prebuilt mockpca-lint)"

step "serve from a second container"
"$DOCKER" run -d --init --name "$NAME" -v "$VOL:/pki" -p "127.0.0.1:$PORT:8080" "$IMAGE" \
	serve --listen 0.0.0.0:8080 >/dev/null
for _ in $(seq 1 60); do
	curl -fsS -o "$WORK/region.crl" "$URL/crl/region.crl" 2>/dev/null && break
	sleep 0.5
done
[[ -s $WORK/region.crl ]] || {
	"$DOCKER" logs "$NAME" >&2 || true
	fail "server did not answer on $URL"
}
get trust/pca.pem
get ca/region/ca.pem
get ee/rpsap/cert.pem
pca="$WORK/trust_pca.pem" region="$WORK/ca_region_ca.pem" rpsap="$WORK/ee_rpsap_cert.pem"

curl -fsS -o "$WORK/region.cer" "$URL/certs/region.cer" || fail "GET /certs/region.cer"
openssl x509 -inform DER -in "$WORK/region.cer" -noout -subject | grep -q 'Mock Region ICA Tier2' ||
	fail "/certs/region.cer is not the region ICA"
openssl crl -inform DER -in "$WORK/region.crl" -noout -CAfile "$region" 2>&1 | grep -q 'verify OK' ||
	fail "/crl/region.crl does not verify with the region ICA"

# ocsp_status: the verified OCSP status of rpsap from the served responder.
ocsp_status() {
	openssl ocsp -issuer "$region" -sha256 -cert "$rpsap" -url "$URL/ocsp/region" -CAfile "$pca" \
		-verify_other "$region" -no_nonce >"$WORK/ocsp.out" 2>&1 || true
	grep -q 'Response verify OK' "$WORK/ocsp.out" || fail "OCSP response does not verify: $(cat "$WORK/ocsp.out")"
	sed -n "s|^$rpsap: ||p" "$WORK/ocsp.out"
}
[[ $(ocsp_status) == good ]] || fail "OCSP: want good; got: $(cat "$WORK/ocsp.out")"

step "revocation in a third container is served at once"
serial="$(openssl x509 -in "$rpsap" -noout -serial | cut -d= -f2)"
m revoke --ee rpsap --reason keyCompromise >/dev/null 2>&1 || fail "revoke --ee rpsap"
[[ $(ocsp_status) == revoked ]] || fail "OCSP: want revoked; got: $(cat "$WORK/ocsp.out")"
curl -fsS -o "$WORK/region2.crl" "$URL/crl/region.crl" || fail "GET /crl/region.crl"
openssl crl -inform DER -in "$WORK/region2.crl" -noout -text | grep -qi "Serial Number: $serial" ||
	fail "the served CRL does not list the revoked certificate"
if m verify --ee rpsap >/dev/null 2>&1; then
	fail "verify accepted a revoked certificate"
fi

step "server stops cleanly"
"$DOCKER" stop -t 10 "$NAME" >/dev/null
code="$("$DOCKER" inspect -f '{{.State.ExitCode}}' "$NAME")"
[[ $code == 0 ]] || fail "serve exited with $code"

echo "OK"
