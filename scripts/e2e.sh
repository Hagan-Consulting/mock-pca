#!/usr/bin/env bash
# End-to-end test: builds the sample hierarchy with OpenSSL, verifies every
# certificate, lints them strictly, serves CRLs and CA certificates over HTTP
# and checks revocation (End-Entity and ICA) and stale CRLs. Needs OpenSSL 3,
# Go and curl. E2E_PORT selects the local port (default 18080).
set -euo pipefail

cd "$(dirname "$0")/.."
M="$PWD/bin/mockpca"
PORT="${E2E_PORT:-18080}"
WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
	[[ -z $SERVER_PID ]] || kill "$SERVER_PID" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT
export MOCKPCA_PKI="$WORK/pki" OPENSSL_CONF=/dev/null
PKI="$MOCKPCA_PKI"

step() { echo "==> $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
expect_fail() {
	local what="$1"
	shift
	if "$@" >"$WORK/out" 2>&1; then
		cat "$WORK/out" >&2
		fail "$what: succeeded"
	fi
}

step "sample hierarchy"
BASE_URL="http://127.0.0.1:$PORT" examples/demo.sh >/dev/null 2>"$WORK/demo.log" || {
	cat "$WORK/demo.log" >&2
	fail "examples/demo.sh"
}

EES=(psap jsmith sal esrp logsign rpsap rsal)

step "external CSR"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/ext.key" 2>/dev/null
openssl req -new -key "$WORK/ext.key" -subj "/CN=ignored" -out "$WORK/ext.csr"
"$M" sign-csr --ca region --profile service --name ext --id ext.region.mock.test --roles ESRP \
	--owner psap.region.mock.test --org "Vendor Lab" --csr "$WORK/ext.csr" 2>/dev/null
EES+=(ext)
[[ $(openssl x509 -in "$PKI/ee/ext/cert.pem" -noout -pubkey) == $(openssl pkey -in "$WORK/ext.key" -pubout) ]] ||
	fail "sign-csr: certificate key differs from the CSR key"

step "openssl verify (chain, CP policy, CRLs) and strict lint"
for ca in pca state county region; do "$M" verify --ca "$ca" >/dev/null; done
for ee in "${EES[@]}"; do
	"$M" verify --ee "$ee" >/dev/null || fail "verify $ee"
	"$M" lint -strict -q "$PKI/ee/$ee/fullchain.pem" || fail "lint $ee"
done
"$M" lint -strict -q -profile pca "$PKI/ca/pca/ca.pem"
for ca in state county region; do
	"$M" lint -strict -q -profile ica -issuer "$PKI/ca/$(grep '^parent=' "$PKI/ca/$ca/ca.conf" | cut -d= -f2)/ca.pem" \
		"$PKI/ca/$ca/ca.pem"
done

step "Quad ID and DN encoding"
openssl x509 -in "$PKI/ee/jsmith/cert.pem" -noout -ext subjectAltName |
	grep -q 'othername: 1.3.6.1.4.1.55670.1.1::agentId/jsmith@psap.county.mock.test/Dispatching,CallTaking/psap.county.mock.test' ||
	fail "agent Quad ID"
openssl asn1parse -in "$PKI/ee/psap/cert.pem" | grep -q 'PRINTABLESTRING   :Mock County PSAP' || fail "O not PrintableString"
openssl asn1parse -in "$PKI/ee/jsmith/cert.pem" | grep -q 'UTF8STRING        :jsmith@psap.county.mock.test' ||
	fail "agent CN not UTF8String"

step "lint rejects a non-conforming certificate"
cat >"$WORK/bad.ext" <<'EOF'
[ bad ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:bad.region.mock.test
EOF
openssl x509 -req -in "$WORK/ext.csr" -CA "$PKI/ca/region/ca.pem" -CAkey "$PKI/ca/region/ca.key" \
	-days 30 -extfile "$WORK/bad.ext" -extensions bad -out "$WORK/bad.pem" 2>/dev/null
expect_fail "lint of a non-conforming element certificate" \
	"$M" lint -profile element -issuer "$PKI/ca/region/ca.pem" "$WORK/bad.pem"
grep -q 'cRLDistributionPoints is missing' "$WORK/out" || fail "lint output: $(cat "$WORK/out")"

step "HTTP publication"
"$M" serve --listen "127.0.0.1:$PORT" 2>"$WORK/serve.log" &
SERVER_PID=$!
for _ in $(seq 50); do
	curl -fsS -o /dev/null "http://127.0.0.1:$PORT/certs/pca.cer" 2>/dev/null && break
	sleep 0.2
done
curl -fsS -o /dev/null "http://127.0.0.1:$PORT/certs/pca.cer" || {
	cat "$WORK/serve.log" >&2
	fail "server did not start"
}
for ee in "${EES[@]}"; do
	cert="$PKI/ee/$ee/cert.pem"
	ca="$(grep '^ca=' "$PKI/ee/$ee/ee.conf" | cut -d= -f2)"
	crl_url="$(openssl x509 -in "$cert" -noout -ext crlDistributionPoints | sed -n 's/^ *URI://p')"
	issuer_url="$(openssl x509 -in "$cert" -noout -ext authorityInfoAccess | sed -n 's/^ *CA Issuers - URI://p')"
	curl -fsS -o "$WORK/crl.der" "$crl_url" || fail "$ee: GET $crl_url"
	openssl crl -inform DER -in "$WORK/crl.der" -CAfile "$PKI/ca/$ca/ca.pem" -noout 2>&1 | grep -q 'verify OK' ||
		fail "$ee: CRL signature"
	curl -fsS -o "$WORK/issuer.der" "$issuer_url" || fail "$ee: GET $issuer_url"
	cmp -s "$WORK/issuer.der" <(openssl x509 -in "$PKI/ca/$ca/ca.pem" -outform DER) || fail "$ee: caIssuers certificate"
done
status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/ocsp/county")"
[[ $status == 501 ]] || fail "OCSP endpoint: HTTP $status"

step "revocation of an End-Entity certificate is published at once"
serial="$(openssl x509 -in "$PKI/ee/jsmith/cert.pem" -noout -serial | cut -d= -f2)"
"$M" revoke --ee jsmith --reason keyCompromise 2>/dev/null
curl -fsS "http://127.0.0.1:$PORT/crl/county.crl" | openssl crl -inform DER -noout -text |
	grep -q "Serial Number: $serial" || fail "revoked serial not in the served CRL"
expect_fail "verify of the revoked agent certificate" "$M" verify --ee jsmith
grep -q 'certificate revoked' "$WORK/out" || fail "verify output: $(cat "$WORK/out")"
"$M" verify --ee psap >/dev/null

step "revocation of an ICA"
"$M" revoke --ca county --reason CACompromise 2>/dev/null
expect_fail "verify below the revoked ICA" "$M" verify --ee sal
grep -q 'certificate revoked' "$WORK/out" || fail "verify output: $(cat "$WORK/out")"
"$M" verify --ee rsal >/dev/null
expect_fail "issuing from the revoked ICA" "$M" issue --ca county --profile agency --name late \
	--id late.county.mock.test --roles x --org X
[[ ! -e $PKI/ee/late ]] || fail "refused issuance left a directory"

step "stale CRL"
"$M" crl --ca region --seconds 1 2>/dev/null
sleep 2
expect_fail "verify with a stale CRL" "$M" verify --ee rsal
grep -q 'CRL has expired' "$WORK/out" || fail "verify output: $(cat "$WORK/out")"
"$M" crl --ca region 2>/dev/null
"$M" verify --ee rsal >/dev/null

echo "OK"
