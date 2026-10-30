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

step "CSR key checks (CP 6.1.6, Table 7)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out "$WORK/small.key" 2>/dev/null
openssl req -new -key "$WORK/small.key" -subj "/CN=ignored" -out "$WORK/small.csr"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/ec.key"
openssl req -new -key "$WORK/ec.key" -subj "/CN=ignored" -out "$WORK/ec.csr"
small=(--ca region --profile element --name small --id small.region.mock.test --roles X --owner psap.region.mock.test --org V)
expect_fail "sign-csr with an RSA-1024 key" "$M" sign-csr "${small[@]}" --csr "$WORK/small.csr"
grep -q 'at least 2048' "$WORK/out" || fail "output: $(cat "$WORK/out")"
expect_fail "sign-csr with an EC key for an Element" "$M" sign-csr "${small[@]}" --csr "$WORK/ec.csr"
grep -q 'need an RSA key' "$WORK/out" || fail "output: $(cat "$WORK/out")"
[[ ! -e $PKI/ee/small ]] || fail "refused sign-csr left a directory"

step "issuance rules"
expect_fail "End-Entity certificate from the PCA" "$M" issue --ca pca --profile agency --name frompca \
	--id frompca.mock.test --roles x --org X
grep -q 'issues ICA certificates only' "$WORK/out" || fail "output: $(cat "$WORK/out")"
expect_fail "certificateHold" "$M" revoke --ee rsal --reason certificateHold
psap_roles=urn:emergency:service:responder.psap,urn:emergency:service:responder.police.local
expect_fail "duplicate Quad ID under another ICA" "$M" issue --ca region --profile agency --name dupquad \
	--id psap.county.mock.test --roles "$psap_roles" --org "Mock Region PSAP"
grep -q 'Quad ID .* is already used' "$WORK/out" || fail "output: $(cat "$WORK/out")"
expect_fail "duplicate ICA subject DN" "$M" ica --name dupdn --parent state --id ica.dupdn.mock.test \
	--owner psap.county.mock.test --org "Mock County 911" --label "Mock County" --ou-serial 2
grep -q 'subject DN .* is already used' "$WORK/out" || fail "output: $(cat "$WORK/out")"
"$M" issue --ca county --profile agency --name psap-renewed --renew psap --id psap.county.mock.test \
	--roles "$psap_roles" --org "Mock County PSAP" 2>/dev/null
expect_fail "renewal with another Quad ID" "$M" issue --ca county --profile agency --name psap-other --renew psap \
	--id psap.county.mock.test --roles urn:emergency:service:responder.psap --org "Mock County PSAP"
"$M" issue --ca region --profile agency --name nioc --id agency.nioc.mock.test --owner pca.mock.test \
	--roles urn:emergency:service:responder.psap --org "NIOC" 2>/dev/null
"$M" issue --ca county --profile agent --name console --id console1.psap.county.mock.test \
	--dns console1.county.mock.test --roles CallTaking --owner psap.county.mock.test --org "Mock County PSAP" 2>/dev/null
openssl x509 -in "$PKI/ee/console/cert.pem" -noout -ext subjectAltName |
	grep -q 'DNS:console1.psap.county.mock.test, DNS:console1.county.mock.test' || fail "agent: iD is not the first dNSName"
expect_fail "agent user@fqdn iD with a dNSName" "$M" issue --ca county --profile agent --name jdoe \
	--id jdoe@psap.county.mock.test --dns jdoe.county.mock.test --roles CallTaking --owner psap.county.mock.test \
	--org "Mock County PSAP"
grep -q 'not a DNS name' "$WORK/out" || fail "output: $(cat "$WORK/out")"
"$M" ica --name county2 --parent state --id ica.county2.mock.test --owner psap2.county.mock.test \
	--org "Mock County 911" --label "Mock County Two" 2>/dev/null
"$M" issue --ca county2 --profile element --name c2 --id c2.county.mock.test --roles SAL \
	--owner psap2.county.mock.test --org "Mock County PSAP Two" 2>/dev/null
EES+=(psap-renewed nioc console c2)
[[ $(openssl x509 -in "$PKI/ca/state/ca.pem" -noout -subject) == \
	"subject=C = US, O = Mock State 911, OU = ICA-1, ST = VT, CN = Mock State ICA Tier2" ]] || fail "ICA subject order"
[[ $(openssl x509 -in "$PKI/ee/sal/cert.pem" -noout -subject) == \
	"subject=C = US, O = Mock County PSAP, CN = sal.county.mock.test" ]] || fail "End-Entity subject order"

step "a failed lint leaves nothing valid behind"
printf '#!/bin/sh\necho "fake lint: ERROR"\nexit 1\n' >"$WORK/fail-lint"
chmod +x "$WORK/fail-lint"
rej=(--ca region --profile element --name rej --id rej.region.mock.test --roles SAL --owner psap.region.mock.test --org V)
expect_fail "issue with a failing lint" env MOCKPCA_LINT="$WORK/fail-lint" "$M" issue "${rej[@]}"
[[ ! -e $PKI/ee/rej ]] || fail "rejected End-Entity certificate left in ee/"
rejcert="$(ls "$PKI"/rejected/rej-*/cert.pem)"
serial="$(openssl x509 -in "$rejcert" -noout -serial | cut -d= -f2)"
openssl crl -in "$PKI/ca/region/crl.pem" -noout -text | grep -q "Serial Number: $serial" ||
	fail "rejected End-Entity certificate not in the CRL"
"$M" issue "${rej[@]}" 2>/dev/null || fail "the name and Quad ID of a rejected certificate are not free again"
expect_fail "ica with a failing lint" env MOCKPCA_LINT="$WORK/fail-lint" "$M" ica --name rejica --parent pca \
	--id ica.rej.mock.test --owner psap.rej.mock.test --org "Rejected 911" --label "Rejected"
[[ ! -e $PKI/ca/rejica ]] || fail "rejected ICA left in ca/"
serial="$(openssl x509 -in "$(ls "$PKI"/rejected/rejica-*/ca.pem)" -noout -serial | cut -d= -f2)"
openssl crl -in "$PKI/ca/pca/crl.pem" -noout -text | grep -q "Serial Number: $serial" || fail "rejected ICA not in the PCA CRL"
expect_fail "issuing from a rejected ICA" "$M" issue --ca rejica --profile agency --name x --id x.rej.mock.test --roles x --org X
expect_fail "init with a failing lint" env MOCKPCA_LINT="$WORK/fail-lint" "$M" --pki "$WORK/pki-fail" init \
	--base-url http://127.0.0.1:1 --id pca.fail.mock.test
[[ ! -e $WORK/pki-fail ]] || fail "failed init left a PKI directory"

step "CRL lifetime warning (CP Table 3)"
"$M" crl --ca region --hours 25 2>"$WORK/out"
grep -q 'WARNING: a CRL lifetime of 25 hours exceeds CP Table 3' "$WORK/out" || fail "output: $(cat "$WORK/out")"
"$M" crl --ca region 2>"$WORK/out"
! grep -q WARNING "$WORK/out" || fail "warning for a 24-hour CRL"

step "openssl verify (chain, CP policy, CRLs) and strict lint"
for ca in pca state county region; do "$M" verify --ca "$ca" >/dev/null; done
for ee in "${EES[@]}"; do
	"$M" verify --ee "$ee" >/dev/null || fail "verify $ee"
	"$M" lint -strict -q -root "$PKI/trust/pca.pem" "$PKI/ee/$ee/fullchain.pem" || fail "lint $ee"
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
crl_url="http://127.0.0.1:$PORT/crl/county.crl"
etag="$(curl -fsSI "$crl_url" | tr -d '\r' | sed -n 's/^[Ee][Tt][Aa][Gg]: //p')"
last_mod="$(curl -fsSI "$crl_url" | tr -d '\r' | sed -n 's/^[Ll]ast-[Mm]odified: //p')"
[[ -n $etag && -n $last_mod ]] || fail "no ETag/Last-Modified on CRLs"
status="$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: $etag" "$crl_url")"
[[ $status == 304 ]] || fail "If-None-Match with the current ETag: HTTP $status"

step "revocation of an End-Entity certificate is published at once"
serial="$(openssl x509 -in "$PKI/ee/jsmith/cert.pem" -noout -serial | cut -d= -f2)"
"$M" revoke --ee jsmith --reason keyCompromise 2>/dev/null
curl -fsS "http://127.0.0.1:$PORT/crl/county.crl" | openssl crl -inform DER -noout -text |
	grep -q "Serial Number: $serial" || fail "revoked serial not in the served CRL"
for hdr in "If-None-Match: $etag" "If-Modified-Since: $last_mod"; do
	status="$(curl -s -o /dev/null -w '%{http_code}' -H "$hdr" "$crl_url")"
	[[ $status == 200 ]] || fail "$hdr after a revocation: HTTP $status"
done
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

step "revoked ancestor ICA"
"$M" revoke --ca state --reason CACompromise 2>/dev/null
expect_fail "issuing below a revoked ancestor" "$M" issue --ca county2 --profile element --name c3 \
	--id c3.county.mock.test --roles SAL --owner psap2.county.mock.test --org "Mock County PSAP Two"
grep -q "its issuer 'state' is revoked" "$WORK/out" || fail "output: $(cat "$WORK/out")"
expect_fail "verify below a revoked ancestor" "$M" verify --ee c2
grep -q 'certificate revoked' "$WORK/out" || fail "verify output: $(cat "$WORK/out")"

step "stale CRL"
"$M" crl --ca region --seconds 1 2>/dev/null
sleep 2
expect_fail "verify with a stale CRL" "$M" verify --ee rsal
grep -q 'CRL has expired' "$WORK/out" || fail "verify output: $(cat "$WORK/out")"
"$M" crl --ca region 2>/dev/null
"$M" verify --ee rsal >/dev/null

echo "OK"
