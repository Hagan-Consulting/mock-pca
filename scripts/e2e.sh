#!/usr/bin/env bash
# Copyright 2026 Hagan Consulting Inc.
# SPDX-License-Identifier: Apache-2.0
#
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

# hdr NAME: value of a response header in $WORK/hdr (case-insensitive).
hdr() {
	tr -d '\r' <"$WORK/hdr" | awk -v k="$(tr '[:upper:]' '[:lower:]' <<<"$1")" \
		'{ i = index($0, ":"); if (i && tolower(substr($0, 1, i - 1)) == k) { print substr($0, i + 2); exit } }'
}
# to_epoch DATE: seconds since the epoch of an HTTP date or an OpenSSL
# "Mon DD HH:MM:SS YYYY GMT" date (GNU date, else BSD date).
to_epoch() {
	date -u -d "$1" +%s 2>/dev/null ||
		date -u -j -f '%a, %d %b %Y %H:%M:%S GMT' "$1" +%s 2>/dev/null ||
		date -u -j -f '%b %e %H:%M:%S %Y GMT' "$1" +%s
}

step "sample hierarchy"
BASE_URL="http://127.0.0.1:$PORT" examples/demo.sh >/dev/null 2>"$WORK/demo.log" || {
	cat "$WORK/demo.log" >&2
	fail "examples/demo.sh"
}

EES=(psap jsmith bcf esrp logsign rpsap rbcf)

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
expect_fail "certificateHold" "$M" revoke --ee rbcf --reason certificateHold
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
"$M" issue --ca county2 --profile element --name c2 --id c2.county.mock.test --roles BCF \
	--owner psap2.county.mock.test --org "Mock County PSAP Two" 2>/dev/null
EES+=(psap-renewed nioc console c2)
[[ $(openssl x509 -in "$PKI/ca/state/ca.pem" -noout -subject) == \
	"subject=C = US, O = Mock State 911, OU = ICA-1, ST = VT, CN = Mock State ICA Tier2" ]] || fail "ICA subject order"
[[ $(openssl x509 -in "$PKI/ee/bcf/cert.pem" -noout -subject) == \
	"subject=C = US, O = Mock County PSAP, CN = bcf.county.mock.test" ]] || fail "End-Entity subject order"

step "ICA re-key (ica --renew, CP 3.1.5)"
"$M" ica --name region2 --renew region 2>/dev/null
[[ $(grep '^quad=' "$PKI/ca/region2/ca.conf") == "$(grep '^quad=' "$PKI/ca/region/ca.conf")" ]] ||
	fail "re-key changed the Quad ID"
old_subj="$(openssl x509 -in "$PKI/ca/region/ca.pem" -noout -subject)"
new_subj="$(openssl x509 -in "$PKI/ca/region2/ca.pem" -noout -subject)"
[[ $old_subj != "$new_subj" && ${old_subj/OU = ICA-*, CN/} == "${new_subj/OU = ICA-*, CN/}" ]] ||
	fail "re-key: subjects should differ in the OU serial only: $old_subj / $new_subj"
[[ $(openssl x509 -in "$PKI/ca/region/ca.pem" -noout -pubkey) != $(openssl x509 -in "$PKI/ca/region2/ca.pem" -noout -pubkey) ]] ||
	fail "re-key kept the key"
"$M" issue --ca region2 --profile element --name rbcf2 --id bcf2.region.mock.test --roles BCF \
	--owner psap.region.mock.test --org "Mock Region PSAP" 2>/dev/null
EES+=(rbcf2)
expect_fail "re-key with another iD" "$M" ica --name region3 --renew region --id other.region.mock.test
grep -q 'a re-key keeps the id' "$WORK/out" || fail "output: $(cat "$WORK/out")"
expect_fail "re-key under another parent" "$M" ica --name region3 --renew region --parent state
expect_fail "second ICA with the same Quad ID without --renew" "$M" ica --name region3 --parent pca \
	--id ica.region.mock.test --owner psap.region.mock.test --org "Mock Region 911" --label "Mock Region Two"
grep -q "use 'ica --renew NAME'" "$WORK/out" || fail "output: $(cat "$WORK/out")"
[[ ! -e $PKI/ca/region3 ]] || fail "refused ICA left a directory"

step "a failed lint leaves nothing valid behind"
printf '#!/bin/sh\necho "fake lint: ERROR"\nexit 1\n' >"$WORK/fail-lint"
chmod +x "$WORK/fail-lint"
rej=(--ca region --profile element --name rej --id rej.region.mock.test --roles BCF --owner psap.region.mock.test --org V)
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
for ca in pca state county region region2; do "$M" verify --ca "$ca" >/dev/null; done
for ee in "${EES[@]}"; do
	"$M" verify --ee "$ee" >/dev/null || fail "verify $ee"
	"$M" lint -strict -q -root "$PKI/trust/pca.pem" "$PKI/ee/$ee/fullchain.pem" || fail "lint $ee"
done
"$M" lint -strict -q -profile pca "$PKI/ca/pca/ca.pem"
for ca in state county region region2; do
	"$M" lint -strict -q -profile ica -issuer "$PKI/ca/$(grep '^parent=' "$PKI/ca/$ca/ca.conf" | cut -d= -f2)/ca.pem" \
		"$PKI/ca/$ca/ca.pem"
done
for ca in pca state county region region2; do
	"$M" lint -strict -q -profile ocsp-responder -issuer "$PKI/ca/$ca/ca.pem" -root "$PKI/trust/pca.pem" \
		"$PKI/ca/$ca/ocsp/cert.pem" || fail "lint of the OCSP responder certificate of $ca"
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
crl_url="http://127.0.0.1:$PORT/crl/county.crl"
etag="$(curl -fsSI "$crl_url" | tr -d '\r' | sed -n 's/^[Ee][Tt][Aa][Gg]: //p')"
last_mod="$(curl -fsSI "$crl_url" | tr -d '\r' | sed -n 's/^[Ll]ast-[Mm]odified: //p')"
[[ -n $etag && -n $last_mod ]] || fail "no ETag/Last-Modified on CRLs"
status="$(curl -s -o /dev/null -w '%{http_code}' -H "If-None-Match: $etag" "$crl_url")"
[[ $status == 304 ]] || fail "If-None-Match with the current ETag: HTTP $status"

step "OCSP (RFC 6960, RFC 5019/9919)"
OCSP="http://127.0.0.1:$PORT/ocsp"
cat "$PKI"/ca/*/ca.pem >"$WORK/cas.pem"
# ocsp_q CA CERT HASH [openssl ocsp options]: query the CA's responder (POST)
# and verify the response against the PCA; output in $WORK/ocsp.out.
ocsp_q() {
	local ca="$1" cert="$2" hash="$3"
	shift 3
	openssl ocsp -issuer "$PKI/ca/$ca/ca.pem" "-$hash" -cert "$cert" -url "$OCSP/$ca" -CAfile "$PKI/trust/pca.pem" \
		-verify_other "$WORK/cas.pem" -no_nonce "$@" >"$WORK/ocsp.out" 2>&1 || true
}
# expect_status CERT STATUS: the last query verified and reported STATUS.
expect_status() {
	{ grep -q 'Response verify OK' "$WORK/ocsp.out" && grep -q "^$1: $2\$" "$WORK/ocsp.out"; } ||
		fail "OCSP: want $2 for $1; got: $(cat "$WORK/ocsp.out")"
}
rpsap="$PKI/ee/rpsap/cert.pem"
for hash in sha256 sha1; do
	ocsp_q region "$rpsap" "$hash"
	expect_status "$rpsap" good
done
grep -q 'Next Update' "$WORK/ocsp.out" || fail "OCSP response without nextUpdate"
# GET (RFC 6960 A.1, RFC 9919 6): base64 in the path, '/' escaped as %2F;
# '+' and '=' are valid unescaped in a path.
openssl ocsp -issuer "$PKI/ca/region/ca.pem" -sha256 -cert "$rpsap" -no_nonce -reqout "$WORK/req.der" >/dev/null
b64="$(base64 <"$WORK/req.der" | tr -d '\n')"
t0="$(date -u +%s)"
curl -fsS -D "$WORK/hdr" -o "$WORK/resp.der" "$OCSP/region/${b64//\//%2F}" || fail "OCSP GET"
grep -qi '^content-type: application/ocsp-response' "$WORK/hdr" || fail "OCSP GET: content type"
# Caching headers (RFC 9919 6, 7.2): Last-Modified = thisUpdate, Expires =
# nextUpdate, max-age ending before nextUpdate, ETag = hex SHA-256.
openssl ocsp -respin "$WORK/resp.der" -resp_text -noverify >"$WORK/resp.txt" 2>&1
this_update="$(sed -n 's/^ *This Update: //p' "$WORK/resp.txt" | head -1)"
next_update="$(sed -n 's/^ *Next Update: //p' "$WORK/resp.txt" | head -1)"
[[ $(to_epoch "$(hdr expires)") == "$(to_epoch "$next_update")" ]] ||
	fail "OCSP GET: Expires $(hdr expires) is not nextUpdate $next_update"
[[ $(to_epoch "$(hdr last-modified)") == "$(to_epoch "$this_update")" ]] ||
	fail "OCSP GET: Last-Modified $(hdr last-modified) is not thisUpdate $this_update"
max_age="$(hdr cache-control | sed -n 's/^max-age=\([0-9][0-9]*\), public, no-transform, must-revalidate$/\1/p')"
{ [[ -n $max_age ]] && ((t0 + max_age < $(to_epoch "$next_update"))); } ||
	fail "OCSP GET: Cache-Control $(hdr cache-control) does not end before nextUpdate $next_update"
[[ $(hdr etag) == "\"$(openssl dgst -sha256 -r "$WORK/resp.der" | cut -d' ' -f1)\"" ]] ||
	fail "OCSP GET: ETag $(hdr etag) is not the SHA-256 of the response"
openssl ocsp -respin "$WORK/resp.der" -issuer "$PKI/ca/region/ca.pem" -sha256 -cert "$rpsap" \
	-CAfile "$PKI/trust/pca.pem" -verify_other "$WORK/cas.pem" >"$WORK/ocsp.out" 2>&1 || true
expect_status "$rpsap" good
# The PCA's responder answers for ICAs.
openssl ocsp -issuer "$PKI/ca/pca/ca.pem" -sha256 -cert "$PKI/ca/region/ca.pem" -url "$OCSP/pca" \
	-CAfile "$PKI/trust/pca.pem" -no_nonce >"$WORK/ocsp.out" 2>&1 || true
expect_status "$PKI/ca/region/ca.pem" good
# A serial the CA never issued.
openssl ocsp -issuer "$PKI/ca/region/ca.pem" -sha256 -serial 0x123456789 -url "$OCSP/region" \
	-CAfile "$PKI/trust/pca.pem" -verify_other "$WORK/cas.pem" -no_nonce >"$WORK/ocsp.out" 2>&1 || true
expect_status 0x123456789 unknown
# GET is strict (RFC 9919 6, RFC 3986, RFC 4648 3.2): an unescaped '/', an
# unescaped "//" (never redirected) and missing padding are malformedRequest.
get_status() { curl -s -o "$WORK/get.der" -w '%{http_code}' "$OCSP/region/$1"; }
raw="$b64"
[[ $raw == */* ]] || raw="MAo/MAo="
for path in "$raw" "MAo//MAo="; do
	[[ $(get_status "$path") == 200 && $(od -An -tx1 "$WORK/get.der" | tr -d ' \n') == 30030a0101 ]] ||
		fail "OCSP GET with an unescaped '/' ($path): not answered malformedRequest"
done
unpadded=""
for n in 1 2 3; do
	certs=()
	for ((i = 0; i < n; i++)); do certs+=(-cert "$rpsap"); done
	openssl ocsp -issuer "$PKI/ca/region/ca.pem" -sha256 "${certs[@]}" -no_nonce -reqout "$WORK/req$n.der" >/dev/null
	p="$(base64 <"$WORK/req$n.der" | tr -d '\n')"
	if [[ $p == *= ]]; then
		unpadded="${p%%=*}"
		break
	fi
done
[[ -n $unpadded ]] || fail "no request with base64 padding to test"
[[ $(get_status "${unpadded//\//%2F}") == 200 && $(od -An -tx1 "$WORK/get.der" | tr -d ' \n') == 30030a0101 ]] ||
	fail "OCSP GET without base64 padding: not answered malformedRequest"
# A malformed request gets malformedRequest and the server stays up.
[[ $(curl -fsS --data-binary garbage -H 'Content-Type: application/ocsp-request' "$OCSP/region" | od -An -tx1 | tr -d ' \n') == 30030a0101 ]] ||
	fail "malformed OCSP request: not answered malformedRequest"
[[ $(curl -fsS --data-binary @"$WORK/req.der" "$OCSP/nosuchca" | od -An -tx1 | tr -d ' \n') == 30030a0106 ]] ||
	fail "OCSP request for an unknown CA: not answered unauthorized"
ocsp_q region "$rpsap" sha256
expect_status "$rpsap" good

step "OCSP signer modes and rotation"
"$M" ocsp-signer --ca region --mode ca 2>/dev/null
ocsp_q region "$rpsap" sha256 -resp_text
expect_status "$rpsap" good
grep -q 'Responder Id: C = US, O = Mock Region 911, OU = ICA-3, CN = Mock Region ICA Tier2' "$WORK/ocsp.out" ||
	fail "CA-signed mode: responder is not the CA"
"$M" ocsp-signer --ca region --mode delegated 2>/dev/null
ocsp_q region "$rpsap" sha256 -resp_text
grep -q 'Responder Id: C = US, O = Mock Region 911, CN = ocsp.ica.region.mock.test' "$WORK/ocsp.out" ||
	fail "delegated mode: responder is not the responder certificate"
grep -q 'OCSP No Check' "$WORK/ocsp.out" || fail "delegated mode: the responder certificate lacks id-pkix-ocsp-nocheck"
old_responder="$(openssl x509 -in "$PKI/ca/region/ocsp/cert.pem" -noout -serial | cut -d= -f2)"
"$M" ocsp-signer --ca region --rotate 2>/dev/null
[[ $(openssl x509 -in "$PKI/ca/region/ocsp/cert.pem" -noout -serial | cut -d= -f2) != "$old_responder" ]] ||
	fail "rotation kept the responder certificate"
awk -F'\t' -v s="$old_responder" 'toupper($4) == toupper(s) { print $1 }' "$PKI/ca/region/index.txt" | grep -q R ||
	fail "rotation did not revoke the previous responder certificate"
ocsp_q region "$rpsap" sha256
expect_status "$rpsap" good
"$M" ocsp-response --ee rpsap --out "$WORK/staple.der" 2>/dev/null
openssl ocsp -respin "$WORK/staple.der" -issuer "$PKI/ca/region/ca.pem" -sha256 -cert "$rpsap" \
	-CAfile "$PKI/trust/pca.pem" -verify_other "$WORK/cas.pem" >"$WORK/ocsp.out" 2>&1 || true
expect_status "$rpsap" good

step "OCSP shows revocations at once"
"$M" issue --ca region --profile element --name ocspee --id ocspee.region.mock.test --roles BCF \
	--owner psap.region.mock.test --org "Mock Region PSAP" 2>/dev/null
ocsp_q region "$PKI/ee/ocspee/cert.pem" sha256
expect_status "$PKI/ee/ocspee/cert.pem" good
"$M" revoke --ee ocspee --reason keyCompromise 2>/dev/null
ocsp_q region "$PKI/ee/ocspee/cert.pem" sha256
expect_status "$PKI/ee/ocspee/cert.pem" revoked
"$M" ica --name ocspica --parent pca --pathlen 0 --id ica.ocsp.mock.test --owner psap.ocsp.mock.test \
	--org "Mock OCSP 911" --label "Mock OCSP" 2>/dev/null
pcaq() {
	openssl ocsp -issuer "$PKI/ca/pca/ca.pem" -sha256 -cert "$PKI/ca/ocspica/ca.pem" -url "$OCSP/pca" \
		-CAfile "$PKI/trust/pca.pem" -no_nonce >"$WORK/ocsp.out" 2>&1 || true
}
pcaq
expect_status "$PKI/ca/ocspica/ca.pem" good
"$M" revoke --ca ocspica --reason CACompromise 2>/dev/null
pcaq
expect_status "$PKI/ca/ocspica/ca.pem" revoked

step "OCSP fault injection"
fault() { "$M" ocsp-fault --ca region "$@" 2>/dev/null; }
fault --http-status 503
[[ $(curl -s -o /dev/null -w '%{http_code}' --data-binary @"$WORK/req.der" "$OCSP/region") == 503 ]] || fail "fault http-status"
fault --delay-ms 1500
t="$(curl -s -o /dev/null -w '%{time_total}' --data-binary @"$WORK/req.der" "$OCSP/region")"
awk -v t="$t" 'BEGIN { exit !(t >= 1.5) }' || fail "fault delay-ms: answered after ${t}s"
for st in unauthorized malformedRequest tryLater internalError; do
	fault --status "$st"
	ocsp_q region "$rpsap" sha256
	grep -qi "Responder Error: $st" "$WORK/ocsp.out" || fail "fault status $st: $(cat "$WORK/ocsp.out")"
done
fault --sha1-only
ocsp_q region "$rpsap" sha256
grep -qi 'Responder Error: unauthorized' "$WORK/ocsp.out" || fail "fault sha1-only, SHA-256 CertID: $(cat "$WORK/ocsp.out")"
ocsp_q region "$rpsap" sha1
expect_status "$rpsap" good
fault --unknown
ocsp_q region "$rpsap" sha256
expect_status "$rpsap" unknown
fault --wrong-signer
ocsp_q region "$rpsap" sha256
grep -q 'Response Verify Failure' "$WORK/ocsp.out" || fail "fault wrong-signer: $(cat "$WORK/ocsp.out")"
# A responder certificate issued by the CA without id-pkix-ocsp-nocheck (a
# negative fixture). OpenSSL's client accepts the response: it never checks a
# responder's own revocation status; mockpca-lint reports the certificate.
fault --no-nocheck
ocsp_q region "$rpsap" sha256 -resp_text
expect_status "$rpsap" good
grep -q 'Responder Id: .*CN = negative-no-nocheck.ocsp.ica.region.mock.test' "$WORK/ocsp.out" ||
	fail "fault no-nocheck: not signed by the fixture: $(cat "$WORK/ocsp.out")"
! grep -q 'OCSP No Check' "$WORK/ocsp.out" || fail "fault no-nocheck: the fixture carries id-pkix-ocsp-nocheck"
expect_fail "lint of the no-nocheck fixture" "$M" lint -profile ocsp-responder -issuer "$PKI/ca/region/ca.pem" \
	-root "$PKI/trust/pca.pem" "$PKI/ca/region/ocsp/negative-no-nocheck/cert.pem"
grep -q 'id-pkix-ocsp-nocheck is missing' "$WORK/out" || fail "lint of the no-nocheck fixture: $(cat "$WORK/out")"
expect_fail "--wrong-signer with --no-nocheck" "$M" ocsp-fault --ca region --wrong-signer --no-nocheck
fault --stale
curl -fsS -o "$WORK/stale1.der" --data-binary @"$WORK/req.der" "$OCSP/region"
sleep 2
curl -fsS -o "$WORK/stale2.der" --data-binary @"$WORK/req.der" "$OCSP/region"
cmp -s "$WORK/stale1.der" "$WORK/stale2.der" || fail "fault stale: the response is not replayed"
openssl ocsp -respin "$WORK/stale2.der" -issuer "$PKI/ca/region/ca.pem" -sha256 -cert "$rpsap" -status_age 1 \
	-CAfile "$PKI/trust/pca.pem" -verify_other "$WORK/cas.pem" >"$WORK/ocsp.out" 2>&1 || true
grep -qi 'status too old' "$WORK/ocsp.out" || fail "fault stale: replayed response is not old: $(cat "$WORK/ocsp.out")"
if [[ ${E2E_SLOW:-} == 1 ]]; then
	sleep 61 # past the replayed response's nextUpdate (one minute)
	openssl ocsp -respin "$WORK/stale2.der" -issuer "$PKI/ca/region/ca.pem" -sha256 -cert "$rpsap" -validity_period 0 \
		-CAfile "$PKI/trust/pca.pem" -verify_other "$WORK/cas.pem" >"$WORK/ocsp.out" 2>&1 || true
	grep -qi 'status expired' "$WORK/ocsp.out" || fail "fault stale: not past nextUpdate: $(cat "$WORK/ocsp.out")"
fi
fault --clear
ocsp_q region "$rpsap" sha256
expect_status "$rpsap" good
grep -q 'Response verify OK' "$WORK/ocsp.out" || fail "after clearing faults"

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
expect_fail "verify below the revoked ICA" "$M" verify --ee bcf
grep -q 'certificate revoked' "$WORK/out" || fail "verify output: $(cat "$WORK/out")"
"$M" verify --ee rbcf >/dev/null
expect_fail "issuing from the revoked ICA" "$M" issue --ca county --profile agency --name late \
	--id late.county.mock.test --roles x --org X
[[ ! -e $PKI/ee/late ]] || fail "refused issuance left a directory"

step "revoked ancestor ICA"
"$M" revoke --ca state --reason CACompromise 2>/dev/null
expect_fail "issuing below a revoked ancestor" "$M" issue --ca county2 --profile element --name c3 \
	--id c3.county.mock.test --roles BCF --owner psap2.county.mock.test --org "Mock County PSAP Two"
grep -q "its issuer 'state' is revoked" "$WORK/out" || fail "output: $(cat "$WORK/out")"
expect_fail "verify below a revoked ancestor" "$M" verify --ee c2
grep -q 'certificate revoked' "$WORK/out" || fail "verify output: $(cat "$WORK/out")"

step "stale CRL"
"$M" crl --ca region --seconds 1 2>/dev/null
sleep 2
expect_fail "verify with a stale CRL" "$M" verify --ee rbcf
grep -q 'CRL has expired' "$WORK/out" || fail "verify output: $(cat "$WORK/out")"
"$M" crl --ca region 2>/dev/null
"$M" verify --ee rbcf >/dev/null

echo "OK"
