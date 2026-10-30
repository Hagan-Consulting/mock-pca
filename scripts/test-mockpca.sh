#!/usr/bin/env bash
# Unit tests for single bin/mockpca functions that need no PKI or OpenSSL.
# Run from anywhere; exits non-zero on failure. scripts/check.sh runs it.
set -euo pipefail

# shellcheck source=../bin/mockpca
source "$(dirname "$0")/../bin/mockpca"

fail=0
check() { # NAME GOT WANT
	if [[ $2 != "$3" ]]; then
		echo "FAIL $1: got $2, want $3" >&2
		fail=1
	fi
}

# serve_wait NOW NEXT_CRL NEXT_CHECK
while read -r name now crl chk want; do
	check "serve_wait $name" "$(serve_wait "$now" "$crl" "$chk")" "$want"
done <<'EOF'
crl-first        100 1900  86500 1800
check-first      100 259300 86500 86400
equal            100 500   500   400
crl-overdue      100 90    86500 1
check-overdue    100 1900  100   1
EOF

# The schedule serve follows with its wait and its due checks: CRLs every
# half lifetime, responder checks daily, whatever the CRL interval.
schedule() { # HOURS DAYS: the CRL and check times (hours) within DAYS
	local crl_every=$(($1 * 1800)) end=$(($2 * 86400)) now=0 crls="" checks=""
	local next_crl=$crl_every next_check=$SERVE_CHECK_EVERY
	while :; do
		now=$((now + $(serve_wait "$now" "$next_crl" "$next_check")))
		((now <= end)) || break
		if ((now >= next_check)); then
			checks+=" $((now / 3600))"
			next_check=$((now + SERVE_CHECK_EVERY))
		fi
		if ((now >= next_crl)); then
			crls+=" $((now / 3600))"
			next_crl=$((now + crl_every))
		fi
	done
	echo "crl${crls} check${checks}"
}
check "schedule 72h" "$(schedule 72 6)" "crl 36 72 108 144 check 24 48 72 96 120 144"
check "schedule 24h" "$(schedule 24 2)" "crl 12 24 36 48 check 24 48"
check "schedule 720h" "$(schedule 720 3)" "crl check 24 48 72"

((fail == 0)) && echo "test-mockpca: OK"
exit "$fail"
