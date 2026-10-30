#!/usr/bin/env bash
# Repository checks: gofmt, go vet, go test (with -race when cgo and a C
# compiler are available). Run from anywhere; exits non-zero on failure.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> gofmt"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
	echo "gofmt needed on:" >&2
	echo "$unformatted" >&2
	exit 1
fi

echo "==> go vet"
go vet ./...

race=""
if [ "$(go env CGO_ENABLED)" = "1" ]; then
	cc="$(go env CC)"
	cc="${cc%% *}"
	if command -v "${cc:-gcc}" >/dev/null 2>&1; then
		race="-race"
	fi
fi

if [ -n "$race" ]; then
	echo "==> go test -race"
else
	echo "==> go test (race detector unavailable: needs CGO_ENABLED=1 and a C compiler)"
fi
go test $race -count=1 ./...

echo "==> bash -n"
for f in bin/mockpca scripts/*.sh examples/*.sh; do
	if [ -e "$f" ]; then
		bash -n "$f"
	fi
done

echo "OK"
