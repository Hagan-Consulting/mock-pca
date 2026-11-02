#!/usr/bin/env bash
# Copyright 2026 Hagan Consulting Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Builds a sample mock PCA hierarchy:
#
#   PCA Root (pca)
#   ├── Mock State ICA Tier2 (state, pathLenConstraint 1)
#   │   └── Mock County ICA Tier3 (county, pathLenConstraint 0)
#   │       ├── agency   psap      psap.county.mock.test
#   │       ├── agent    jsmith    jsmith@psap.county.mock.test
#   │       ├── element  bcf       bcf.county.mock.test (+ localhost, 127.0.0.1)
#   │       ├── service  esrp      esrp.county.mock.test
#   │       └── signing  logsign   log.county.mock.test (ECDSA P-256)
#   └── Mock Region ICA Tier2 (region, pathLenConstraint 0)
#       ├── agency   rpsap     psap.region.mock.test
#       └── element  rbcf      bcf.region.mock.test
#
# Environment: MOCKPCA_PKI (default ./pki), BASE_URL (default
# http://pca.mock.test:8080; the host must resolve to where `mockpca serve`
# runs, e.g. through /etc/hosts).
set -euo pipefail

M="$(cd "$(dirname "$0")/.." && pwd)/bin/mockpca"
BASE_URL="${BASE_URL:-http://pca.mock.test:8080}"

"$M" init --base-url "$BASE_URL" --id pca.mock.test

"$M" ica --name state --parent pca --id ica.state.mock.test --owner agency.state.mock.test \
	--org "Mock State 911" --st VT --label "Mock State"
"$M" ica --name county --parent state --id ica.county.mock.test --owner psap.county.mock.test \
	--org "Mock County 911" --label "Mock County"
"$M" ica --name region --parent pca --pathlen 0 --id ica.region.mock.test --owner psap.region.mock.test \
	--org "Mock Region 911" --label "Mock Region"

county=(--ca county --org "Mock County PSAP" --owner psap.county.mock.test)
"$M" issue "${county[@]}" --profile agency --name psap --id psap.county.mock.test \
	--roles urn:emergency:service:responder.psap,urn:emergency:service:responder.police.local
"$M" issue "${county[@]}" --profile agent --name jsmith --id jsmith@psap.county.mock.test \
	--roles Dispatching,CallTaking
"$M" issue "${county[@]}" --profile element --name bcf --id bcf.county.mock.test --roles BCF \
	--dns localhost --ip 127.0.0.1
"$M" issue "${county[@]}" --profile service --name esrp --id esrp.county.mock.test --roles ESRP,Bridge
"$M" issue "${county[@]}" --profile signing --name logsign --id log.county.mock.test --roles LoggingService

region=(--ca region --org "Mock Region PSAP" --owner psap.region.mock.test)
"$M" issue "${region[@]}" --profile agency --name rpsap --id psap.region.mock.test \
	--roles urn:emergency:service:responder.psap
"$M" issue "${region[@]}" --profile element --name rbcf --id bcf.region.mock.test --roles BCF

"$M" list
