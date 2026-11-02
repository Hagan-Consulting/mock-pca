# Copyright 2026 Hagan Consulting Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Container image for mock-pca: bin/mockpca with OpenSSL 3 and prebuilt
# mockpca-lint and mockpca-serve (no Go toolchain at run time).
# DEVELOPMENT ONLY, NOT FOR PRODUCTION. See README.md, "Container".
#
#   docker build -t mock-pca:dev .
#   docker run --rm -v mockpca-pki:/pki mock-pca:dev init --base-url http://pca.mock.test:8080 --id pca.mock.test
#   docker run --rm --init -v mockpca-pki:/pki -p 127.0.0.1:8080:8080 mock-pca:dev serve --listen 0.0.0.0:8080
#
# Supply chain (CLAUDE.md): base images are pinned by multi-arch index digest,
# each one public for at least a week when adopted. Digests were taken from
# the docker-library/repo-info history (repos/<image>/remote/<tag>.md) and
# pulled from Docker Hub, which checks them against the content. Dependabot
# proposes digest updates (7-day cooldown). Debian packages come from the
# Debian archive, whose signatures apt verifies.

# golang:1.27.3-trixie as of 2026-10-21 (repo-info 7f748edf).
FROM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS build
# Use exactly this toolchain (go.mod); never download another one. Standard
# library only, so nothing is fetched from the module proxy either.
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-trimpath
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
RUN go build -ldflags=-buildid= -o /out/ ./cmd/mockpca-lint ./cmd/mockpca-serve

# debian:trixie-slim as of 2026-10-20 (repo-info 8561b0da).
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
LABEL org.opencontainers.image.title="mock-pca" \
      org.opencontainers.image.description="Development-only mock of the NG9-1-1 PCA PKI. NOT FOR PRODUCTION." \
      org.opencontainers.image.source="https://github.com/hagan-consulting/mock-pca" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Hagan Consulting Inc."

# bash, coreutils and mawk are in the base image; OpenSSL 3 is not.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 mockpca \
 && useradd --system --uid 10001 --gid mockpca --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin mockpca \
 && install -d -o mockpca -g mockpca -m 0700 /pki

# bin/mockpca finds profiles/ relative to itself, so the tree keeps the
# repository layout under /opt/mockpca. Root-owned and read-only for the
# runtime user, whatever the umask of the checkout was.
COPY bin/mockpca /opt/mockpca/bin/
COPY profiles/ /opt/mockpca/profiles/
COPY examples/ /opt/mockpca/examples/
COPY LICENSE NOTICE /opt/mockpca/
RUN chmod -R u=rwX,go=rX /opt/mockpca \
 && chmod 0755 /opt/mockpca/bin/mockpca /opt/mockpca/examples/demo.sh
COPY --from=build /out/mockpca-lint /out/mockpca-serve /usr/local/bin/

ENV PATH="/opt/mockpca/bin:$PATH" \
    MOCKPCA_PKI=/pki \
    MOCKPCA_LINT=/usr/local/bin/mockpca-lint \
    MOCKPCA_SERVE=/usr/local/bin/mockpca-serve

USER mockpca
WORKDIR /pki
EXPOSE 8080
ENTRYPOINT ["mockpca"]
CMD ["help"]
