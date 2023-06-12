# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


ARG PACKAGES_TO_COVER="config\|keymanager\|transport\|service"
ARG VERSION=v0.0.0

FROM golang:1.20.4 AS builder
ARG VERSION
WORKDIR /app
COPY . .
RUN GITTAG=$(git describe --tags --abbrev=0 2>/dev/null); \
        GITCOMMIT=$(git describe --always); \
        VERSION=${VERSION:-v0.0.0}; \
        BUILDDATE=$(TZ=UTC date +%Y-%m-%dT%H:%M:%S%z); \
        cd cmd && GOOS=linux GOSUMDB=off \
        go build -ldflags "-X intel/amber/kbs/v1/version.BuildDate=${BUILDDATE} -X intel/amber/kbs/v1/version.Version=${VERSION} -X intel/amber/kbs/v1/version.GitHash=${GITCOMMIT}" -o kbs

FROM gcr.io/distroless/base-debian11 AS final
WORKDIR /
COPY --from=builder /app/cmd/kbs .
EXPOSE 9443
ENTRYPOINT ["/kbs"]
CMD ["run"]

FROM builder AS tester
ARG VERSION
ARG GITCOMMIT
ARG PACKAGES_TO_COVER
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    BUILDDATE=$(TZ=UTC date +%Y-%m-%dT%H:%M:%S%z); \
    COVER_PACKAGES=$(go list ./... | grep v1/ | grep ${PACKAGES_TO_COVER} | tr '\n' ','); \
    env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off \
    /usr/local/go/bin/go test ./... \
        -coverpkg="${COVER_PACKAGES}" -coverprofile cover.out \
    -ldflags "-X intel/amber/kbs/cache/v1/version.BuildDate=${BUILDDATE} -X intel/amber/kbs/cache/v1/version.Version=${VERSION} -X intel/amber/kbs/cache/v1/version.GitHash=${GITCOMMIT}"
RUN  /usr/local/go/bin/go tool cover -html=cover.out -o cover.html

FROM builder AS swagger
ARG VERSION
ARG GITCOMMIT
ARG PACKAGES_TO_COVER
WORKDIR /app
COPY . .
RUN wget https://github.com/go-swagger/go-swagger/releases/download/v0.30.0/swagger_linux_amd64 -O /usr/local/bin/swagger
RUN chmod +x /usr/local/bin/swagger
