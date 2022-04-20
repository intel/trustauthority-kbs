# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM golang:1.17 AS builder
WORKDIR /app
COPY . .
RUN GITTAG=$(git describe --tags --abbrev=0 2>/dev/null); \
        GITCOMMIT=$(git describe --always); \
        VERSION=${GITTAG:-v0.0.0}; \
        BUILDDATE=$(TZ=UTC date +%Y-%m-%dT%H:%M:%S%z); \
        cd cmd && GOOS=linux GOSUMDB=off \
        go build -ldflags "-X intel/amber/kbs/v1/version.BuildDate=${BUILDDATE} -X intel/amber/kbs/v1/version.Version=${VERSION} -X intel/amber/kbs/v1/version.GitHash=${GITCOMMIT}" -o kbs

FROM gcr.io/distroless/base-debian11 AS final
WORKDIR /
COPY --from=builder /app/cmd/kbs .
EXPOSE 9443
ENTRYPOINT ["/kbs"]
CMD ["run"]
