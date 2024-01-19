#Copyright(C) 2023 Intel Corporation. All Rights Reserved.


ARG PACKAGES_TO_COVER="config\|keymanager\|transport\|service"
ARG VERSION=v0.0.0

FROM golang:1.21.6-bullseye AS builder
ARG VERSION
WORKDIR /app
COPY . .
RUN GITTAG=$(git describe --tags --abbrev=0 2>/dev/null); \
        GITCOMMIT=$(git describe --always); \
        VERSION=${VERSION:-v0.0.0}; \
        BUILDDATE=$(TZ=UTC date +%Y-%m-%dT%H:%M:%S%z); \
        cd cmd && env GOOS=linux CGO_CPPFLAGS="-D_FORTIFY_SOURCE=2" \
         go build \
            -buildmode=pie \
                -ldflags "-linkmode=external -s -extldflags '-Wl,-z,relro,-z,now' -X intel/kbs/v1/version.BuildDate=${BUILDDATE} -X intel/kbs/v1/version.Version=${VERSION} -X intel/kbs/v1/version.GitHash=${GITCOMMIT}" \
                -o kbs

FROM ubuntu:22.04 AS final
# Install ca-certificates package to get the system certificates
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ARG USERNAME=kbs
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

WORKDIR /
COPY --from=builder /app/cmd/kbs .
EXPOSE 9443
RUN chown $USER_UID:$USER_GID kbs
USER $USERNAME
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
    -ldflags "-X intel/kbs/cache/v1/version.BuildDate=${BUILDDATE} -X intel/kbs/cache/v1/version.Version=${VERSION} -X intel/kbs/cache/v1/version.GitHash=${GITCOMMIT}"
RUN  /usr/local/go/bin/go tool cover -html=cover.out -o cover.html

FROM builder AS swagger
ARG VERSION
ARG GITCOMMIT
ARG PACKAGES_TO_COVER
WORKDIR /app
COPY . .
RUN wget https://github.com/go-swagger/go-swagger/releases/download/v0.30.0/swagger_linux_amd64 -O /usr/local/bin/swagger
RUN chmod +x /usr/local/bin/swagger
