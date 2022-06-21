#
# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

ORGNAME := taas
APPNAME := key-broker-service
REPO := localhost:5000
SHELL := /bin/bash

GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
ifeq ($(PROXY_EXISTS),1)
    DOCKER_PROXY_FLAGS = --build-arg http_proxy="${http_proxy}" --build-arg https_proxy="${https_proxy}" --build-arg no_proxy="${no_proxy}"
    DOCKER_RUN_PROXY_FLAGS = -e HTTP_PROXY="${http_proxy}" -e HTTPS_PROXY="${https_proxy}" -e NO_PROXY="${no_proxy}"
else
        undefine DOCKER_PROXY_FLAGS
        undefine DOCKER_RUN_PROXY_FLAGS
endif

makefile_path := $(realpath $(lastword $(MAKEFILE_LIST)))
makefile_dir := $(dir $(makefile_path))
OUTDIR := $(addprefix $(makefile_dir),out)
TMPDIR := $(addprefix $(makefile_dir),tmp)

.PHONY: all installer docker test clean help

all: docker

kbs:
	cd cmd && go mod tidy && \
                go build -ldflags "-X intel/amber/kbs/v1/version.BuildDate=$(BUILDDATE) -X intel/amber/kbs/v1/version.Version=$(VERSION) -X intel/amber/kbs/v1/version.GitHash=$(GITCOMMIT)" -o kbs

installer: kbs
	mkdir -p installer
	cp build/linux/* installer/
	chmod +x installer/install.sh
	cp cmd/kbs installer/kbs
	makeself installer kbs-$(VERSION).bin "kbs $(VERSION)" ./install.sh
	rm -rf installer

docker: docker.timestamp

docker.timestamp: Dockerfile go.mod go.sum $(shell find $(makefile_dir) -type f -name '*.go')
	pushd "$(makefile_dir)"
	docker build ${DOCKER_PROXY_FLAGS} -f Dockerfile --target final -t $(ORGNAME)/$(APPNAME):$(VERSION) .
	touch $@

test-image:
	DOCKER_BUILDKIT=1 docker build ${DOCKER_PROXY_FLAGS} \
                                  -f Dockerfile --target tester \
                                          -t $(ORGNAME)/$(APPNAME)-unit-test:$(VERSION) .

test: test-image
	docker run -i ${DOCKER_RUN_PROXY_FLAGS} --rm $(ORGNAME)/$(APPNAME)-unit-test:$(VERSION) /bin/bash -c "/usr/local/go/bin/go test ./..."

test-coverage: test-image
	docker run -i ${DOCKER_RUN_PROXY_FLAGS} --rm $(ORGNAME)/$(APPNAME)-unit-test:$(VERSION) /bin/bash -c "/usr/local/go/bin/go test ./... -coverprofile=cover.out; /usr/local/go/bin/go tool cover -func cover.out"

go-fmt: test-image
	docker run -i --rm $(ORGNAME)/$(APPNAME)-unit-test:$(VERSION) env GOOS=linux GOSUMDB=off /usr/local/go/bin/gofmt -l .

push-commit: push
	docker tag $(ORGNAME)/$(APPNAME):$(VERSION) $(REPO)/$(ORGNAME)/$(APPNAME):$(VERSION)-$(GITCOMMIT)
	docker push $(REPO)/$(ORGNAME)/$(APPNAME):$(VERSION)-$(GITCOMMIT)

push: docker.timestamp
	docker tag $(ORGNAME)/$(APPNAME):$(VERSION) $(REPO)/$(ORGNAME)/$(APPNAME):$(VERSION)
	docker push $(REPO)/$(ORGNAME)/$(APPNAME):$(VERSION)

clean:
	if pushd $(makefile_dir); then \
		rm -rf $(OUTDIR) $(TMPDIR); \
		rm -f *.bin docker.timestamp cmd/kbs; \
	fi;

help:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$'
