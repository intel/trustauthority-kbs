#
# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := v1.0.0
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
ifeq ($(PROXY_EXISTS),1)
        DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
else
        undefine DOCKER_PROXY_FLAGS
endif

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

all: clean installer

clean:
	rm -rf *.bin

.PHONY: installer all clean
