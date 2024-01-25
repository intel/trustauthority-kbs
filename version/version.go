/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package version

import (
	"fmt"

	"intel/kbs/v1/constant"
)

var Version = ""
var GitHash = ""
var BuildDate = ""

type ServiceVersion struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	GitHash   string `json:"gitHash"`
	BuildDate string `json:"buildDate"`
}

var ver = ServiceVersion{
	Name:      constant.ExplicitServiceName,
	Version:   Version,
	GitHash:   GitHash,
	BuildDate: BuildDate,
}

func GetVersion() *ServiceVersion {
	return &ver
}

func (ver *ServiceVersion) String() string {
	return fmt.Sprintf("%s %s-%s [%s]", ver.Name, ver.Version, ver.GitHash, ver.BuildDate)
}
