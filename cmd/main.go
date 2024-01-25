/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package main

import (
	"intel/kbs/v1"
)

func main() {
	app := &kbs.App{}
	app.Run()
}
