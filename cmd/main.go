/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"os"

	"intel/amber/kbs/v1"
)

func main() {
	app := &kbs.App{}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println("Application returned with error : ", err.Error())
		os.Exit(1)
	}
}
