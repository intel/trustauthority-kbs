/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package main

import (
	"fmt"
	"os"

	"intel/kbs/v1"
)

func main() {
	app := &kbs.App{}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println("Application returned with error : ", err.Error())
		os.Exit(1)
	}
}
