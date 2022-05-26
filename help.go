/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"fmt"

	"intel/amber/kbs/v1/version"
)

const helpStr = `Usage:
	 kbs <command> [arguments]
	 
 Available Commands:
	 help|-h|--help         Show this help message
	 version|-v|--version   Show the version of current kbs build
	 start                  Start kbs
	 status                 Show the status of kbs
	 stop                   Stop kbs
	 uninstall [--purge]    Uninstall kbs
		 --purge            all configuration and data files will be removed if this flag is set
 `

func (app *App) printUsage() {
	fmt.Fprintln(app.consoleWriter(), helpStr)
}

func (app *App) printUsageWithError(err error) {
	fmt.Fprintln(app.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(app.errorWriter(), helpStr)
}

func (app *App) printVersion() {
	fmt.Fprintf(app.consoleWriter(), version.GetVersion().String())
}