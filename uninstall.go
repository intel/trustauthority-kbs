/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package kbs

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"intel/amber/kbs/v1/constant"

	log "github.com/sirupsen/logrus"
)

func (app *App) executablePath() string {
	if app.ExecutablePath != "" {
		return app.ExecutablePath
	}
	exc, err := os.Executable()
	if err != nil {
		// If we can't find self-executable path, we're probably in a state that is panic() worthy
		panic(err)
	}
	return exc
}

func (app *App) homeDir() string {
	if app.HomeDir != "" {
		return app.HomeDir
	}
	return constant.HomeDir
}

func (app *App) configDir() string {
	if app.ConfigDir != "" {
		return app.ConfigDir
	}
	return constant.ConfigDir
}

func (app *App) execLinkPath() string {
	if app.ExecLinkPath != "" {
		return app.ExecLinkPath
	}
	return constant.ExecLinkPath
}

func (app *App) runDirPath() string {
	if app.RunDirPath != "" {
		return app.RunDirPath
	}
	return constant.RunDirPath
}

func (app *App) uninstall(purge bool) error {
	fmt.Println("Uninstalling KBS Service")
	// Remove service
	_, _, err := RunCommandWithTimeout(constant.ServiceRemoveCmd, 5)
	if err != nil {
		fmt.Println("Could not disable KBS Service")
		fmt.Println("Error : ", err)
	}

	fmt.Println("removing : ", app.executablePath())
	err = os.Remove(app.executablePath())
	if err != nil {
		log.WithError(err).Error("Error removing executable")
	}
	fmt.Println("removing : ", app.runDirPath())
	err = os.Remove(app.runDirPath())
	if err != nil {
		log.WithError(err).Error("Error removing ", app.runDirPath())
	}
	fmt.Println("removing : ", app.execLinkPath())
	err = os.Remove(app.execLinkPath())
	if err != nil {
		log.WithError(err).Error("Error removing ", app.execLinkPath())
	}
	// If purge is set
	if purge {
		fmt.Println("removing : ", app.configDir())
		err = os.RemoveAll(app.configDir())
		if err != nil {
			log.WithError(err).Error("Error removing config dir")
		}
	}
	fmt.Println("removing : ", app.homeDir())
	err = os.RemoveAll(app.homeDir())
	if err != nil {
		log.WithError(err).Error("Error removing home dir")
	}
	err = app.stop()
	if err != nil {
		log.WithError(err).Error("error stopping service")
	}
	fmt.Fprintln(app.consoleWriter(), "KBS Service uninstalled")
	return nil
}

// RunCommandWithTimeout takes a command line and returs the stdout and stderr output
// If command does not terminate within 'timeout', it returns an error
func RunCommandWithTimeout(commandLine string, timeout int) (stdout, stderr string, err error) {

	// Create a new context and add a timeout to it
	// log.Println(commandLine)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel() // The cancel should be deferred so resources are cleaned up

	r := csv.NewReader(strings.NewReader(commandLine))
	r.Comma = ' '
	records, err := r.Read()
	if records == nil {
		return "", "", fmt.Errorf("No command to execute - commandLine - %s", commandLine)
	}

	var cmd *exec.Cmd
	if len(records) > 1 {
		cmd = exec.CommandContext(ctx, records[0], records[1:]...)
	} else {
		cmd = exec.CommandContext(ctx, records[0])
	}

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err = cmd.Run()
	stdout = outb.String()
	stderr = errb.String()

	return stdout, stderr, err
}
