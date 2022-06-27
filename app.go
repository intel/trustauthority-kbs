/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"intel/amber/kbs/v1/config"
	"intel/amber/kbs/v1/constant"
	constants "intel/amber/kbs/v1/constant"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var errInvalidCmd = errors.New("Invalid input after command")

type App struct {
	HomeDir        string
	ConfigDir      string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string

	Config *config.Configuration

	ConsoleWriter io.Writer
	ErrorWriter   io.Writer
}

func (app *App) Run(args []string) error {
	defer func() {
		if err := recover(); err != nil {
			logrus.Errorf("Panic occurred: %+v", err)
		}
	}()
	if len(args) < 2 {
		err := errors.New("Invalid usage of " + constants.ServiceName)
		app.printUsageWithError(err)
		return err
	}
	cmd := args[1]
	switch cmd {
	default:
		err := errors.New("Invalid command: " + cmd)
		app.printUsageWithError(err)
		return err
	case "help", "-h", "--help":
		app.printUsage()
		return nil
	case "version", "-v", "--version":
		app.printVersion()
		return nil
	case "run":
		if len(args) != 2 {
			return errInvalidCmd
		}
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
		viper.AutomaticEnv()
		if app.configuration() == nil {
			app.Config = defaultConfig()
		}
		return app.startServer()
	case "start":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return app.start()
	case "stop":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return app.stop()
	case "status":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return app.status()
	case "uninstall":
		// the only allowed flag is --purge
		purge := false
		if len(args) == 3 {
			if args[2] != "--purge" {
				return errors.New("Invalid flag: " + args[2])
			}
			purge = true
		} else if len(args) != 2 {
			return errInvalidCmd
		}
		return app.uninstall(purge)
	case "setup":
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
		viper.AutomaticEnv()
		if app.configuration() == nil {
			app.Config = defaultConfig()
		}

		err := app.Config.Validate()
		if err != nil {
			return errors.Wrap(err, "Invalid configuration")
		}

		err = app.Config.Save(constant.DefaultConfigFilePath)
		if err != nil {
			return errors.Wrap(err, "Failed to save configuration")
		}
		return ChownDirForUser(constant.ServiceUserName, app.configDir())
	}
}

func (app *App) consoleWriter() io.Writer {
	if app.ConsoleWriter != nil {
		return app.ConsoleWriter
	}
	return os.Stdout
}

func (app *App) errorWriter() io.Writer {
	if app.ErrorWriter != nil {
		return app.ErrorWriter
	}
	return os.Stderr
}

func (app *App) configuration() *config.Configuration {
	if app.Config != nil {
		return app.Config
	}
	config, err := config.LoadConfiguration()
	if err == nil {
		app.Config = config
		return app.Config
	}
	return nil
}

func (app *App) configureLogs() error {

	lv, err := logrus.ParseLevel(app.Config.LogLevel)
	if err != nil {
		return errors.Wrap(err, "Failed to initiate loggers. Invalid log level: "+app.Config.LogLevel)
	}
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetReportCaller(app.Config.LogCaller)
	logrus.SetLevel(lv)

	logrus.Info("logger initialized")
	return nil
}

func (app *App) start() error {
	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl start kbs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, "start", "kbs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (app *App) stop() error {
	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl stop kbs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, "stop", "kbs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (app *App) status() error {
	fmt.Fprintln(app.consoleWriter(), `Forwarding to "systemctl status kbs"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, "status", "kbs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func ChownDirForUser(serviceUserName, configDir string) error {
	svcUser, err := user.Lookup(serviceUserName)
	if err != nil {
		return errors.Wrapf(err, "Could not find service user '%s'", serviceUserName)
	}
	uid, err := strconv.Atoi(svcUser.Uid)
	if err != nil {
		return errors.Wrapf(err, "Could not parse service user uid '%s'", svcUser.Uid)
	}
	gid, err := strconv.Atoi(svcUser.Gid)
	if err != nil {
		return errors.Wrapf(err, "Could not parse service user gid '%s'", svcUser.Gid)
	}
	err = ChownR(configDir, uid, gid)
	if err != nil {
		return errors.Wrap(err, "Error while changing ownership of files inside config directory")
	}
	return nil
}

// ChownR method is used to change the ownership of all the file in a directory
func ChownR(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, uid, gid)
		}
		return err
	})
}
