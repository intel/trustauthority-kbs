/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package kbs

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"intel/kbs/v1/config"
)

type App struct {
	Config *config.Configuration
}

func (app *App) Run() {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
	if app.configuration() == nil {
		app.Config = config.DefaultConfig()
	}
	err := app.startServer()
	if err != nil {
		fmt.Printf("KBS application exit with an error : %v\n", err.Error())
		os.Exit(1)
	}
}

func (app *App) configuration() *config.Configuration {
	if app.Config != nil {
		return app.Config
	}
	cfg, err := config.LoadConfiguration()
	if err == nil {
		app.Config = cfg
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
