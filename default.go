/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"intel/amber/kbs/v1/config"
	"intel/amber/kbs/v1/constant"
	"strings"

	"github.com/spf13/viper"
)

// This init function sets the default values for viper keys.
func init() {
	viper.SetDefault(config.ServicePort, constant.DefaultHttpPort)
	viper.SetDefault(config.LogLevel, constant.DefaultLogLevel)
	viper.SetDefault(config.LogCaller, false)

	viper.SetDefault(config.KeyManager, constant.DefaultKeyManager)

	// Set default value for kmip config
	viper.SetDefault(config.KmipVersion, constant.KMIP20)
	viper.SetDefault(config.KmipServerPort, constant.DefaultKmipPort)
	viper.SetDefault(config.KmipClientKeyPath, constant.KmipClientKeyPath)
	viper.SetDefault(config.KmipClientCertPath, constant.KmipClientCertPath)
	viper.SetDefault(config.KmipRootCertPath, constant.KmipRootCertPath)
}

func defaultConfig() *config.Configuration {
	var cfg *config.Configuration

	cfg = &config.Configuration{
		ServicePort: viper.GetInt(config.ServicePort),
		LogLevel:    viper.GetString(config.LogLevel),
		LogCaller:   viper.GetBool(config.LogCaller),
		ASBaseUrl:   viper.GetString(config.ASBaseUrl),
		ASApiKey:    viper.GetString(config.ASApiKey),
		KeyManager:  viper.GetString(config.KeyManager),
	}

	if strings.ToLower(cfg.KeyManager) == constant.VaultKeyManager {
		cfg.Vault = config.VaultConfig{
			ServerIP:    viper.GetString(config.VaultServerIP),
			ServerPort:  viper.GetString(config.VaultServerPort),
			ClientToken: viper.GetString(config.VaultClientToken),
		}
	} else {
		cfg.Kmip = config.KmipConfig{
			Version:                   viper.GetString(config.KmipVersion),
			ServerIP:                  viper.GetString(config.KmipServerIP),
			ServerPort:                viper.GetString(config.KmipServerPort),
			Hostname:                  viper.GetString(config.KmipHostname),
			Username:                  viper.GetString(config.KmipUsername),
			Password:                  viper.GetString(config.KmipPassword),
			ClientKeyFilePath:         viper.GetString(config.KmipClientKeyPath),
			ClientCertificateFilePath: viper.GetString(config.KmipClientCertPath),
			RootCertificateFilePath:   viper.GetString(config.KmipRootCertPath),
		}
	}

	return cfg
}
