/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"intel/amber/kbs/v1/config"
	"intel/amber/kbs/v1/constant"

	"github.com/spf13/viper"
)

// This init function sets the default values for viper keys.
func init() {
	viper.SetDefault(config.ServicePort, constant.DefaultKBSListenerPort)
	viper.SetDefault(config.LogLevel, constant.DefaultLogLevel)
	viper.SetDefault(config.LogCaller, false)

	viper.SetDefault(config.EndpointUrl, constant.DefaultEndpointUrl)
	viper.SetDefault(config.KeyManager, constant.DefaultKeyManager)

	// Set default value for kmip version
	viper.SetDefault(config.KmipVersion, constant.KMIP20)
}

func defaultConfig() *config.Configuration {
	return &config.Configuration{
		ServicePort: viper.GetInt(config.ServicePort),
		LogLevel:    viper.GetString(config.LogLevel),
		LogCaller:   viper.GetBool(config.LogCaller),
		ASBaseUrl:   viper.GetString(config.ApsBaseUrl),
		ASApiKey:    viper.GetString(config.CustomToken),
		EndpointURL: viper.GetString(config.EndpointUrl),
		KeyManager:  viper.GetString(config.KeyManager),

		Kmip: config.KmipConfig{
			Version:                   viper.GetString(config.KmipVersion),
			ServerIP:                  viper.GetString(config.KmipServerIP),
			ServerPort:                viper.GetString(config.KmipServerPort),
			Hostname:                  viper.GetString(config.KmipHostname),
			Username:                  viper.GetString(config.KmipUsername),
			Password:                  viper.GetString(config.KmipPassword),
			ClientKeyFilePath:         viper.GetString(config.KmipClientKeyPath),
			ClientCertificateFilePath: viper.GetString(config.KmipClientCertPath),
			RootCertificateFilePath:   viper.GetString(config.KmipRootCertPath),
		},
	}
}
