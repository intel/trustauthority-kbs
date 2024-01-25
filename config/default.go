/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package config

import (
	"github.com/spf13/viper"
	"intel/kbs/v1/constant"
	"strings"
)

// This init function sets the default values for viper keys.
func init() {
	viper.SetDefault(ServicePort, constant.DefaultHttpPort)
	viper.SetDefault(LogLevel, constant.DefaultLogLevel)
	viper.SetDefault(LogCaller, false)
	viper.SetDefault(SanList, constant.DefaultTlsSan)
	viper.SetDefault(BearerTokenValidityInMinutes, constant.DefaultTokenExpiration)
	viper.SetDefault(KeyManager, constant.DefaultKeyManager)
	viper.SetDefault(HttpReadHeaderTimeout, constant.DefaultHttpReadHeaderTimeOut)

	// Set default value for vault config
	viper.SetDefault(VaultServerPort, constant.DefaultVaultPort)

	// set default defender config
	viper.SetDefault(AuthenticationDefendLockoutMinutes, constant.DefaultAuthDefendLockoutMins)
	viper.SetDefault(AuthenticationDefendMaxAttempts, constant.DefaultAuthDefendMaxAttempts)
	viper.SetDefault(AuthenticationDefendIntervalMinutes, constant.DefaultAuthDefendIntervalMins)

}

func DefaultConfig() *Configuration {
	var cfg *Configuration

	cfg = &Configuration{
		ServicePort:                         viper.GetInt(ServicePort),
		LogLevel:                            viper.GetString(LogLevel),
		LogCaller:                           viper.GetBool(LogCaller),
		TrustAuthorityApiUrl:                viper.GetString(TrustAuthorityApiUrl),
		TrustAuthorityBaseUrl:               viper.GetString(TrustAuthorityBaseUrl),
		TrustAuthorityApiKey:                viper.GetString(TrustAuthorityApiKey),
		KeyManager:                          viper.GetString(KeyManager),
		AdminPassword:                       viper.GetString(AdminPassword),
		AdminUsername:                       viper.GetString(AdminUsername),
		SanList:                             viper.GetString(SanList),
		BearerTokenValidityInMinutes:        viper.GetInt(BearerTokenValidityInMinutes),
		HttpReadHeaderTimeout:               viper.GetInt(HttpReadHeaderTimeout),
		AuthenticationDefendMaxAttempts:     viper.GetInt(AuthenticationDefendMaxAttempts),
		AuthenticationDefendIntervalMinutes: viper.GetInt(AuthenticationDefendIntervalMinutes),
		AuthenticationDefendLockoutMinutes:  viper.GetInt(AuthenticationDefendLockoutMinutes),
	}

	if strings.ToLower(cfg.KeyManager) == constant.VaultKeyManager {
		cfg.Vault = VaultConfig{
			ServerIP:    viper.GetString(VaultServerIP),
			ServerPort:  viper.GetString(VaultServerPort),
			ClientToken: viper.GetString(VaultClientToken),
		}
	} else {
		cfg.Kmip = KmipConfig{
			Version:                   viper.GetString(KmipVersion),
			ServerIP:                  viper.GetString(KmipServerIP),
			ServerPort:                viper.GetString(KmipServerPort),
			Hostname:                  viper.GetString(KmipHostname),
			Username:                  viper.GetString(KmipUsername),
			Password:                  viper.GetString(KmipPassword),
			ClientKeyFilePath:         viper.GetString(KmipClientKeyPath),
			ClientCertificateFilePath: viper.GetString(KmipClientCertPath),
			RootCertificateFilePath:   viper.GetString(KmipRootCertPath),
		}
	}
	return cfg
}
