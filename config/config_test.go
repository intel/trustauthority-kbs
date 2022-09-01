/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"github.com/onsi/gomega"
	"github.com/spf13/viper"
	"intel/amber/kbs/v1/constant"
	"os"
	"strings"
	"testing"
)

// go test intel/amber/kbs/v1/config -v

func clearEnv() {
	os.Unsetenv("SERVICE_PORT")
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("LOG_CALLER")
	os.Unsetenv("AS_BASE_URL")
	os.Unsetenv("AS_API_KEY")
	os.Unsetenv("KEY_MANAGER")
	os.Unsetenv("KMIP_VERSION")
	os.Unsetenv("KMIP_SERVER_IP")
	os.Unsetenv("KMIP_SERVER_PORT")
	os.Unsetenv("KMIP_HOSTNAME")
	os.Unsetenv("KMIP_USERNAME")
	os.Unsetenv("KMIP_PASSWORD")
	os.Unsetenv("ADMIN_USERNAME")
	os.Unsetenv("ADMIN_PASSWORD")
	os.Unsetenv("KMIP_CLIENT_KEY_PATH")
	os.Unsetenv("KMIP_CLIENT_CERT_PATH")
	os.Unsetenv("KMIP_ROOT_CERT_PATH")
	os.Unsetenv("SAN_LIST")
}

func setValidEnv() {
	os.Setenv("SERVICE_PORT", "6566")
	os.Setenv("LOG_LEVEL", "info")
	os.Setenv("LOG_CALLER", "true")
	os.Setenv("AS_BASE_URL", "https://as.taas.cluster.local")
	os.Setenv("AS_API_KEY", "73616d706c65537472696e67")
	os.Setenv("KEY_MANAGER", "KMIP")
	os.Setenv("KMIP_VERSION", "2.0")
	os.Setenv("KMIP_SERVER_IP", "0.0.0.0")
	os.Setenv("KMIP_SERVER_PORT", "5696")
	os.Setenv("KMIP_HOSTNAME", "")
	os.Setenv("KMIP_USERNAME", "")
	os.Setenv("KMIP_PASSWORD", "")
	os.Setenv("ADMIN_USERNAME", "adminUser")
	os.Setenv("ADMIN_PASSWORD", "adminPassword")
	os.Setenv("KMIP_CLIENT_KEY_PATH", "/etc/pykmip/client_key.pem")
	os.Setenv("KMIP_CLIENT_CERT_PATH", "/etc/pykmip/client_certificate.pem")
	os.Setenv("KMIP_ROOT_CERT_PATH", "/etc/pykmip/root_certificate.pem")
	os.Unsetenv("SAN_LIST")
}

func setViperInit() {
	viper.SetConfigName(constant.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./../test/resource")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
}

func TestLoadValidConf(t *testing.T) {
	setValidEnv()
	setViperInit()
	_, err := LoadConfiguration()
	if err != nil {
		t.Errorf("Loaded valid conf not expected to fail")
	}
	clearEnv()
}
func TestLoadInvalidConf(t *testing.T) {
	viper.SetConfigName("InvalidConf")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./../test/resource")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
	_, err := LoadConfiguration()
	if err == nil {
		t.Errorf("Expected parsing to fail because provided invalid conf")
	}
}

func TestLoadInvalidServicePort(t *testing.T) {
	setValidEnv()
	os.Setenv("SERVICE_PORT", "invalidport")
	setViperInit()
	_, err := LoadConfiguration()
	if err == nil {
		t.Errorf("Expected parsing to fail because config provided invalid port no")
	}
	clearEnv()
}
func TestSaveConf(t *testing.T) {
	setValidEnv()
	setViperInit()
	cfg, err := LoadConfiguration()
	if err != nil {
		t.Log(err)
	}
	err = cfg.Save("./../test/resource/tmp")
	if err != nil {
		t.Log(err)
	}
	clearEnv()
}

func TestSaveConfInvalidFilename(t *testing.T) {
	setValidEnv()
	setViperInit()
	cfg, err := LoadConfiguration()
	if err != nil {
		t.Log(err)
	}
	err = cfg.Save("./../testFolder/tmpInvalid")
	if err != nil {
		t.Log(err)
	}
	clearEnv()
}

func TestValidate(t *testing.T) {
	setValidEnv()
	setViperInit()
	cfg, err := LoadConfiguration()
	if err != nil {
		t.Log(err)
	}
	err = cfg.Save("./../test/resource/tmp")
	if err != nil {
		t.Log(err)
	}
	err = cfg.Validate()
	if err != nil {
		t.Log(err)
	}
	clearEnv()
}

func TestValidateHexString(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	// valid hex string
	err := ValidateHexString("74657374537472696e67")
	if err != nil {
		t.Log(err)
	}
	g.Expect(err).To(gomega.BeNil())

	//invalid hex string
	err = ValidateHexString("InvalidString")
	if err != nil {
		t.Log(err)
	}
	g.Expect(err).To(gomega.HaveOccurred())

}
