/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package config

import (
	"github.com/onsi/gomega"
	"github.com/spf13/viper"
	"intel/kbs/v1/constant"
	"os"
	"strings"
	"testing"
)

// go test intel/amber/kbs/v1/config -v

func clearEnv() {
	os.Unsetenv("SERVICE_PORT")
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("LOG_CALLER")
	os.Unsetenv("TRUSTAUTHORITY_API_URL")
	os.Unsetenv("TRUSTAUTHORITY_API_KEY")
	os.Unsetenv("TRUSTAUTHORITY_BASE_URL")
	os.Unsetenv("KEY_MANAGER")
	os.Unsetenv("BEARER_TOKEN_VALIDITY_IN_MINUTES")
	os.Unsetenv("HTTP_READ_HEADER_TIMEOUT")
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
	os.Setenv("TRUSTAUTHORITY_API_URL", "https://as.taas.cluster.local")
	os.Setenv("TRUSTAUTHORITY_API_KEY", "YXBpa2V5")
	os.Setenv("TRUSTAUTHORITY_BASE_URL", "https://as.taas.cluster.local")
	os.Setenv("BEARER_TOKEN_VALIDITY_IN_MINUTES", "5")
	os.Setenv("HTTP_READ_HEADER_TIMEOUT", "10")
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
	os.Setenv("SAN_LIST", "localhost")
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
	_, err := LoadConfiguration()
	if err == nil {
		t.Errorf("Expected parsing to fail because config provided invalid port no")
	}
	clearEnv()
}

func TestSaveConf(t *testing.T) {
	setValidEnv()
	setViperInit()
	_, err := LoadConfiguration()
	if err != nil {
		t.Log(err)
	}

	clearEnv()
}

func TestSaveConfInvalidFilename(t *testing.T) {
	setValidEnv()
	setViperInit()
	_, err := LoadConfiguration()
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
	err = cfg.Validate()
	if err != nil {
		t.Log(err)
	}
	clearEnv()
}

func TestValidateInvalidConfig(t *testing.T) {
	setValidEnv()
	setViperInit()
	cfg, err := LoadConfiguration()
	if err != nil {
		t.Log(err)
	}
	g := gomega.NewGomegaWithT(t)
	// invalid service port
	cfg.ServicePort = 10

	err = cfg.Validate()
	g.Expect(err).To(gomega.HaveOccurred())

	// invalid username and password
	cfg, err = LoadConfiguration()
	if err != nil {
		t.Log(err)
	}
	cfg.AdminPassword = ""
	cfg.AdminUsername = ""
	err = cfg.Validate()
	g.Expect(err).To(gomega.HaveOccurred())

	// invalid username
	cfg, err = LoadConfiguration()
	if err != nil {
		t.Log(err)
	}
	cfg.AdminUsername = "!!!"
	err = cfg.Validate()
	g.Expect(err).To(gomega.HaveOccurred())

	// invalid API key and URL
	cfg, err = LoadConfiguration()
	if err != nil {
		t.Log(err)
	}
	cfg.TrustAuthorityApiKey = ""
	cfg.TrustAuthorityBaseUrl = ""
	cfg.TrustAuthorityApiUrl = ""
	err = cfg.Validate()
	g.Expect(err).To(gomega.HaveOccurred())

	// invalid api key
	cfg, err = LoadConfiguration()
	if err != nil {
		t.Log(err)
	}
	cfg.TrustAuthorityApiKey = "123"
	err = cfg.Validate()
	g.Expect(err).To(gomega.HaveOccurred())

	// invalid api url
	cfg, err = LoadConfiguration()
	if err != nil {
		t.Log(err)
	}
	cfg.TrustAuthorityBaseUrl = ":invalid-url"
	err = cfg.Validate()
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestInvalidTokenValidity(t *testing.T) {
	setValidEnv()
	setViperInit()
	cfg, err := LoadConfiguration()
	if err != nil {
		t.Log(err)
	}
	g := gomega.NewGomegaWithT(t)
	cfg.BearerTokenValidityInMinutes = 0
	err = cfg.Validate()
	g.Expect(err).To(gomega.HaveOccurred())
}
