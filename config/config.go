/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package config

import (
	"encoding/base64"
	"intel/kbs/v1/constant"
	"net/url"
	"regexp"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// Constants for viper variable names. Will be used to set
// default values as well as to get each value
const (
	ServicePort                  = "service-port"
	LogLevel                     = "log-level"
	LogCaller                    = "log-caller"
	TrustAuthorityBaseUrl        = "trustauthority-base-url"
	TrustAuthorityApiUrl         = "trustauthority-api-url"
	TrustAuthorityApiKey         = "trustauthority-api-key"
	KeyManager                   = "key-manager"
	AdminUsername                = "admin-username"
	AdminPassword                = "admin-password"
	SanList                      = "san-list"
	KmipVersion                  = "kmip.version"
	KmipServerIP                 = "kmip.server-ip"
	KmipServerPort               = "kmip.server-port"
	KmipHostname                 = "kmip.hostname"
	KmipUsername                 = "kmip.username"
	KmipPassword                 = "kmip.password"
	KmipClientKeyPath            = "kmip.client-key-path"
	KmipClientCertPath           = "kmip.client-cert-path"
	KmipRootCertPath             = "kmip.root-cert-path"
	VaultClientToken             = "vault.client-token"
	VaultServerIP                = "vault.server-ip"
	VaultServerPort              = "vault.server-port"
	BearerTokenValidityInMinutes = "bearer-token-validity-in-minutes"
)

var (
	userOrEmailReg = regexp.MustCompile(`^[a-zA-Z0-9.-_]+@?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	passwordReg    = regexp.MustCompile("(?:([a-zA-Z0-9_\\\\.\\\\, @!#$%^+=>?:{}()\\[\\]\\\"|;~`'*-/]+))")
)

type Configuration struct {
	ServicePort                  int         `yaml:"service-port" mapstructure:"service-port"`
	LogLevel                     string      `yaml:"log-level" mapstructure:"log-level"`
	LogCaller                    bool        `yaml:"log-caller" mapstructure:"log-caller"`
	TrustAuthorityBaseUrl        string      `yaml:"trustauthority-base-url" mapstructure:"trustauthority-base-url"`
	TrustAuthorityApiUrl         string      `yaml:"trustauthority-api-url" mapstructure:"trustauthority-api-url"`
	TrustAuthorityApiKey         string      `yaml:"trustauthority-api-key" mapstructure:"trustauthority-api-key"`
	KeyManager                   string      `yaml:"key-manager" mapstructure:"key-manager"`
	AdminUsername                string      `yaml:"admin-username" mapstructure:"admin-username"`
	AdminPassword                string      `yaml:"admin-password" mapstructure:"admin-password"`
	SanList                      string      `yaml:"san-list" mapstructure:"san-list"`
	Kmip                         KmipConfig  `yaml:"kmip"`
	Vault                        VaultConfig `yaml:"vault"`
	BearerTokenValidityInMinutes int         `yaml:"bearer-token-validity-in-minutes" mapstructure:"bearer-token-validity-in-minutes"`
}

type KmipConfig struct {
	Version                   string `yaml:"version" mapstructure:"version"`
	ServerIP                  string `yaml:"server-ip" mapstructure:"server-ip"`
	ServerPort                string `yaml:"server-port" mapstructure:"server-port"`
	Hostname                  string `yaml:"hostname" mapstructure:"hostname"`
	Username                  string `yaml:"username" mapstructure:"username"`
	Password                  string `yaml:"password" mapstructure:"password"`
	ClientKeyFilePath         string `yaml:"client-key-path" mapstructure:"client-key-path"`
	ClientCertificateFilePath string `yaml:"client-cert-path" mapstructure:"client-cert-path"`
	RootCertificateFilePath   string `yaml:"root-cert-path" mapstructure:"root-cert-path"`
}

type VaultConfig struct {
	ServerIP    string `yaml:"server-ip" mapstructure:"server-ip"`
	ServerPort  string `yaml:"server-port" mapstructure:"server-port"`
	ClientToken string `yaml:"client-token" mapstructure:"client-token"`
}

// init sets the configuration file name and type
func init() {
	viper.SetConfigName(constant.ConfigFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(constant.ConfigDir)
}

// LoadConfiguration loads application specific configuration from config.yml
func LoadConfiguration() (*Configuration, error) {
	ret := Configuration{}
	// Find and read the config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			return &ret, errors.Wrap(err, "Config file not found")
		}
		return &ret, errors.Wrap(err, "Failed to load config")
	}
	if err := viper.Unmarshal(&ret); err != nil {
		return &ret, errors.Wrap(err, "Failed to unmarshal config")
	}
	return &ret, nil
}

func (conf *Configuration) Validate() error {

	if conf.ServicePort < 1024 || conf.ServicePort > 65535 {
		return errors.New("Configured port is not valid")
	}

	if conf.TrustAuthorityApiUrl == "" || conf.TrustAuthorityApiKey == "" || conf.TrustAuthorityBaseUrl == "" {
		return errors.New("Either TRUSTAUTHORITY_API_URL or TRUSTAUTHORITY_API_KEY or TRUSTAUTHORITY_BASE_URL is missing")
	}

	if conf.AdminUsername == "" || conf.AdminPassword == "" {
		return errors.New("Either Admin username or password is missing")
	}

	if conf.BearerTokenValidityInMinutes < constant.MinTokenValidityInMinutes || conf.BearerTokenValidityInMinutes > constant.MaxTokenValidityInMinutes {
		return errors.Errorf("Invalid Bearer Token Validity configured, it must be between %v to %v", constant.MinTokenValidityInMinutes, constant.MaxTokenValidityInMinutes)
	}

	// validate username
	err := ValidateUsername(conf.AdminUsername)
	if err != nil {
		return err
	}

	//validate password
	err = ValidatePassword(conf.AdminPassword)
	if err != nil {
		return err
	}

	_, err = url.Parse(conf.TrustAuthorityApiUrl)
	if err != nil {
		return errors.Wrap(err, "ITA TRUSTAUTHORITY_API_URL is not a valid url")
	}

	_, err = url.Parse(conf.TrustAuthorityBaseUrl)
	if err != nil {
		return errors.Wrap(err, "ITA TRUSTAUTHORITY_BASE_URL is not a valid url")
	}

	_, err = base64.URLEncoding.DecodeString(conf.TrustAuthorityApiKey)
	if err != nil {
		return errors.Wrap(err, "ITA TRUSTAUTHORITY_API_KEY  is not a valid base64 string")
	}

	return nil
}

func ValidateUsername(username string) error {
	if len(username) < constant.UserCredsMaxLen && userOrEmailReg.MatchString(username) {
		return nil
	}
	return errors.New("Invalid input for ADMIN_USERNAME configuration")
}

func ValidatePassword(password string) error {
	if len(password) < constant.UserCredsMaxLen && len(password) > constant.PasswordMinLen && passwordReg.MatchString(password) {
		return nil
	}
	return errors.New("Invalid input for ADMIN_PASSWORD configuration")
}
