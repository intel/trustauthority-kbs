/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package config

import (
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	"intel/amber/kbs/v1/constant"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Constants for viper variable names. Will be used to set
// default values as well as to get each value
const (
	ServicePort        = "service-port"
	LogLevel           = "log-level"
	LogCaller          = "log-caller"
	ASBaseUrl          = "as-base-url"
	ASApiKey           = "as-api-key"
	KeyManager         = "key-manager"
	AdminUsername      = "admin-username"
	AdminPassword      = "admin-password"
	SanList            = "san-list"
	KmipVersion        = "kmip.version"
	KmipServerIP       = "kmip.server-ip"
	KmipServerPort     = "kmip.server-port"
	KmipHostname       = "kmip.hostname"
	KmipUsername       = "kmip.username"
	KmipPassword       = "kmip.password"
	KmipClientKeyPath  = "kmip.client-key-path"
	KmipClientCertPath = "kmip.client-cert-path"
	KmipRootCertPath   = "kmip.root-cert-path"
	VaultClientToken   = "vault.client-token"
	VaultServerIP      = "vault.server-ip"
	VaultServerPort    = "vault.server-port"
)

var (
	UserOrEmailReg  = regexp.MustCompile(`^[a-zA-Z0-9.-_]+@?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	PasswordReg     = regexp.MustCompile("(?:([a-zA-Z0-9_\\\\.\\\\, @!#$%^+=>?:{}()\\[\\]\\\"|;~`'*-/]+))")
	UserCredsMaxLen = 256
)

type Configuration struct {
	ServicePort   int         `yaml:"service-port" mapstructure:"service-port"`
	LogLevel      string      `yaml:"log-level" mapstructure:"log-level"`
	LogCaller     bool        `yaml:"log-caller" mapstructure:"log-caller"`
	ASBaseUrl     string      `yaml:"as-base-url" mapstructure:"as-base-url"`
	ASApiKey      string      `yaml:"as-api-key" mapstructure:"as-api-key"`
	KeyManager    string      `yaml:"key-manager" mapstructure:"key-manager"`
	AdminUsername string      `yaml:"admin-username" mapstructure:"admin-username"`
	AdminPassword string      `yaml:"admin-password" mapstructure:"admin-password"`
	SanList       string      `yaml:"san-list" mapstructure:"san-list"`
	Kmip          KmipConfig  `yaml:"kmip"`
	Vault         VaultConfig `yaml:"vault"`
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

// Save saves application specific configuration to config.yml
func (config *Configuration) Save(filename string) error {
	configFile, err := os.OpenFile(filepath.Clean(filename), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "Failed to create config file")
	}
	defer func() {
		derr := configFile.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing config file")
		}
	}()
	err = yaml.NewEncoder(configFile).Encode(config)
	if err != nil {
		return errors.Wrap(err, "Failed to encode config structure")
	}
	return nil
}

func (conf *Configuration) Validate() error {

	if conf.ServicePort < 1024 || conf.ServicePort > 65535 {
		return errors.New("Configured port is not valid")
	}

	if conf.ASBaseUrl == "" || conf.ASApiKey == "" {
		return errors.New("Either AS URL or APIKey is missing")
	}

	if conf.AdminUsername == "" || conf.AdminPassword == "" {
		return errors.New("Either Admin username or password is missing")
	}

	// validate username
	if len(conf.AdminUsername) > UserCredsMaxLen || !UserOrEmailReg.MatchString(conf.AdminUsername) {
		return errors.New("Invalid admin username. The length of username must be <256 and must contain only valid characters")
	}

	//validate password
	if len(conf.AdminPassword) > UserCredsMaxLen || !PasswordReg.MatchString(conf.AdminPassword) {
		return errors.New("Invalid admin password. The length of password must be <256 and must contain only valid characters")
	}

	_, err := url.Parse(conf.ASBaseUrl)
	if err != nil {
		return errors.Wrap(err, "AS URL is not a valid url")
	}

	_, err = base64.URLEncoding.DecodeString(conf.ASApiKey)
	if err != nil {
		return errors.Wrap(err, "AS ApiKey is not a valid base64 string")
	}

	return nil
}
