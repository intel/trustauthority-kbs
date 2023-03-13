/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constant

import (
	"time"
)

// general KBS constants
const (
	ServiceName         = "kbs"
	ExplicitServiceName = "Key Broker Service"
	ServiceDir          = "kbs/"
	ApiVersion          = "v1"
	ServiceUserName     = "kbs"

	HomeDir      = "/opt/" + ServiceDir
	RunDirPath   = "/run/" + ServiceDir
	ExecLinkPath = "/usr/bin/" + ServiceName
	ConfigDir    = "/etc/" + ServiceDir
	ConfigFile   = "config"

	KeysDir               = "keys/"
	KeysTransferPolicyDir = "keys-transfer-policy/"
	UserDir               = "users/"

	// certificates' path
	TrustedJWTSigningCertsDir = ConfigDir + "certs/trustedjwt/"
	TrustedCACertsDir         = ConfigDir + "certs/trustedca/"

	// defaults
	DefaultKeyManager     = "Kmip"
	DefaultEndpointUrl    = "http://localhost"
	DefaultConfigFilePath = ConfigDir + "config.yml"

	// default locations for tls certificate and key
	TLSCertsPath       = ConfigDir + "certs/tls/"
	DefaultTLSCertPath = TLSCertsPath + "tls.crt"
	DefaultTLSKeyPath  = TLSCertsPath + "tls.key"
	ValidityDays       = 365
	CommonName         = "KBS TLS Certificate"
	DefaultIssuer      = "Intel"
	DefaultTlsSan      = "127.0.0.1,localhost"

	// default location for JWT signing certificate and key
	JWTSigningCertsPath      = ConfigDir + "certs/signing-keys/"
	DefaultJWTSigningKeyPath = JWTSigningCertsPath + "jwt-signing.key"
	DefaultKeyLength         = 3072
	DefaultTokenExpiration   = time.Hour

	// service remove command
	ServiceRemoveCmd = "systemctl disable kbs"

	// jwt constants
	JWTCertsCacheTime = "1m"

	// log constants
	DefaultLogLevel = "info"

	// server constants
	DefaultHttpPort = 9443

	// kmipmanager constants
	KmipKeyManager     = "kmip"
	VaultKeyManager    = "vault"
	DefaultKmipPort    = 5696
	DefaultVaultPort   = 8200
	KmipCertsPath      = ConfigDir + "certs/kmip/"
	KmipClientKeyPath  = KmipCertsPath + "client_key.pem"
	KmipClientCertPath = KmipCertsPath + "client_certificate.pem"
	KmipRootCertPath   = KmipCertsPath + "root_certificate.pem"

	// algorithm constants
	CRYPTOALGAES = "AES"
	CRYPTOALGRSA = "RSA"
	CRYPTOALGEC  = "EC"

	// kmip constants
	KMIP14 = "1.4"
	KMIP20 = "2.0"

	TCBStatusUpToDate = "OK"

	// vault constants
	VAULT_KEY_ROOT_PATH = "keybroker/"

	MaxQueryParamsLength = 50
	UUIDReg              = "[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}"
	AtsCertChainMaxLen   = 10
)
