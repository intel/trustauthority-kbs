/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constant

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

	// certificates' path
	TrustedJWTSigningCertsDir = ConfigDir + "certs/trustedjwt/"
	TrustedCACertsDir         = ConfigDir + "certs/trustedca/"

	// defaults
	DefaultKeyManager     = "Kmip"
	DefaultEndpointUrl    = "http://localhost"
	DefaultConfigFilePath = ConfigDir + "config.yml"

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
	DefaultKmipPort    = 5696
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
)
