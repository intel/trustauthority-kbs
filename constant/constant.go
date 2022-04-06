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
	LogDir       = "/var/log/" + ServiceDir
	ConfigDir    = "/etc/" + ServiceDir
	ConfigFile   = "config"

	KeysDir               = "keys/"
	KeysTransferPolicyDir = "keys-transfer-policy/"

	// certificates' path
	ApsJWTSigningCertsDir = ConfigDir + "certs/apsjwt/"
	TrustedCaCertsDir     = ConfigDir + "certs/trustedca/"

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
	DefaultKBSListenerPort = 9443

	// keymanager constants
	KmipKeyManager = "kmip"

	// algorithm constants
	CRYPTOALGAES = "AES"
	CRYPTOALGRSA = "RSA"
	CRYPTOALGEC  = "EC"

	// kmip constants
	KMIP14 = "1.4"
	KMIP20 = "2.0"

	TCBStatusUpToDate = "OK"
)
