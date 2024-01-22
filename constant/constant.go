/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package constant

// general KBS constants
const (
	ServiceName         = "kbs"
	ExplicitServiceName = "Key Broker Service"
	ServiceDir          = "kbs/"
	ApiVersion          = "v1"

	HomeDir    = "/opt/" + ServiceDir
	ConfigDir  = "/etc/" + ServiceDir
	ConfigFile = "config"

	KeysDir               = "keys/"
	KeysTransferPolicyDir = "keys-transfer-policy/"
	UserDir               = "users/"

	// defaults
	DefaultKeyManager = "Vault"

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
	DefaultTokenExpiration   = 5

	// log constants
	DefaultLogLevel = "info"

	// server constants
	DefaultHttpPort = 9443

	// kmipmanager constants
	KmipKeyManager   = "kmip"
	VaultKeyManager  = "vault"
	DefaultVaultPort = 8200

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

	HTTPHeaderKeyContentType           = "Content-Type"
	HTTPHeaderValueApplicationJwt      = "application/jwt"
	HTTPHeaderValueApplicationJson     = "application/json"
	HTTPHeaderValueApplicationXPEMFile = "application/x-pem-file"
	HTTPHeaderKeyAccept                = "Accept"
	HTTPHeaderKeyAttestationType       = "Attestation-Type"

	UserCredsMaxLen = 256
	PasswordMinLen  = 8
	// this limit is enforced by the crypt/bcrypt library
	PasswordMaxLen               = 72
	MaxTokenValidityInMinutes    = 30
	MinTokenValidityInMinutes    = 1
	DefaultHttpReadHeaderTimeOut = 10

	// defender constants
	DefaultAuthDefendMaxAttempts  = 5
	DefaultAuthDefendIntervalMins = 5
	DefaultAuthDefendLockoutMins  = 15
)
