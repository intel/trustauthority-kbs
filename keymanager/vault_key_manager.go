/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"intel/amber/kbs/v1/crypt"
	"time"

	"github.com/google/uuid"

	"github.com/pkg/errors"
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/vaultclient"
)

type VaultManager struct {
	client vaultclient.VaultClient
}

func (vm *VaultManager) CreateKey(request *model.KeyRequest) (*model.KeyAttributes, error) {
	keyAttributes := &model.KeyAttributes{
		Algorithm:        request.KeyInfo.Algorithm,
		TransferPolicyId: request.TransferPolicyID,
	}

	var err error
	if request.KeyInfo.Algorithm == constant.CRYPTOALGAES {
		keyBytes, err := generateAESKey(request.KeyInfo.KeyLength)
		if err != nil {
			return nil, errors.Wrap(err, "Could not generate AES key")
		}

		keyAttributes.KeyLength = request.KeyInfo.KeyLength
		keyAttributes.KeyData = base64.StdEncoding.EncodeToString(keyBytes)
	} else {

		var public crypto.PublicKey
		var private crypto.PrivateKey
		if request.KeyInfo.Algorithm == constant.CRYPTOALGRSA {
			private, public, err = generateRSAKeyPair(request.KeyInfo.KeyLength)
			if err != nil {
				return nil, errors.Wrap(err, "Could not generate RSA keypair")
			}
			keyAttributes.KeyLength = request.KeyInfo.KeyLength
		} else {
			private, public, err = generateECKeyPair(request.KeyInfo.CurveType)
			if err != nil {
				return nil, errors.Wrap(err, "Could not generate EC keypair")
			}
			keyAttributes.CurveType = request.KeyInfo.CurveType
		}

		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal private key")
		}

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal public key")
		}

		keyAttributes.PrivateKey = base64.StdEncoding.EncodeToString(privateKeyBytes)
		keyAttributes.PublicKey = base64.StdEncoding.EncodeToString(publicKeyBytes)
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	keyAttributes.ID = newUuid
	keyAttributes.CreatedAt = time.Now().UTC()
	err = vm.client.CreateKey(keyAttributes)
	if err != nil {
		return nil, err
	}
	// remove the keyData, Private and Public key from attributes so that it's not saved on disk
	keyAttributes.KeyData = ""
	keyAttributes.PrivateKey = ""
	keyAttributes.PublicKey = ""
	return keyAttributes, nil
}

func (vm *VaultManager) DeleteKey(attributes *model.KeyAttributes) error {
	err := vm.client.DeleteKey(attributes.ID.String())
	if err != nil {
		log.Errorf("Error while deleting key: %s", err.Error())
		return err
	}
	return nil
}

func (vm *VaultManager) RegisterKey(request *model.KeyRequest) (*model.KeyAttributes, error) {
	if request.KeyInfo.KeyData == "" {
		return nil, errors.New("key_string cannot be empty for register operation")
	}

	var key, publicKey, privateKey string
	if request.KeyInfo.Algorithm == constant.CRYPTOALGAES {
		key = request.KeyInfo.KeyData
	} else {

		var public crypto.PublicKey
		var private crypto.PrivateKey
		private, err := crypt.GetPrivateKeyFromPem([]byte(request.KeyInfo.KeyData))
		if err != nil {
			return nil, errors.Wrap(err, "Failed to decode private key")
		}

		if request.KeyInfo.Algorithm == constant.CRYPTOALGRSA {
			rsaKey, ok := private.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.Wrap(err, "Private key in request is not RSA key")
			}

			public = &rsaKey.PublicKey
		} else {
			ecKey, ok := private.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.Wrap(err, "Private key in request is not EC key")
			}

			public = &ecKey.PublicKey
		}

		privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal private key")
		}
		privateKey = base64.StdEncoding.EncodeToString(privateKeyBytes)

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal public key")
		}
		publicKey = base64.StdEncoding.EncodeToString(publicKeyBytes)
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	keyAttributes := &model.KeyAttributes{
		ID:               newUuid,
		Algorithm:        request.KeyInfo.Algorithm,
		KeyLength:        request.KeyInfo.KeyLength,
		KeyData:          key,
		PublicKey:        publicKey,
		PrivateKey:       privateKey,
		TransferPolicyId: request.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
	}
	err = vm.client.CreateKey(keyAttributes)
	if err != nil {
		return nil, err
	}
	// remove the keyData, Private and Public key from attributes so that it's not saved on disk
	keyAttributes.KeyData = ""
	keyAttributes.PrivateKey = ""
	keyAttributes.PublicKey = ""
	return keyAttributes, nil
}

func (vm *VaultManager) TransferKey(attributes *model.KeyAttributes) ([]byte, error) {
	id := attributes.ID
	var key string

	keyInfo, err := vm.client.GetKey(id.String())
	if err != nil {
		return nil, err
	}
	var keyAttributes model.KeyAttributes
	err = json.Unmarshal(keyInfo, &keyAttributes)
	if err != nil {
		return nil, err
	}

	if attributes.Algorithm == constant.CRYPTOALGAES {
		key = keyAttributes.KeyData
	} else if attributes.Algorithm == constant.CRYPTOALGRSA {
		key = keyAttributes.PrivateKey
	} else {
		key = attributes.PrivateKey
	}

	return base64.StdEncoding.DecodeString(key)
}

func generateAESKey(length int) ([]byte, error) {
	return crypt.GetRandomBytes(length / 8)
}

func generateRSAKeyPair(length int) (crypto.PrivateKey, crypto.PublicKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return nil, nil, err
	}

	public := &private.PublicKey
	if bits := private.N.BitLen(); bits != length {
		return nil, nil, errors.Errorf("key too short (%d vs %d)", bits, length)
	}

	return private, public, nil
}

func generateECKeyPair(curveType string) (crypto.PrivateKey, crypto.PublicKey, error) {
	var curve elliptic.Curve
	switch curveType {
	case "prime256v1", "secp256r1":
		curve = elliptic.P256()
	case "secp384r1":
		curve = elliptic.P384()
	case "secp521r1":
		curve = elliptic.P521()
	default:
		return nil, nil, errors.New("unsupported curve type")
	}

	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	public := &private.PublicKey
	if !curve.IsOnCurve(public.X, public.Y) {
		return nil, nil, errors.New("public key invalid")
	}

	return private, public, nil
}
