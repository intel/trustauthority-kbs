/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
	"io"
)

// GetPrivateKeyFromPem retrieve the private key from a private pem block
func GetPrivateKeyFromPem(keyPem []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		log.Error("failed to parse private key PEM")
		return nil, errors.New("failed to decode PEM formatted private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.WithError(err).Error("failed to parse private key")
		return nil, errors.Wrap(err, "failed to parse private key")
	}
	return key, nil
}

// GetPublicKeyFromPem retrieve the public key from a public pem block
func GetPublicKeyFromPem(keyPem []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Error("failed to parse public key PEM")
		return nil, errors.New("failed to decode PEM formatted public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.WithError(err).Error("failed to parse public key")
		return nil, errors.Wrap(err, "failed to parse public key")
	}
	return key, nil
}

// GetDerivedKey is used to get an AES key of given length using crypto hkdf function
func GetDerivedKey(keySize int) ([]byte, error) {
	hash := sha256.New
	secret := make([]byte, keySize)
	_, err := rand.Read(secret)
	defer ZeroizeByteArray(secret)
	if err != nil {
		return nil, errors.Wrap(err, "Failed during rand initialization for secret value")
	}

	salt := make([]byte, hash().Size())
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("Failed during rand initialization for salt value")
	}

	// generate 256-bit derived key
	hkdFunc := hkdf.New(hash, secret, salt, nil)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(hkdFunc, key); err != nil {
		return nil, errors.New("Failed while reading hkdf buffer into key")
	}
	return key, nil
}
