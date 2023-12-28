/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	MaxCertChainLength = 10
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

// GetRandomBytes retrieves a byte array of 'length'
func GetRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}
