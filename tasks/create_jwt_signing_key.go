/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"intel/amber/kbs/v1/constant"
	"os"
	"path/filepath"
)

type CreateSigningKey struct {
	JWTSigningKeyPath string
}

func (csk *CreateSigningKey) CreateJWTSigningKey() error {
	key, err := rsa.GenerateKey(rand.Reader, constant.DefaultKeyLength)
	if err != nil {
		return errors.Wrap(err, "Could not generate rsa key pair, Error")
	}
	// store key and cert to file
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal private key")
	}

	keyOut, err := os.OpenFile(filepath.Clean(csk.JWTSigningKeyPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0) // open file with restricted permissions
	if err != nil {
		return errors.Wrap(err, "could not open private key file for writing")
	}
	// private key should not be world readable
	err = os.Chmod(csk.JWTSigningKeyPath, 0600)
	if err != nil {
		return errors.Wrapf(err, "Error while changing file permission for file : %s", csk.JWTSigningKeyPath)
	}
	defer func() {
		derr := keyOut.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing Key file")
		}
	}()

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDer}); err != nil {
		return errors.Wrap(err, "could not pem encode the private key")
	}

	return nil
}
