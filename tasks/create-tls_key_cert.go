/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"intel/kbs/v1/constant"
	"intel/kbs/v1/crypt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type TLSKeyAndCert struct {
	TLSCertPath string
	TLSKeyPath  string
	TlsSanList  string
}

func (tkc *TLSKeyAndCert) GenerateTLSKeyandCert() error {
	key, err := rsa.GenerateKey(rand.Reader, constant.DefaultKeyLength)
	defer crypt.ZeroizeRSAPrivateKey(key)
	if err != nil {
		return fmt.Errorf("could not generate rsa key pair, Error: %s", err)
	}
	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: constant.CommonName,
		},
		Issuer: pkix.Name{
			CommonName: constant.DefaultIssuer,
		},

		SignatureAlgorithm: x509.SHA384WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(0, 0, constant.ValidityDays),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return errors.Wrap(err, "Failed to create serial number")
	}
	template.SerialNumber = serialNumber
	// add the san list for tls certificate
	hosts := strings.Split(tkc.TlsSanList, ",")
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	selfSignCert, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	defer crypt.ZeroizeByteArray(selfSignCert)
	if err != nil {
		return errors.Wrap(err, "x509.CreateCertificate Failed")
	}
	// store key and cert to file
	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	defer crypt.ZeroizeByteArray(keyDer)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal private key")
	}

	tlsKeyPath := filepath.Clean(tkc.TLSKeyPath)
	keyOut, err := os.OpenFile(tkc.TLSKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0) // open file with restricted permissions
	if err != nil {
		return fmt.Errorf("could not open private key file for writing: %v", err)
	}
	// private key should not be world readable
	err = os.Chmod(tlsKeyPath, 0600)
	if err != nil {
		return errors.Wrapf(err, "Error while changing file permission for file : %s", tkc.TLSKeyPath)
	}
	defer func() {
		derr := keyOut.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing Key file")
		}
	}()

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDer}); err != nil {
		return fmt.Errorf("could not pem encode the private key: %v", err)
	}

	tlsCertPath := filepath.Clean(tkc.TLSCertPath)
	certOut, err := os.OpenFile(tlsCertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("could not open file for writing: %v", err)
	}
	defer func() {
		derr := certOut.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing Cert file")
		}
	}()
	err = os.Chmod(tlsCertPath, 0600)
	if err != nil {
		return fmt.Errorf("could not change file permissions: %s", tlsCertPath)
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: selfSignCert}); err != nil {
		return fmt.Errorf("could not pem encode cert: %v", err)
	}

	return nil
}
