/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func GetCertsFromDir(path string) ([]x509.Certificate, error) {
	var certificates []x509.Certificate
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return certificates, fmt.Errorf("Error while reading certs from dir %s", path)
	}
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	for _, certFile := range files {
		certFilePath := path + certFile.Name()
		certs, err := GetSubjectCertsMapFromPemFile(certFilePath)
		if err != nil {
			log.WithError(err).Warn("Error while reading certs from dir - " + certFilePath)
		}

		for _, v := range certs {
			certificates = append(certificates, v)
		}
	}
	return certificates, nil
}

func GetSubjectCertsMapFromPemFile(path string) ([]x509.Certificate, error) {
	log.Debugf("Loading certificates from  %s", path)

	certsBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return GetX509CertsFromPem(certsBytes)
}

func GetX509CertsFromPem(certBytes []byte) ([]x509.Certificate, error) {
	var certificates []x509.Certificate
	block, rest := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("Unable to decode pem bytes")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithError(err).Warn("Failed to parse certificate")
	} else {
		certificates = append(certificates, *cert)
		log.Debugf("CommonName %s", cert.Subject.CommonName)
	}

	// Return if no more certificates present in file
	if rest == nil {
		return certificates, nil
	}

	for len(rest) > 1 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.WithError(err).Warn("Failed to parse certificate")
			continue
		}
		certificates = append(certificates, *cert)
		log.Debugf("CommonName %s", cert.Subject.CommonName)
	}
	return certificates, nil
}

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

func GetCertPool(certs []x509.Certificate) *x509.CertPool {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for i := range certs {
		rootCAs.AddCert(&certs[i])
	}
	return rootCAs
}

func GetCertAndChainFromPem(certPem []byte) (cert *x509.Certificate, chain *x509.CertPool, err error) {
	block, rest := pem.Decode(certPem)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode PEM certificate")
	}

	if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, nil, fmt.Errorf("failed to parse X509 certificate")
	}

	if chain = x509.NewCertPool(); chain.AppendCertsFromPEM(rest) {
		return
	}
	return cert, nil, nil
}

func GetCertHashInHex(cert *x509.Certificate, hashAlg crypto.Hash) (string, error) {
	hash, err := GetHashData(cert.Raw, hashAlg)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash), nil
}

// GetHash returns a byte array to the hash of the data.
// alg indicates the hashing algorithm. Currently, the only supported hashing algorithms
// are SHA1, SHA256, SHA384 and SHA512
func GetHashData(data []byte, alg crypto.Hash) ([]byte, error) {

	if data == nil {
		return nil, fmt.Errorf("data is nil")
	}

	switch alg {
	case crypto.SHA1:
		s := sha1.Sum(data)
		return s[:], nil
	case crypto.SHA256:
		s := sha256.Sum256(data)
		return s[:], nil
	case crypto.SHA384:
		s := sha512.Sum384(data)
		return s[:], nil
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:], nil
	}

	return nil, fmt.Errorf("Unsupported hashing function %d. Only SHA1, SHA256, SHA384 and SHA512 supported", alg)
}

// GetPublicKeyFromCert retrieve the public key from a certificate
// We only support ECDSA and RSA public key
func GetPublicKeyFromCert(cert *x509.Certificate) (crypto.PublicKey, error) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("public key algorithm of cert reported as RSA cert does not match RSA public key struct")
	case x509.ECDSA:
		if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("public key algorithm of cert reported as ECDSA cert does not match ECDSA public key struct")
	}
	return nil, fmt.Errorf("only RSA and ECDSA public keys are supported")
}

// GetRandomBytes retrieves a byte array of 'length'
func GetRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}
