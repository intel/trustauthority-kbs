/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package crypt

import (
	"crypto/x509"
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
		return certificates, errors.Wrap(err, "Error while reading certs from dir "+path)
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
