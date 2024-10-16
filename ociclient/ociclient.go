/*
 *   Copyright (c) 2024 Oracle Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package ociclient

import (
	log "github.com/sirupsen/logrus"
)

type OCIClient interface {
	InitializeClient() error
	CreateKey(string, string, string, string) (string, error)
	DeleteKey(string) error
	GetKey(string, int64) ([]byte, error)
}

type ociClient struct {
}

func NewOCIClient() OCIClient {
	return &ociClient{}
}

func (oc *ociClient) InitializeClient() error {
	log.Info("ociclient/ociclient:InitializeClient() OCI client initialized")

	return nil
}

func (oc *ociClient) CreateKey(OciCompartmentId, OciKeyId, OciSecretName, OciVaultId string) (string, error) {
	return "", nil
}

func (oc *ociClient) DeleteKey(secretId string) error {
	return nil
}

func (oc *ociClient) GetKey(secretId string, secretVersionNumber int64) ([]byte, error) {
	return nil, nil
}
