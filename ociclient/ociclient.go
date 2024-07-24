/*
 *   Copyright (c) 2024 Oracle Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package ociclient

import (
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type OCIClient interface {
	InitializeClient() error
	CreateKey(string, string, string, string) (string, error)
	DeleteKey(string) error
	GetKey(string, int64) ([]byte, error)
}

type ociClient struct {
	sc *(secrets.SecretsClient)
	vc *(vault.VaultsClient)
}

func NewOCIClient() OCIClient {
	return &ociClient{}
}

func (oc *ociClient) InitializeClient() error {
	secretsClient, err := secrets.NewSecretsClientWithConfigurationProvider(common.DefaultConfigProvider())
	if err != nil {
		return errors.Wrap(err, "ociclient/ociclient:InitializeClient() Failed to initialize OCI secrets client")
	}

	vaultsClient, err := vault.NewVaultsClientWithConfigurationProvider(common.DefaultConfigProvider())
	if err != nil {
		return errors.Wrap(err, "ociclient/ociclient:InitializeClient() Failed to initialize OCI vaults client")
	}

	oc.sc = &secretsClient
	oc.vc = &vaultsClient

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
