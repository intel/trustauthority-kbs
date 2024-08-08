/*
 *   Copyright (c) 2024 Oracle Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package ociclient

import (
	"context"
	"intel/kbs/v1/model"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type OCIClient interface {
	InitializeClient() error
	CreateKey(keyAttrib *model.KeyAttributes) error
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

func (oc *ociClient) CreateKey(keyAttributes *model.KeyAttributes) error {
	// Create request and dependent object(s).
	req := vault.CreateSecretRequest{
		CreateSecretDetails: vault.CreateSecretDetails{
			// Required
			CompartmentId: common.String(keyAttributes.OciCompartmentId),
			KeyId:         common.String(keyAttributes.OciKeyId),
			SecretName:    common.String(keyAttributes.OciSecretName),
			VaultId:       common.String(keyAttributes.OciVaultId),

			// TODO: For now just use random bytes, but it should be possible
			//       to select the key type.
			SecretGenerationContext: vault.BytesGenerationContext{
				GenerationTemplate: vault.BytesGenerationContextGenerationTemplate512,
			},

			// Optional
			EnableAutoGeneration: common.Bool(true),
		},
	}

	// Send the request using the vault client.
	resp, err := oc.vc.CreateSecret(context.Background(), req)
	if err != nil {
		return errors.Wrap(err, "ociclient/ociclient:CreateKey() Failed to create OCI secret")
	}

	// Retrieve value from the response.
	keyAttributes.OciSecretId = *resp.Secret.Id

	log.Infof("ociclient/ociclient:CreateKey() Created key '%s' (%s) on oci server", keyAttributes.OciSecretId, keyAttributes.OciSecretName)

	return nil
}

func (oc *ociClient) DeleteKey(secretId string) error {
	return nil
}

func (oc *ociClient) GetKey(secretId string, secretVersionNumber int64) ([]byte, error) {
	return nil, nil
}
