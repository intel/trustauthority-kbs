/*
 *   Copyright (c) 2024 Oracle Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package ociclient

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"

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
	// Create request and dependent object(s).
	req := vault.CreateSecretRequest{
		CreateSecretDetails: vault.CreateSecretDetails{
			// Required
			CompartmentId: &OciCompartmentId,
			KeyId:         &OciKeyId,
			SecretName:    &OciSecretName,
			VaultId:       &OciVaultId,

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
		return "", errors.Wrap(err, "ociclient/ociclient:CreateKey() Failed to create OCI secret")
	}

	log.Infof("ociclient/ociclient:CreateKey() Created key '%s' (%s) on oci server", *resp.Secret.Id, OciSecretName)

	return *resp.Secret.Id, nil
}

func (oc *ociClient) DeleteKey(secretId string) error {
	return nil
}

func (oc *ociClient) GetKey(secretId string, secretVersionNumber int64) ([]byte, error) {
	// Create request and dependent object(s).
	req := secrets.GetSecretBundleRequest{
		SecretId: common.String(secretId),
	}

	// If the secret version was provided, include it. Otherwise it'll just
	// fallback to the current version.
	if secretVersionNumber > 0 {
		req.VersionNumber = common.Int64(secretVersionNumber)
	}

	// Send the request using the secrets client.
	resp, err := oc.sc.GetSecretBundle(context.Background(), req)
	if err != nil {
		return nil, errors.Wrap(err, "could not get secret bundle")
	}

	// Parse bundle contents.
	re := regexp.MustCompile(`\{ Content=([-A-Za-z0-9+/]*) \}`)
	strs := re.FindStringSubmatch(fmt.Sprintf("%s", resp.SecretBundle.SecretBundleContent))
	if strs == nil || len(strs) != 2 {
		return nil, errors.New("could not extract secret")
	}
	contentStr := strs[1]

	// Decode the contents.
	decodedStr, err := base64.StdEncoding.DecodeString(contentStr)
	if err != nil {
		return nil, err
	}

	return decodedStr, nil
}
