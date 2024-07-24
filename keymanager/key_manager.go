/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"intel/kbs/v1/ociclient"
	"intel/kbs/v1/vaultclient"
	"strings"

	"intel/kbs/v1/config"
	"intel/kbs/v1/constant"
	"intel/kbs/v1/kmipclient"
	"intel/kbs/v1/model"

	"github.com/pkg/errors"
)

func NewKeyManager(cfg *config.Configuration) (KeyManager, error) {

	if strings.ToLower(cfg.KeyManager) == constant.KmipKeyManager {
		kmipClient := kmipclient.NewKmipClient()
		err := kmipClient.InitializeClient(cfg.Kmip.Version, cfg.Kmip.ServerIP, cfg.Kmip.ServerPort, cfg.Kmip.Hostname, cfg.Kmip.Username, cfg.Kmip.Password, cfg.Kmip.ClientKeyFilePath, cfg.Kmip.ClientCertificateFilePath, cfg.Kmip.RootCertificateFilePath)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to initialize KmipManager")
		}
		return NewKmipManager(kmipClient), nil
	} else if strings.ToLower(cfg.KeyManager) == constant.OCIKeyManager {
		ociClient := ociclient.NewOCIClient()
		err := ociClient.InitializeClient()
		if err != nil {
			return nil, errors.Wrap(err, "keymanager/key_manager:NewKeyManager() Failed to initialize OCI client")
		}
		return NewOCIManager(ociClient), nil
	} else if strings.ToLower(cfg.KeyManager) == constant.VaultKeyManager {
		vaultClient := vaultclient.NewVaultClient()
		err := vaultClient.InitializeClient(cfg.Vault.ServerIP, cfg.Vault.ServerPort, cfg.Vault.ClientToken)
		if err != nil {
			return nil, errors.Wrap(err, "keymanager/key_manager:NewKeyManager() Failed to initialize vault client")
		}
		return &VaultManager{vaultClient}, nil
	} else {
		return nil, errors.Errorf("No Key Manager supported for provider: %s", cfg.KeyManager)
	}
}

type KeyManager interface {
	CreateKey(*model.KeyRequest) (*model.KeyAttributes, error)
	DeleteKey(*model.KeyAttributes) error
	RegisterKey(*model.KeyRequest) (*model.KeyAttributes, error)
	TransferKey(*model.KeyAttributes) ([]byte, error)
}
