/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"strings"

	"intel/amber/kbs/v1/config"
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/kmipclient"
	"intel/amber/kbs/v1/model"

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
