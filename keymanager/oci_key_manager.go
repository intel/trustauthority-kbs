/*
 *   Copyright (c) 2024 Oracle Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"intel/kbs/v1/model"
	"intel/kbs/v1/ociclient"
)

type OCIManager struct {
	client ociclient.OCIClient
}

func NewOCIManager(c ociclient.OCIClient) *OCIManager {
	return &OCIManager{c}
}

func (om *OCIManager) CreateKey(keyRequest *model.KeyRequest) (*model.KeyAttributes, error) {
	return nil, nil
}

func (om *OCIManager) DeleteKey(keyAttributes *model.KeyAttributes) error {
	return nil
}

func (om *OCIManager) RegisterKey(keyRequest *model.KeyRequest) (*model.KeyAttributes, error) {
	return nil, nil
}

func (om *OCIManager) TransferKey(keyAttributes *model.KeyAttributes) ([]byte, error) {
	return nil, nil
}
