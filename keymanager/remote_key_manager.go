/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"fmt"
	"strings"

	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/repository"

	"github.com/google/uuid"
)

type RemoteManager struct {
	store       repository.KeyStore
	manager     KeyManager
	endpointURL string
}

func NewRemoteManager(ks repository.KeyStore, km KeyManager, url string) *RemoteManager {
	return &RemoteManager{
		store:       ks,
		manager:     km,
		endpointURL: url,
	}
}

func (rm *RemoteManager) CreateKey(request *model.KeyRequest) (*model.KeyResponse, error) {

	keyAttributes, err := rm.manager.CreateKey(request)
	if err != nil {
		return nil, err
	}

	keyAttributes.TransferLink = rm.getTransferLink(keyAttributes.ID)
	storedKey, err := rm.store.Create(keyAttributes)
	if err != nil {
		return nil, err
	}

	return storedKey.ToKeyResponse(), nil
}

func (rm *RemoteManager) RetrieveKey(keyId uuid.UUID) (*model.KeyResponse, error) {

	keyAttributes, err := rm.store.Retrieve(keyId)
	if err != nil {
		return nil, err
	}

	return keyAttributes.ToKeyResponse(), nil
}

func (rm *RemoteManager) DeleteKey(keyId uuid.UUID) error {

	keyAttributes, err := rm.store.Retrieve(keyId)
	if err != nil {
		return err
	}

	if err := rm.manager.DeleteKey(keyAttributes); err != nil {
		return err
	}

	return rm.store.Delete(keyId)
}

func (rm *RemoteManager) SearchKeys(criteria *model.KeyFilterCriteria) ([]*model.KeyResponse, error) {

	keyAttributesList, err := rm.store.Search(criteria)
	if err != nil {
		return nil, err
	}

	var keyResponses = []*model.KeyResponse{}
	for _, keyAttributes := range keyAttributesList {
		keyResponses = append(keyResponses, keyAttributes.ToKeyResponse())
	}

	return keyResponses, nil
}

func (rm *RemoteManager) RegisterKey(request *model.KeyRequest) (*model.KeyResponse, error) {

	keyAttributes, err := rm.manager.RegisterKey(request)
	if err != nil {
		return nil, err
	}

	keyAttributes.TransferLink = rm.getTransferLink(keyAttributes.ID)
	storedKey, err := rm.store.Create(keyAttributes)
	if err != nil {
		return nil, err
	}

	return storedKey.ToKeyResponse(), nil
}

func (rm *RemoteManager) TransferKey(keyId uuid.UUID) ([]byte, error) {

	keyAttributes, err := rm.store.Retrieve(keyId)
	if err != nil {
		return nil, err
	}

	return rm.manager.TransferKey(keyAttributes)
}

func (rm *RemoteManager) getTransferLink(keyId uuid.UUID) string {

	if strings.HasSuffix(rm.endpointURL, "/") {
		return fmt.Sprintf("%skeys/%s/transfer", rm.endpointURL, keyId.String())
	} else {
		return fmt.Sprintf("%s/keys/%s/transfer", rm.endpointURL, keyId.String())
	}
}
