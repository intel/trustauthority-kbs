/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package keymanager

import (
	"fmt"
	"intel/kbs/v1/model"
	"intel/kbs/v1/repository"

	"github.com/google/uuid"
)

type RemoteManager struct {
	store   repository.KeyStore
	manager KeyManager
}

func NewRemoteManager(ks repository.KeyStore, km KeyManager) *RemoteManager {
	return &RemoteManager{
		store:   ks,
		manager: km,
	}
}

func (rm *RemoteManager) CreateKey(request *model.KeyRequest) (*model.KeyResponse, error) {

	keyAttributes, err := rm.manager.CreateKey(request)
	if err != nil {
		return nil, err
	}

	keyAttributes.TransferLink = getTransferLink(keyAttributes.ID)
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

func (rm *RemoteManager) UpdateKey(keyUpdateRequest *model.KeyUpdateRequest) (*model.KeyResponse, error) {

	keyAttributes, err := rm.store.Retrieve(keyUpdateRequest.KeyId)
	if err != nil {
		return nil, err
	}
	keyAttributes.TransferPolicyId = keyUpdateRequest.TransferPolicyID
	updatedKey, err := rm.store.Update(keyAttributes)
	if err != nil {
		return nil, err
	}

	return updatedKey.ToKeyResponse(), nil
}

func (rm *RemoteManager) RegisterKey(request *model.KeyRequest) (*model.KeyResponse, error) {

	keyAttributes, err := rm.manager.RegisterKey(request)
	if err != nil {
		return nil, err
	}

	keyAttributes.TransferLink = getTransferLink(keyAttributes.ID)
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

func getTransferLink(keyId uuid.UUID) string {
	return fmt.Sprintf("/kbs/v1/keys/%s/transfer", keyId.String())
}
