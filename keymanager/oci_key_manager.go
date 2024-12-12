/*
 *   Copyright (c) 2024 Oracle Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"intel/kbs/v1/model"
	"intel/kbs/v1/ociclient"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type OCIManager struct {
	client ociclient.OCIClient
}

func NewOCIManager(c ociclient.OCIClient) *OCIManager {
	return &OCIManager{c}
}

func (om *OCIManager) CreateKey(keyRequest *model.KeyRequest) (*model.KeyAttributes, error) {
	if keyRequest.KeyInfo.OciCompartmentId == "" || keyRequest.KeyInfo.OciKeyId == "" ||
		keyRequest.KeyInfo.OciSecretName == "" || keyRequest.KeyInfo.OciVaultId == "" {
		return nil, errors.New("Missing oci_compartment_id, oci_key_id, oci_secret_name, or oci_vault_id")
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	keyAttributes := &model.KeyAttributes{
		ID:               newUuid,
		Algorithm:        keyRequest.KeyInfo.Algorithm,
		KeyLength:        keyRequest.KeyInfo.KeyLength,
		OciCompartmentId: keyRequest.KeyInfo.OciCompartmentId,
		OciKeyId:         keyRequest.KeyInfo.OciKeyId,
		OciSecretName:    keyRequest.KeyInfo.OciSecretName,
		OciVaultId:       keyRequest.KeyInfo.OciVaultId,
		TransferPolicyId: keyRequest.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
	}

	log.Infof("OCI: Creating key: algorithm = %q; secret name = %q", keyAttributes.Algorithm, keyAttributes.OciSecretName)

	if err := om.client.CreateKey(keyAttributes); err != nil {
		return nil, errors.Wrap(err, "failed to create key")
	}

	return keyAttributes, nil
}

func (om *OCIManager) DeleteKey(keyAttributes *model.KeyAttributes) error {
	err := om.client.DeleteKey(keyAttributes.OciSecretId)
	if err != nil {
		log.Errorf("Error while deleting key: %s", err.Error())
		return err
	}

	log.Infof("OCI: Deleting key: algorithm = %q; secret id = %q", keyAttributes.Algorithm, keyAttributes.OciSecretId)

	return nil
}

func (om *OCIManager) RegisterKey(keyRequest *model.KeyRequest) (*model.KeyAttributes, error) {
	if keyRequest.KeyInfo.OciSecretId == "" {
		return nil, errors.New("oci_secret_id cannot be empty for register operation in OCI mode")
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	keyAttributes := &model.KeyAttributes{
		ID:               newUuid,
		Algorithm:        keyRequest.KeyInfo.Algorithm,
		KeyLength:        keyRequest.KeyInfo.KeyLength,
		OciSecretId:      keyRequest.KeyInfo.OciSecretId,
		TransferPolicyId: keyRequest.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
	}

	log.Infof("OCI: Registering key: algorithm = %q; secret id = %q", keyAttributes.Algorithm, keyAttributes.OciSecretId)

	return keyAttributes, nil
}

func (om *OCIManager) TransferKey(keyAttributes *model.KeyAttributes) ([]byte, error) {
	if keyAttributes.OciSecretId == "" {
		return nil, errors.New("key is not created with OCI key manager")
	}

	secretVersionNumber := int64(0)

	log.Infof("OCI: Transferring key: secret id = %q; secret version = %d", keyAttributes.OciSecretId, secretVersionNumber)

	return om.client.GetKey(keyAttributes.OciSecretId, secretVersionNumber)
}
