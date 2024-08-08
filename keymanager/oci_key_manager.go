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
	if keyRequest.OciInfo.CompartmentId == "" || keyRequest.OciInfo.KeyId == "" ||
		keyRequest.OciInfo.SecretName == "" || keyRequest.OciInfo.VaultId == "" {
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
		TransferPolicyId: keyRequest.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
		Oci: &model.OciAttributes{
			CompartmentId: keyRequest.OciInfo.CompartmentId,
			KeyId:         keyRequest.OciInfo.KeyId,
			SecretName:    keyRequest.OciInfo.SecretName,
			VaultId:       keyRequest.OciInfo.VaultId,
		},
	}

	log.Infof("OCI: Creating key: algorithm = %q; secret name = %q", keyAttributes.Algorithm, keyAttributes.Oci.SecretName)

	keyAttributes.Oci.SecretId, err = om.client.CreateKey(keyAttributes.Oci.CompartmentId, keyAttributes.Oci.KeyId, keyAttributes.Oci.SecretName, keyAttributes.Oci.VaultId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create key")
	}

	return keyAttributes, nil
}

func (om *OCIManager) DeleteKey(keyAttributes *model.KeyAttributes) error {
	err := om.client.DeleteKey(keyAttributes.Oci.SecretId)
	if err != nil {
		errors.Wrap(err, "failed to delete key")
		return err
	}

	log.Infof("OCI: Deleting key: algorithm = %q; secret id = %q", keyAttributes.Algorithm, keyAttributes.Oci.SecretId)

	return nil
}

func (om *OCIManager) RegisterKey(keyRequest *model.KeyRequest) (*model.KeyAttributes, error) {
	if keyRequest.OciInfo.SecretId == "" {
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
		TransferPolicyId: keyRequest.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
		Oci: &model.OciAttributes{
			SecretId: keyRequest.OciInfo.SecretId,
		},
	}

	log.Infof("OCI: Registering key: algorithm = %q; secret id = %q", keyAttributes.Algorithm, keyAttributes.Oci.SecretId)

	return keyAttributes, nil
}

func (om *OCIManager) TransferKey(keyAttributes *model.KeyAttributes) ([]byte, error) {
	if keyAttributes.Oci.SecretId == "" {
		return nil, errors.New("key is not created with OCI key manager")
	}

	secretVersionNumber := int64(0)

	log.Infof("OCI: Transferring key: secret id = %q; secret version = %d", keyAttributes.Oci.SecretId, secretVersionNumber)

	return om.client.GetKey(keyAttributes.Oci.SecretId, secretVersionNumber)
}
