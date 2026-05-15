/*
 *   Copyright (c) 2024 Oracle Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"intel/kbs/v1/model"
	"intel/kbs/v1/ociclient"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type OCIManager struct {
	client ociclient.OCIClient
}

func checkOCID(ocid string) bool {
	re := regexp.MustCompile(`^ocid1\.[A-Za-z0-9]+\.[A-Za-z0-9]+\.[A-Za-z0-9-]*\.[A-Za-z0-9.]+$`)

	return re.MatchString(ocid)
}

func checkSecretName(name string) bool {
	re := regexp.MustCompile(`[A-Za-z0-9]+`)

	return re.MatchString(name)
}

func NewOCIManager(c ociclient.OCIClient) *OCIManager {
	return &OCIManager{c}
}

func (om *OCIManager) CreateKey(keyRequest *model.KeyRequest) (*model.KeyAttributes, error) {
	if keyRequest.OciInfo.CompartmentId == "" || keyRequest.OciInfo.KeyId == "" ||
		keyRequest.OciInfo.SecretName == "" || keyRequest.OciInfo.VaultId == "" {
		return nil, errors.New("Missing oci_compartment_id, oci_key_id, oci_secret_name, or oci_vault_id")
	}

	if !checkOCID(keyRequest.OciInfo.CompartmentId) {
		return nil, errors.New("Invalid oci_compartment_id")
	}
	if !checkOCID(keyRequest.OciInfo.KeyId) {
		return nil, errors.New("Invalid oci_key_id")
	}
	if !checkSecretName(keyRequest.OciInfo.SecretName) {
		return nil, errors.New("Invalid oci_secret_name")
	}
	if !checkOCID(keyRequest.OciInfo.VaultId) {
		return nil, errors.New("Invalid oci_vault_id")
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
	log.Infof("OCI: Deleting key: algorithm = %q; secret id = %q", keyAttributes.Algorithm, keyAttributes.Oci.SecretId)

	err := om.client.DeleteKey(keyAttributes.Oci.SecretId)
	if err != nil {
		return errors.Wrap(err, "failed to delete key")
	}

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
