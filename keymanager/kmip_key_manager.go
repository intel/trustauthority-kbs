/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package keymanager

import (
	"time"

	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/kmipclient"
	"intel/amber/kbs/v1/model"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type KmipManager struct {
	client kmipclient.KmipClient
}

func NewKmipManager(c kmipclient.KmipClient) *KmipManager {
	return &KmipManager{c}
}

func (km *KmipManager) CreateKey(request *model.KeyRequest) (*model.KeyAttributes, error) {

	keyAttributes := &model.KeyAttributes{
		Algorithm: request.KeyInfo.Algorithm,
	}

	switch request.KeyInfo.Algorithm {
	case constant.CRYPTOALGAES:
		kmipId, err := km.client.CreateSymmetricKey(request.KeyInfo.KeyLength)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create AES key")
		}
		keyAttributes.KeyLength = request.KeyInfo.KeyLength
		keyAttributes.KmipKeyID = kmipId
	case constant.CRYPTOALGRSA:
		kmipId, err := km.client.CreateAsymmetricKeyPair(constant.CRYPTOALGRSA, "", request.KeyInfo.KeyLength)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create RSA key pair")
		}
		keyAttributes.KeyLength = request.KeyInfo.KeyLength
		keyAttributes.KmipKeyID = kmipId
	default:
		return nil, errors.Errorf("%s algorithm is not supported", request.KeyInfo.Algorithm)
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	keyAttributes.ID = newUuid
	keyAttributes.CreatedAt = time.Now().UTC()
	keyAttributes.TransferPolicyId = request.TransferPolicyID

	return keyAttributes, nil
}

func (km *KmipManager) DeleteKey(attributes *model.KeyAttributes) error {

	if attributes.KmipKeyID == "" {
		return errors.New("key is not created with KMIP key manager")
	}

	return km.client.DeleteKey(attributes.KmipKeyID)
}

func (km *KmipManager) RegisterKey(request *model.KeyRequest) (*model.KeyAttributes, error) {

	if request.KeyInfo.KmipKeyID == "" {
		return nil, errors.New("kmip_key_id cannot be empty for register operation in kmip mode")
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	keyAttributes := &model.KeyAttributes{
		ID:               newUuid,
		Algorithm:        request.KeyInfo.Algorithm,
		KeyLength:        request.KeyInfo.KeyLength,
		KmipKeyID:        request.KeyInfo.KmipKeyID,
		TransferPolicyId: request.TransferPolicyID,
		CreatedAt:        time.Now().UTC(),
	}

	return keyAttributes, nil
}

func (km *KmipManager) TransferKey(attributes *model.KeyAttributes) ([]byte, error) {

	if attributes.KmipKeyID == "" {
		return nil, errors.New("key is not created with KMIP key manager")
	}

	if attributes.Algorithm == constant.CRYPTOALGAES || attributes.Algorithm == constant.CRYPTOALGRSA {
		return km.client.GetKey(attributes.KmipKeyID, attributes.Algorithm)
	} else {
		return nil, errors.Errorf("%s algorithm is not supported", attributes.Algorithm)
	}
}
