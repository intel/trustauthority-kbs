/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package kmipclient

import (
	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/kmip20"
	"github.com/gemalto/kmip-go/ttlv"
	"github.com/pkg/errors"
	"intel/kbs/v1/constant"
)

// CreateSymmetricKey creates a symmetric key on kmip server
func (kc *kmipClient) CreateSymmetricKey(length int) (string, error) {

	var createRequestPayLoad interface{}
	if kc.KMIPVersion == constant.KMIP20 {
		createRequestPayLoad = CreateRequestPayload{
			ObjectType: kmip20.ObjectTypeSymmetricKey,
			Attributes: Attributes{
				CryptographicAlgorithm: kmip14.CryptographicAlgorithmAES,
				CryptographicLength:    int32(length),
				CryptographicUsageMask: kmip14.CryptographicUsageMaskEncrypt | kmip14.CryptographicUsageMaskDecrypt,
			},
		}
	} else {
		createRequestPayLoad = kmip.CreateRequestPayload{
			ObjectType: kmip14.ObjectTypeSymmetricKey,
			TemplateAttribute: kmip.TemplateAttribute{
				Attribute: []kmip.Attribute{
					{
						AttributeName:  "Cryptographic Algorithm",
						AttributeValue: kmip14.CryptographicAlgorithmAES,
					},
					{
						AttributeName:  "Cryptographic Length",
						AttributeValue: int32(length),
					},
					{
						AttributeName:  "Cryptographic Usage Mask",
						AttributeValue: kmip14.CryptographicUsageMaskEncrypt | kmip14.CryptographicUsageMaskDecrypt,
					},
				},
			},
		}
	}

	batchItem, decoder, err := kc.SendRequest(createRequestPayLoad, kmip14.OperationCreate)
	if err != nil {
		return "", errors.Wrap(err, "failed to perform create symmetric key operation")
	}

	var respPayload CreateResponsePayload
	err = decoder.DecodeValue(&respPayload, batchItem.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return "", errors.Wrap(err, "failed to decode create symmetric key response payload")
	}

	return respPayload.UniqueIdentifier, nil
}

// CreateAsymmetricKeyPair creates a asymmetric key on kmip server
func (kc *kmipClient) CreateAsymmetricKeyPair(algorithm, curveType string, length int) (string, error) {

	var createKeyPairRequestPayLoad interface{}
	if kc.KMIPVersion == constant.KMIP20 {
		createKeyPairRequestPayLoad = CreateKeyPairRequestPayload{
			CommonAttributes: CommonAttributes{
				CryptographicAlgorithm: kmip14.CryptographicAlgorithmRSA,
				CryptographicLength:    int32(length),
			},
			PrivateKeyAttributes: PrivateKeyAttributes{
				CryptographicUsageMask: kmip14.CryptographicUsageMaskDecrypt,
			},
			PublicKeyAttributes: PublicKeyAttributes{
				CryptographicUsageMask: kmip14.CryptographicUsageMaskEncrypt,
			},
		}
	} else {
		createKeyPairRequestPayLoad = kmip.CreateKeyPairRequestPayload{
			CommonTemplateAttribute: &kmip.TemplateAttribute{
				Attribute: []kmip.Attribute{
					{
						AttributeName:  "Cryptographic Algorithm",
						AttributeValue: kmip14.CryptographicAlgorithmRSA,
					},
					{
						AttributeName:  "Cryptographic Length",
						AttributeValue: int32(length),
					},
				},
			},
			PrivateKeyTemplateAttribute: &kmip.TemplateAttribute{
				Attribute: []kmip.Attribute{
					{
						AttributeName:  "Cryptographic Usage Mask",
						AttributeValue: kmip14.CryptographicUsageMaskDecrypt,
					},
				},
			},
			PublicKeyTemplateAttribute: &kmip.TemplateAttribute{
				Attribute: []kmip.Attribute{
					{
						AttributeName:  "Cryptographic Usage Mask",
						AttributeValue: kmip14.CryptographicUsageMaskEncrypt,
					},
				},
			},
		}
	}

	batchItem, decoder, err := kc.SendRequest(createKeyPairRequestPayLoad, kmip14.OperationCreateKeyPair)
	if err != nil {
		return "", errors.Wrap(err, "failed to perform create keypair operation")
	}

	var respPayload CreateKeyPairResponsePayload
	err = decoder.DecodeValue(&respPayload, batchItem.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return "", errors.Wrap(err, "failed to decode create keypair response payload")
	}

	return respPayload.PrivateKeyUniqueIdentifier, nil
}

// GetKey retrieves a key from kmip server
func (kc *kmipClient) GetKey(keyID, algorithm string) ([]byte, error) {

	getRequestPayLoad := GetRequestPayload{
		UniqueIdentifier: kmip20.UniqueIdentifierValue{
			Text: keyID,
		},
	}

	batchItem, decoder, err := kc.SendRequest(getRequestPayLoad, kmip14.OperationGet)
	if err != nil {
		return nil, errors.Wrap(err, "failed to perform get key operation")
	}

	var respPayload GetResponsePayload
	err = decoder.DecodeValue(&respPayload, batchItem.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode get key response payload")
	}

	var keyValue KeyValue

	switch algorithm {
	case constant.CRYPTOALGAES:
		err = decoder.DecodeValue(&keyValue, respPayload.SymmetricKey.KeyBlock.KeyValue.(ttlv.TTLV))
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode symmetric keyblock")
		}
	case constant.CRYPTOALGRSA:
		if respPayload.ObjectType == kmip14.ObjectTypePrivateKey {
			err = decoder.DecodeValue(&keyValue, respPayload.PrivateKey.KeyBlock.KeyValue.(ttlv.TTLV))
			if err != nil {
				return nil, errors.Wrap(err, "failed to decode private keyblock")
			}
		} else {
			return nil, errors.Errorf("unsupported object type %s", respPayload.ObjectType)
		}
	default:
		return nil, errors.Errorf("unsupported %s algorithm provided", algorithm)
	}

	return keyValue.KeyMaterial, nil
}

// DeleteKey deletes a key from kmip server
func (kc *kmipClient) DeleteKey(keyID string) error {

	deleteRequestPayLoad := DeleteRequest{
		UniqueIdentifier: kmip20.UniqueIdentifierValue{
			Text: keyID,
		},
	}

	_, _, err := kc.SendRequest(deleteRequestPayLoad, kmip14.OperationDestroy)
	if err != nil {
		return errors.Wrap(err, "failed to perform delete key operation")
	}

	return nil
}
