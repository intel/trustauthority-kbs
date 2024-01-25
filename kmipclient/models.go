/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package kmipclient

import (
	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/kmip20"
)

// CreateRequestPayload used to construct create symmetric key request message
type CreateRequestPayload struct {
	ObjectType kmip20.ObjectType
	Attributes Attributes
}

// Attributes payload requires in create request
type Attributes struct {
	CryptographicAlgorithm kmip14.CryptographicAlgorithm
	CryptographicLength    int32
	CryptographicUsageMask kmip14.CryptographicUsageMask
}

// CreateResponsePayload to receive response message for create operation
type CreateResponsePayload struct {
	UniqueIdentifier string
}

// CreateKeyPairRequestPayload used to construct asymmetric key request message
type CreateKeyPairRequestPayload struct {
	CommonAttributes     CommonAttributes
	PrivateKeyAttributes PrivateKeyAttributes
	PublicKeyAttributes  PublicKeyAttributes
}

// CommonAttributes payload required in CreateKeyPair request.
type CommonAttributes struct {
	CryptographicAlgorithm kmip14.CryptographicAlgorithm
	CryptographicLength    int32
}

// PrivateKeyAttributes payload represents usage mask for private key
type PrivateKeyAttributes struct {
	CryptographicUsageMask kmip14.CryptographicUsageMask
}

// PublicKeyAttributes payload represents usage mask for public key
type PublicKeyAttributes struct {
	CryptographicUsageMask kmip14.CryptographicUsageMask
}

// CreateKeyPairResponsePayload to receive response message for CreateKeyPair operation
type CreateKeyPairResponsePayload struct {
	PrivateKeyUniqueIdentifier string
	PublicKeyUniqueIdentifier  string
}

// GetRequestPayload used to construct GET request operation
type GetRequestPayload struct {
	UniqueIdentifier kmip20.UniqueIdentifierValue
}

// DeleteRequest payload used to construct DELETE request operation
type DeleteRequest struct {
	UniqueIdentifier kmip20.UniqueIdentifierValue
}

// GetResponsePayload to receive response of GET operation
type GetResponsePayload struct {
	ObjectType       kmip14.ObjectType
	UniqueIdentifier string
	SymmetricKey     kmip.SymmetricKey
	PrivateKey       kmip.PrivateKey
}

// KeyValue payload to hold actual key value
type KeyValue struct {
	KeyMaterial []byte
}
