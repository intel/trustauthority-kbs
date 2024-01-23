/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package model

import (
	"time"

	"github.com/google/uuid"
)

type KeyRequest struct {
	KeyInfo *KeyInfo `json:"key_information"`
	// Universal Unique IDentifier of the Key Transfer Policy
	// required: true
	// example: 4110594b-a753-4457-7d7f-3e52b62f2ed8
	TransferPolicyID uuid.UUID `json:"transfer_policy_id,omitempty"`
}

type KeyUpdateRequest struct {
	KeyId uuid.UUID `json:"-"`
	// Universal Unique IDentifier of the Key Transfer Policy
	// required: true
	// example: 4110594b-a753-4457-7d7f-3e52b6252ed6
	TransferPolicyID uuid.UUID `json:"transfer_policy_id"`
}

type KeyResponse struct {
	// Universal Unique IDentifier of the Key created
	// required: true
	// example: 4110594b-a753-4457-7d7f-3e52b6252ed6
	ID      uuid.UUID `json:"id"`
	KeyInfo *KeyInfo  `json:"key_info"`
	// Universal Unique IDentifier of the Key Transfer Policy
	// required: true
	// example: 4110594b-a753-4457-7d7f-3e52b62f2ed8
	TransferPolicyID uuid.UUID `json:"transfer_policy_id,omitempty"`
	TransferLink     string    `json:"transfer_link"`
	CreatedAt        time.Time `json:"created_at"`
}

type KeyInfo struct {
	// Denotes the Encryption Algorithm (AES, RSA or EC) used while creating the key
	// required: true
	// example: rsa
	Algorithm string `json:"algorithm"`
	// Denotes the key length in bits used while creating the key
	// required: true
	// example: 3072
	KeyLength int `json:"key_length,omitempty"`
	// Denotes the curve type used while creating the EC key
	// example: secp384r1
	CurveType string `json:"curve_type,omitempty"`
	// Denotes the private key(RSA/EC) or AES key in base64 string
	// example: YG2UtIG6OtaPjIIHQXJGxRmR0ozqiF3iQoVztc74ijo=
	KeyData string `json:"key_data,omitempty"`
	// KMIP Key ID, if the key is already created in KMIP Backend
	// example: 7110194b-a703-4657-9d7f-3e02b62f2ed8
	KmipKeyID string `json:"kmip_key_id,omitempty"`
}

type KeyFilterCriteria struct {
	// Denotes the Encryption Algorithm (AES, RSA or EC) used while creating the key
	// example: rsa
	Algorithm string
	// Denotes the key length in bits used while creating the key
	// example: 3072
	KeyLength int
	// Denotes the curve type used while creating the EC key
	// example: secp384r1
	CurveType string
	// Universal Unique IDentifier of the Key Transfer Policy
	// example: 4110594b-a753-4457-7d7f-3e52b62f2ed8
	TransferPolicyId uuid.UUID
}
