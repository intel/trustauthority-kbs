/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"time"

	"github.com/google/uuid"
)

type KeyAttributes struct {
	ID               uuid.UUID `json:"id"`
	Algorithm        string    `json:"algorithm"`
	KeyLength        int       `json:"key_length,omitempty"`
	KeyData          string    `json:"key_data,omitempty"`
	CurveType        string    `json:"curve_type,omitempty"`
	PublicKey        string    `json:"public_key,omitempty"`
	PrivateKey       string    `json:"private_key,omitempty"`
	KmipKeyID        string    `json:"kmip_key_id,omitempty"`
	TransferPolicyId uuid.UUID `json:"transfer_policy_id,omitempty"`
	TransferLink     string    `json:"transfer_link,omitempty"`
	CreatedAt        time.Time `json:"created_at,omitempty"`

	Oci *OciAttributes `json:"oci_attributes,omitempty"`
}

type OciAttributes struct {
	CompartmentId string `json:"compartment_id,omitempty"`
	KeyId         string `json:"key_id,omitempty"`
	SecretName    string `json:"secret_name,omitempty"`
	SecretId      string `json:"secret_id,omitempty"`
	VaultId       string `json:"vault_id,omitempty"`
}

func (ka *KeyAttributes) ToKeyResponse() *KeyResponse {

	keyInfo := KeyInfo{
		Algorithm: ka.Algorithm,
		KeyLength: ka.KeyLength,
		CurveType: ka.CurveType,
		KmipKeyID: ka.KmipKeyID,
	}

	keyResponse := KeyResponse{
		ID:               ka.ID,
		KeyInfo:          &keyInfo,
		TransferPolicyID: ka.TransferPolicyId,
		TransferLink:     ka.TransferLink,
		CreatedAt:        ka.CreatedAt,
	}

	return &keyResponse
}
