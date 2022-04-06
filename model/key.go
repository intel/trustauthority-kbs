/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"time"

	"github.com/google/uuid"
)

type KeyRequest struct {
	KeyInfo          *KeyInfo  `json:"key_information"`
	TransferPolicyID uuid.UUID `json:"transfer_policy_id,omitempty"`
}

type KeyResponse struct {
	ID               uuid.UUID `json:"id"`
	KeyInfo          *KeyInfo  `json:"key_info"`
	TransferPolicyID uuid.UUID `json:"transfer_policy_id,omitempty"`
	TransferLink     string    `json:"transfer_link"`
	CreatedAt        time.Time `json:"created_at"`
}

type KeyInfo struct {
	Algorithm string `json:"algorithm"`
	KeyLength int    `json:"key_length,omitempty"`
	CurveType string `json:"curve_type,omitempty"`
	KeyData   string `json:"key_data,omitempty"`
	KmipKeyID string `json:"kmip_key_id,omitempty"`
}

type KeyFilterCriteria struct {
	Algorithm        string
	KeyLength        int
	CurveType        string
	TransferPolicyId uuid.UUID
}
