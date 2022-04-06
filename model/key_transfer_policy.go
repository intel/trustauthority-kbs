/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"time"

	"github.com/google/uuid"
)

type KeyTransferPolicy struct {
	ID              uuid.UUID         `json:"id,omitempty"`
	CreatedAt       time.Time         `json:"created_at,omitempty"`
	AttestationType []AttestationType `json:"attestation_type"`
	SGX             *SgxPolicy        `json:"sgx,omitempty"`
	TDX             *TdxPolicy        `json:"tdx,omitempty"`
}

type SgxPolicy struct {
	Attributes *SgxAttributes `json:"attributes,omitempty"`
	PolicyIds  []uuid.UUID    `json:"policy_ids,omitempty"`
}

type SgxAttributes struct {
	MrSigner           []string `json:"mrsigner,omitempty"`
	IsvProductId       []uint16 `json:"isvprodid,omitempty"`
	MrEnclave          []string `json:"mrenclave,omitempty"`
	IsvSvn             *uint16  `json:"isvsvn,omitempty"`
	ClientPermissions  []string `json:"client_permissions,omitempty"`
	EnforceTCBUptoDate *bool    `json:"enforce_tcb_upto_date,omitempty"`
}

type TdxPolicy struct {
	Attributes *TdxAttributes `json:"attributes,omitempty"`
	PolicyIds  []uuid.UUID    `json:"policy_ids,omitempty"`
}

type TdxAttributes struct {
	MrSignerSeam       []string `json:"mrsignerseam,omitempty"`
	MrSeam             []string `json:"mrseam,omitempty"`
	SeamSvn            *uint8   `json:"seamsvn,omitempty"`
	MRTD               []string `json:"mrtd,omitempty"`
	RTMR0              string   `json:"rtmr0,omitempty"`
	RTMR1              string   `json:"rtmr1,omitempty"`
	RTMR2              string   `json:"rtmr2,omitempty"`
	RTMR3              string   `json:"rtmr3,omitempty"`
	EnforceTCBUptoDate *bool    `json:"enforce_tcb_upto_date,omitempty"`
}

type KeyTransferPolicyFilterCriteria struct {
}
