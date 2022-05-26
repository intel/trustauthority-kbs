/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "github.com/google/uuid"

type AttestationTokenClaim struct {
	MrSeam       string          `json:"mrseam,omitempty"`
	MrEnclave    string          `json:"mrenclave,omitempty"`
	MrSigner     string          `json:"mrsigner,omitempty"`
	MrSignerSeam string          `json:"mrsignerseam,omitempty"`
	IsvProductId *uint16         `json:"isvprodid,omitempty"`
	MRTD         string          `json:"mrtd,omitempty"`
	RTMR0        string          `json:"rtmr0,omitempty"`
	RTMR1        string          `json:"rtmr1,omitempty"`
	RTMR2        string          `json:"rtmr2,omitempty"`
	RTMR3        string          `json:"rtmr3,omitempty"`
	SeamSvn      *uint8          `json:"seamsvn,omitempty"`
	IsvSvn       *uint16         `json:"isvsvn,omitempty"`
	TeeHeldData  string          `json:"tee_held_data,omitempty"`
	PolicyIds    []uuid.UUID     `json:"policy_ids"`
	TcbStatus    string          `json:"tcb_status"`
	Tee          AttestationType `json:"tee"`
	Version      string          `json:"ver"`
}
