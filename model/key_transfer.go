/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "intel/amber/kbs/v1/clients/as"

type KeyTransferRequest struct {
	AttestationToken string          `json:"attestation_token,omitempty"`
	Quote            []byte          `json:"quote,omitempty"`
	SignedNonce      *as.SignedNonce `json:"signed_nonce,omitempty"`
	UserData         []byte          `json:"user_data,omitempty"`
	EventLog         []byte          `json:"event_log,omitempty"`
}

type KeyTransferResponse struct {
	WrappedKey []byte `json:"wrapped_key"`
	WrappedSWK []byte `json:"wrapped_swk"`
}
