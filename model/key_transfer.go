/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "intel/amber/kbs/v1/clients/as"

type KeyTransferRequest struct {
	Quote       []byte          `json:"quote"`
	SignedNonce *as.SignedNonce `json:"signed_nonce"`
	UserData    []byte          `json:"user_data"`
	EventLog    []byte          `json:"event_log,omitempty"`
}

type KeyTransferResponse struct {
	WrappedKey []byte `json:"wrapped_key"`
	WrappedSWK []byte `json:"wrapped_swk"`
}
