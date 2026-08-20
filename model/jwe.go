/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

type JWEFlattened struct {
	// Base64url-encoded protected header JSON.
	// required: true
	Protected string `json:"protected"`
	// Base64url-encoded wrapped content encryption key.
	// required: true
	EncryptedKey string `json:"encrypted_key"`
	// Optional additional authenticated data.
	AAD string `json:"aad,omitempty"`
	// Base64url-encoded IV/nonce for content encryption.
	// required: true
	IV string `json:"iv"`
	// Base64url-encoded encrypted payload.
	// required: true
	Ciphertext string `json:"ciphertext"`
	// Base64url-encoded authentication tag.
	// required: true
	Tag string `json:"tag"`
}
