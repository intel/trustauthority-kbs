/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

// JWEFlattened represents a flattened JWE JSON serialization used for RCAR
// encrypted resource responses.
type JWEFlattened struct {
	Protected    string `json:"protected"`
	EncryptedKey string `json:"encrypted_key"`
	AAD          string `json:"aad,omitempty"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
	Tag          string `json:"tag"`
}
