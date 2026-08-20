/*
 *   Copyright (c) 2024-2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"encoding/json"

	"github.com/pkg/errors"
)

type AttesterType string

const (
	TDX   AttesterType = "TDX"
	SGX   AttesterType = "SGX"
	NVGPU AttesterType = "NVGPU"
)

func (at AttesterType) String() string {
	return string(at)
}

func (at AttesterType) Valid() bool {
	switch at {
	case TDX, SGX, NVGPU:
		return true
	}
	return false
}

type AttesterTypes []AttesterType

// Contains reports whether the slice contains the given attester type.
func (ats AttesterTypes) Contains(at AttesterType) bool {
	for _, a := range ats {
		if a == at {
			return true
		}
	}
	return false
}

// KeyWrappingAttesterType returns the first TDX or SGX type found in the slice.
// Only TDX and SGX can supply attester_held_data for SWK wrapping; NVGPU cannot.
// Returns an error if no TDX or SGX entry is present.
func (ats AttesterTypes) KeyWrappingAttesterType() (AttesterType, error) {
	for _, t := range ats {
		if t == TDX || t == SGX {
			return t, nil
		}
	}
	return "", errors.New("no key-wrapping attester type (TDX/SGX) found in policy")
}

// UnmarshalJSON accepts both a plain JSON string ("TDX") and a JSON array
// (["TDX","NVGPU"]), converting either form to AttesterTypes.
func (ats *AttesterTypes) UnmarshalJSON(data []byte) error {
	// Try array first.
	var arr []AttesterType
	if err := json.Unmarshal(data, &arr); err == nil {
		*ats = arr
		return nil
	}
	// Fall back to plain string.
	var s AttesterType
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.Wrap(err, "attestation_type must be a string or array of strings")
	}
	*ats = AttesterTypes{s}
	return nil
}

// MarshalJSON emits a plain JSON string when the slice has exactly one element
// (backward-compatible with legacy single-string stored policies) and a JSON
// array for composite policies (e.g. ["TDX","NVGPU"]).
func (ats AttesterTypes) MarshalJSON() ([]byte, error) {
	if len(ats) == 1 {
		return json.Marshal(string(ats[0]))
	}
	type plain []AttesterType
	return json.Marshal(plain(ats))
}
