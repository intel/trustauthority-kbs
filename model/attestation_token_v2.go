/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import "github.com/google/uuid"

// AttestationTokenV2Claim represents the claims in an ITA v2 attestation token
// (ver: "2.0.0").  In v2, TDX and NVGPU evidence are nested as sub-objects.
type AttestationTokenV2Claim struct {
	PolicyIdsMatched    []PolicyClaim `json:"policy_ids_matched,omitempty"`
	PolicyIdsUnmatched  []PolicyClaim `json:"policy_ids_unmatched,omitempty"`
	VerifierInstanceIds []uuid.UUID   `json:"verifier_instance_ids,omitempty"`
	Version             string        `json:"ver"`
	IntUse              string        `json:"intuse,omitempty"`
	EatProfile          string        `json:"eat_profile,omitempty"`

	// Nested sub-objects for composite attestation.
	// SGX and TDX are mutually exclusive; NVGPU can only accompany TDX.
	SGX   *SGXClaimV2   `json:"sgx,omitempty"`
	TDX   *TDXClaimV2   `json:"tdx,omitempty"`
	NVGPU *NVGPUClaimV2 `json:"nvgpu,omitempty"`
}

// TDXClaimV2 holds TDX-specific claims nested under the "tdx" key in a v2 token.
// attester_held_data, attester_tcb_status, attester_advisory_ids and dbgstat all
// live here (not at the top level) in V2 tokens.
type TDXClaimV2 struct {
	AttesterHeldData    string      `json:"attester_held_data,omitempty"`
	AttesterUserData    interface{} `json:"attester_user_data,omitempty"` // Claim for Azure TD only
	AttesterTcbStatus   string      `json:"attester_tcb_status,omitempty"`
	AttesterTcbDate     string      `json:"attester_tcb_date,omitempty"`
	AttesterAdvisoryIds []string    `json:"attester_advisory_ids,omitempty"`
	DbgStat             string      `json:"dbgstat,omitempty"`
	AttesterRuntime     interface{} `json:"attester_runtime_data,omitempty"`
	*TDXClaims
}

// SGXClaimV2 holds SGX-specific claims nested under the "sgx" key in a v2 token.
// attester_held_data, attester_tcb_status, attester_advisory_ids and dbgstat all
// live here (not at the top level) in V2 tokens. SGX cannot be combined with NVGPU.
type SGXClaimV2 struct {
	AttesterHeldData    string      `json:"attester_held_data,omitempty"`
	AttesterTcbStatus   string      `json:"attester_tcb_status,omitempty"`
	AttesterTcbDate     string      `json:"attester_tcb_date,omitempty"`
	AttesterAdvisoryIds []string    `json:"attester_advisory_ids,omitempty"`
	DbgStat             string      `json:"dbgstat,omitempty"`
	AttesterRuntime     interface{} `json:"attester_runtime_data,omitempty"`
	*SGXClaims
}

// NVGPUClaimV2 holds NVGPU-specific claims nested under the "nvgpu" key in a v2 token.
type NVGPUClaimV2 struct {
	OverallAttResult *bool                       `json:"x-nvidia-overall-att-result,omitempty"`
	Claims           map[string]NVGPUClaimDetail `json:"claim_details,omitempty"`
}

// ToAttestationTokenClaim converts an ITA v2 token into the flat v1-shaped
// AttestationTokenClaim used throughout the rest of the service.
// Rules:
//   - attester_held_data is taken from the SGX or TDX sub-object (key-wrapping RSA key).
//   - AttesterType is set from whichever sub-object is present (SGX or TDX).
//   - NVGPU overall result and per-GPU claims are lifted to the flat structure.
//   - SGX and NVGPU are mutually exclusive; a token with both is treated as SGX-only.
func (v2 *AttestationTokenV2Claim) ToAttestationTokenClaim() *AttestationTokenClaim {
	flat := &AttestationTokenClaim{
		Version:             v2.Version,
		PolicyIdsMatched:    v2.PolicyIdsMatched,
		PolicyIdsUnmatched:  v2.PolicyIdsUnmatched,
		VerifierInstanceIds: v2.VerifierInstanceIds,
		IntUse:              v2.IntUse,
		EatProfile:          v2.EatProfile,
		// AttesterTcbStatus, AttesterAdvisoryIds and DbgStat are populated
		// from the TEE sub-object below — they are not top-level in V2 tokens.
	}

	if v2.SGX != nil {
		flat.SGXClaims = v2.SGX.SGXClaims
		flat.AttesterHeldData = v2.SGX.AttesterHeldData
		flat.AttesterType = SGX
		// In V2 tokens these fields are nested inside the TEE sub-object.
		flat.AttesterTcbStatus = v2.SGX.AttesterTcbStatus
		flat.AttesterTcbDate = v2.SGX.AttesterTcbDate
		flat.AttesterAdvisoryIds = v2.SGX.AttesterAdvisoryIds
		flat.DbgStat = v2.SGX.DbgStat
		flat.AttesterRuntime = v2.SGX.AttesterRuntime
	} else if v2.TDX != nil {
		flat.TDXClaims = v2.TDX.TDXClaims
		flat.AttesterHeldData = v2.TDX.AttesterHeldData
		flat.AttesterUserData = v2.TDX.AttesterUserData
		flat.AttesterType = TDX
		// In V2 tokens these fields are nested inside the TEE sub-object.
		flat.AttesterTcbStatus = v2.TDX.AttesterTcbStatus
		flat.AttesterTcbDate = v2.TDX.AttesterTcbDate
		flat.AttesterAdvisoryIds = v2.TDX.AttesterAdvisoryIds
		flat.DbgStat = v2.TDX.DbgStat
		flat.AttesterRuntime = v2.TDX.AttesterRuntime

		// NVGPU can only accompany TDX, not SGX.
		if v2.NVGPU != nil {
			flat.NVGPUOverallAttResult = v2.NVGPU.OverallAttResult
			flat.NVGPUClaimDetails = v2.NVGPU.Claims
		}
	}

	return flat
}
