/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

// Fuzz tests for service-layer claim validation and JWT parsing.
// Run with: go test ./service -fuzz=FuzzAttestationTokenClaims -fuzztime=60s

package service

import (
	"encoding/json"
	"intel/kbs/v1/model"
	"testing"

	jwtpkg "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// FuzzAttestationTokenClaims feeds arbitrary JSON into the attestation claim
// parser and then runs the claim validator.  Any panic is a security defect.
func FuzzAttestationTokenClaims(f *testing.F) {
	// Seed corpus: valid SGX claim
	sgxSeed := model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: "ad46749ed41ebaa2327252041ee746d3791a9f2431830fee0883f7993caf316a",
			SgxMrSigner:  "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e",
			SgxIsvProdId: 1,
			SgxIsvSvn:    1,
		},
		AttesterType:      model.SGX,
		AttesterTcbStatus: "UpToDate",
	}
	sgxSeedBytes, _ := json.Marshal(sgxSeed)

	// Seed corpus: valid TDX claim
	tdxSeed := model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			TdxMrSignerSeam: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			TdxMRTD:         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		},
		AttesterType:      model.TDX,
		AttesterTcbStatus: "UpToDate",
	}
	tdxSeedBytes, _ := json.Marshal(tdxSeed)

	f.Add(sgxSeedBytes)
	f.Add(tdxSeedBytes)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"attester_type":"SGX"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	// Corresponding policy seeds
	sgxPolicy := &model.KeyTransferPolicy{
		AttestationType: model.SGX,
		SGX: &model.SgxPolicy{
			Attributes: &model.SgxAttributes{
				MrEnclave: []string{"ad46749ed41ebaa2327252041ee746d3791a9f2431830fee0883f7993caf316a"},
				MrSigner:  []string{"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e"},
			},
		},
	}

	tdxPolicy := &model.KeyTransferPolicy{
		AttestationType: model.TDX,
		TDX: &model.TdxPolicy{
			Attributes: &model.TdxAttributes{},
		},
	}

	f.Fuzz(func(t *testing.T, claimsJSON []byte) {
		var claims model.AttestationTokenClaim
		if err := json.Unmarshal(claimsJSON, &claims); err != nil {
			return // invalid JSON — not a target scenario
		}
		// Exercise with both SGX and TDX policies; must not panic
		_ = validateAttestationTokenClaims(&claims, sgxPolicy)
		_ = validateAttestationTokenClaims(&claims, tdxPolicy)
	})
}

// FuzzKeyTransferPolicyJSON feeds arbitrary JSON into the KeyTransferPolicy
// deserializer to catch any panics in the unmarshal path.
func FuzzKeyTransferPolicyJSON(f *testing.F) {
	validPolicy := model.KeyTransferPolicy{
		ID:              uuid.New(),
		AttestationType: model.SGX,
		SGX: &model.SgxPolicy{
			PolicyIds: []uuid.UUID{uuid.New()},
		},
	}
	validBytes, _ := json.Marshal(validPolicy)

	f.Add(validBytes)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"attestation_type":"INVALID"}`))
	f.Add([]byte(`{"sgx":{"policy_ids":["not-a-uuid"]}}`))
	f.Add([]byte(`{"sgx":{"attributes":{"mrsigner":["` + string(make([]byte, 4096)) + `"]}}}`))
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, policyJSON []byte) {
		var policy model.KeyTransferPolicy
		if err := json.Unmarshal(policyJSON, &policy); err != nil {
			return
		}
		// A validly deserialized policy must always survive validation without panic
		var claims model.AttestationTokenClaim
		_ = validateAttestationTokenClaims(&claims, &policy)
	})
}

// FuzzJWTTokenParsing feeds arbitrary byte strings to the JWT parser to
// detect panics or undefined behaviour in the golang-jwt library integration.
// It does NOT verify signatures — the goal is crash safety.
func FuzzJWTTokenParsing(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	f.Add("")
	f.Add("not.a.jwt")
	f.Add("header.payload.signature")
	f.Add(".......")
	f.Add(string(make([]byte, 4096)))

	f.Fuzz(func(t *testing.T, tokenString string) {
		// Parse without validating the signature — any panic is a bug.
		_, _ = jwtpkg.Parse(tokenString, func(_ *jwtpkg.Token) (interface{}, error) {
			return []byte("fuzz-secret"), nil
		})
	})
}
