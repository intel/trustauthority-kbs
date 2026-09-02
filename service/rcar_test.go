/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"intel/kbs/v1/mocks"
	"intel/kbs/v1/model"

	itaConnector "github.com/intel/trustauthority-client/go-connector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestVerifyRCARAttestationSGXPrimaryQuoteString(t *testing.T) {
	ctx := WithRCARTEEHint(context.Background(), model.TeeSGX)
	mockITA := mocks.NewMockClient()

	runtimeData := model.RuntimeData{
		Nonce: "nonce-1",
		TEEPubKey: model.JWK{
			Kty: "RSA",
			N:   "abc",
			E:   "AQAB",
		},
	}
	expectedRuntimeJSON := `{"nonce":"nonce-1","tee-pubkey":{"kty":"RSA","n":"abc","e":"AQAB"},"additional-evidence":""}`

	quote := []byte("test-quote")
	quoteB64 := base64.StdEncoding.EncodeToString(quote)

	mockITA.On("AttestEvidence", mock.Anything, "", "nonce-1").
		Run(func(args mock.Arguments) {
			reqBody := args.Get(0).(*AttestRequest)
			require.NotNil(t, reqBody.SGX)
			assert.Equal(t, quote, reqBody.SGX.Quote)
			assert.JSONEq(t, expectedRuntimeJSON, string(reqBody.SGX.RuntimeData))
			assert.Nil(t, reqBody.TDX)
		}).
		Return(itaConnector.AttestResponse{Token: "ita-token"}, nil)

	svc := service{itaClient: mockITA}
	req := &model.RCARAttestationRequest{
		RuntimeData: runtimeData,
		TEEEvidence: model.CompositeEvidence{PrimaryEvidence: json.RawMessage("\"" + quoteB64 + "\"")},
	}

	token, err := svc.VerifyRCARAttestation(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "ita-token", token)
	mockITA.AssertExpectations(t)
}

func TestVerifyRCARAttestationTDXWithAdditionalNVGPU(t *testing.T) {
	ctx := WithRCARTEEHint(context.Background(), model.TeeTDX)
	mockITA := mocks.NewMockClient()

	primary := map[string]interface{}{
		"quote":       []byte("tdx-quote"),
		"cc_eventlog": []byte("eventlog"),
	}
	primaryRaw, err := json.Marshal(primary)
	require.NoError(t, err)

	additionalMap := map[string]interface{}{
		"nvidia": map[string]interface{}{
			"gpu_nonce":     "abcd",
			"arch":          "HOPPER",
			"evidence_list": []map[string]string{{"evidence": "ev", "certificate": "cert"}},
		},
	}
	additionalRaw, err := json.Marshal(additionalMap)
	require.NoError(t, err)

	runtimeData := model.RuntimeData{
		Nonce:     "nonce-2",
		TEEPubKey: model.JWK{Kty: "RSA", N: "abc", E: "AQAB"},
	}
	mockITA.On("AttestEvidence", mock.Anything, "", "nonce-2").
		Run(func(args mock.Arguments) {
			reqBody := args.Get(0).(*AttestRequest)
			require.NotNil(t, reqBody.TDX)
			assert.Equal(t, []byte("tdx-quote"), reqBody.TDX.Quote)
			assert.Equal(t, []byte("eventlog"), reqBody.TDX.EventLog)
			require.NotNil(t, reqBody.NVGPU)
			assert.Contains(t, reqBody.NVGPU.Arch, "HOPPER")
		}).
		Return(itaConnector.AttestResponse{Token: "ita-token-tdx"}, nil)

	svc := service{itaClient: mockITA}
	req := &model.RCARAttestationRequest{
		RuntimeData: runtimeData,
		TEEEvidence: model.CompositeEvidence{
			PrimaryEvidence:    primaryRaw,
			AdditionalEvidence: string(additionalRaw),
		},
	}

	token, err := svc.VerifyRCARAttestation(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "ita-token-tdx", token)
	mockITA.AssertExpectations(t)
}

func TestVerifyRCARAttestationTransformsTrusteeNvidiaEvidence(t *testing.T) {
	ctx := WithRCARTEEHint(context.Background(), model.TeeTDX)
	mockITA := mocks.NewMockClient()

	primary := map[string]interface{}{
		"quote":     []byte("tdx-quote"),
		"event_log": []byte("eventlog"),
	}
	primaryRaw, err := json.Marshal(primary)
	require.NoError(t, err)

	additionalMap := map[string]interface{}{
		"nvidia": map[string]interface{}{
			"device_evidence_list": []map[string]string{
				{"evidence": "ev1", "certificate": "cert1", "arch": "LS10"},
				{"evidence": "ev2", "certificate": "cert2", "arch": "blackwell"},
			},
		},
	}
	additionalRaw, err := json.Marshal(additionalMap)
	require.NoError(t, err)

	runtimeData := model.RuntimeData{
		Nonce:     "nonce-nv",
		TEEPubKey: model.JWK{Kty: "RSA", N: "abc", E: "AQAB"},
	}
	expectedRuntime, err := json.Marshal(runtimeData)
	require.NoError(t, err)
	h := sha512.Sum512(expectedRuntime)
	expectedNonce := hex.EncodeToString(h[:32])

	mockITA.On("AttestEvidence", mock.Anything, "", "nonce-nv").
		Run(func(args mock.Arguments) {
			reqBody := args.Get(0).(*AttestRequest)
			require.NotNil(t, reqBody.TDX)
			require.NotNil(t, reqBody.NVGPU)

			assert.Equal(t, "BLACKWELL", reqBody.NVGPU.Arch)
			assert.Equal(t, expectedNonce, reqBody.NVGPU.GPUNonce)

			list := reqBody.NVGPU.EvidenceList
			require.Len(t, list, 1)
			item := list[0]
			assert.Equal(t, "ev2", item.Evidence)
			assert.Equal(t, "cert2", item.Certificate)
		}).
		Return(itaConnector.AttestResponse{Token: "ita-token-nv"}, nil)

	svc := service{itaClient: mockITA}
	req := &model.RCARAttestationRequest{
		RuntimeData: runtimeData,
		TEEEvidence: model.CompositeEvidence{
			PrimaryEvidence:    primaryRaw,
			AdditionalEvidence: string(additionalRaw),
		},
	}

	token, err := svc.VerifyRCARAttestation(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "ita-token-nv", token)
	mockITA.AssertExpectations(t)
}

func TestVerifyRCARAttestationNilRequest(t *testing.T) {
	svc := service{itaClient: mocks.NewMockClient()}
	token, err := svc.VerifyRCARAttestation(context.Background(), nil)
	require.Error(t, err)
	assert.Equal(t, "", token)
	h, ok := err.(*HandledError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, h.Code)
}

func TestVerifyRCARAttestationITAFailure(t *testing.T) {
	ctx := WithRCARTEEHint(context.Background(), model.TeeSGX)
	mockITA := mocks.NewMockClient()

	mockITA.On("AttestEvidence", mock.Anything, "", "nonce-3").
		Return(itaConnector.AttestResponse{}, assert.AnError)

	svc := service{itaClient: mockITA}
	req := &model.RCARAttestationRequest{
		RuntimeData: model.RuntimeData{
			Nonce:     "nonce-3",
			TEEPubKey: model.JWK{Kty: "RSA", N: "abc", E: "AQAB"},
		},
		TEEEvidence: model.CompositeEvidence{PrimaryEvidence: json.RawMessage("\"" + base64.StdEncoding.EncodeToString([]byte("q")) + "\"")},
	}

	token, err := svc.VerifyRCARAttestation(ctx, req)
	require.Error(t, err)
	assert.Equal(t, "", token)
	h, ok := err.(*HandledError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadGateway, h.Code)
}

func TestRCARHintContextAndRuntimeDataLookup(t *testing.T) {
	ctx := context.Background()
	_, ok := rcarTEEHintFromContext(ctx)
	assert.False(t, ok)

	ctx = WithRCARTEEHint(ctx, model.TeeSGX)
	tee, ok := rcarTEEHintFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, model.TeeSGX, tee)

	ctx = context.Background()
	ctx = WithRCARTEEHint(ctx, "")
	_, ok = rcarTEEHintFromContext(ctx)
	assert.False(t, ok)

	claims := map[string]interface{}{
		"attester_runtime_data": "eyJ0ZWUtcHVia2V5Ijp7Imt0eSI6IlJTQSIsIm4iOiJtb2QiLCJlIjoiQVFBQiJ9LCJub25jZSI6Im4ifQ==",
	}
	assert.NotNil(t, runtimeDataFromClaims(claims))

	nestedClaims := map[string]interface{}{"tdx": map[string]interface{}{"attester_runtime_data": "data"}}
	assert.Equal(t, "data", runtimeDataFromClaims(nestedClaims))
	assert.Nil(t, runtimeDataFromClaims(map[string]interface{}{"other": "value"}))
}

func TestBuildAttestRequest_ValidSGXAndTDXBranches(t *testing.T) {
	quote := json.RawMessage("\"" + base64.StdEncoding.EncodeToString([]byte("sgx-quote")) + "\"")
	request := &model.RCARAttestationRequest{
		RuntimeData: model.RuntimeData{
			Nonce:     "nonce-sgx",
			TEEPubKey: model.JWK{Kty: "RSA", N: "mod", E: "AQAB"},
		},
		TEEEvidence: model.CompositeEvidence{PrimaryEvidence: quote},
	}

	reqBody, nonce, err := buildAttestRequest(request, model.TeeSGX)
	require.NoError(t, err)
	assert.Equal(t, "nonce-sgx", nonce)
	require.NotNil(t, reqBody)
	require.NotNil(t, reqBody.SGX)
	assert.Equal(t, []byte("sgx-quote"), reqBody.SGX.Quote)
	assert.Nil(t, reqBody.TDX)

	primary := map[string]interface{}{"quote": []byte("tdx-quote"), "event_log": []byte("eventlog")}
	primaryRaw, err := json.Marshal(primary)
	require.NoError(t, err)

	request2 := &model.RCARAttestationRequest{
		RuntimeData: model.RuntimeData{
			Nonce:     "nonce-tdx",
			TEEPubKey: model.JWK{Kty: "RSA", N: "mod", E: "AQAB"},
		},
		TEEEvidence: model.CompositeEvidence{PrimaryEvidence: primaryRaw},
	}

	reqBody2, nonce2, err := buildAttestRequest(request2, model.TeeTDX)
	require.NoError(t, err)
	assert.Equal(t, "nonce-tdx", nonce2)
	require.NotNil(t, reqBody2)
	require.NotNil(t, reqBody2.TDX)
	assert.Equal(t, []byte("eventlog"), reqBody2.TDX.EventLog)
	assert.Nil(t, reqBody2.SGX)
}

func TestBuildAttestRequest_RejectsInvalidEvidenceCombinations(t *testing.T) {
	reqWithBadBase64 := &model.RCARAttestationRequest{
		RuntimeData: model.RuntimeData{Nonce: "bad", TEEPubKey: model.JWK{Kty: "RSA", N: "mod", E: "AQAB"}},
		TEEEvidence: model.CompositeEvidence{PrimaryEvidence: json.RawMessage("{\"quote\":\"not-base64\"}")},
	}
	_, _, err := buildAttestRequest(reqWithBadBase64, model.TeeSGX)
	assert.Error(t, err)

	eventLogPrimary := map[string]interface{}{"quote": []byte("ok"), "event_log": []byte("data")}
	primaryRaw, err := json.Marshal(eventLogPrimary)
	require.NoError(t, err)

	_, _, err = buildAttestRequest(&model.RCARAttestationRequest{
		RuntimeData: model.RuntimeData{Nonce: "bad2", TEEPubKey: model.JWK{Kty: "RSA", N: "mod", E: "AQAB"}},
		TEEEvidence: model.CompositeEvidence{PrimaryEvidence: primaryRaw},
	}, model.TeeSGX)
	assert.Error(t, err)

	nvgpuPrimary := map[string]interface{}{"quote": []byte("ok")}
	nvgpuRaw, err := json.Marshal(nvgpuPrimary)
	require.NoError(t, err)
	_, _, err = buildAttestRequest(&model.RCARAttestationRequest{
		RuntimeData: model.RuntimeData{Nonce: "bad3", TEEPubKey: model.JWK{Kty: "RSA", N: "mod", E: "AQAB"}},
		TEEEvidence: model.CompositeEvidence{
			PrimaryEvidence:    nvgpuRaw,
			AdditionalEvidence: `{"nvidia":{"device_evidence_list":[{"evidence":"ev","certificate":"cert","arch":"HOPPER"}]}}`,
		},
	}, model.TeeSGX)
	assert.Error(t, err)
}

func TestBuildNVGPUAdditionalEvidenceAndFindEntry(t *testing.T) {
	steadyPayload := `{"nvidia":{"device_evidence_list":[{"evidence":"ev","certificate":"cert","arch":"HOPPER"}]}}`
	gpu, err := buildNVGPUAdditionalEvidence(steadyPayload, []byte("runtime-data"))
	require.NoError(t, err)
	require.NotNil(t, gpu)
	assert.Equal(t, nvidiaArchHopper, gpu.Arch)

	_, ok := findNVGPUEntry(map[string]json.RawMessage{"nvidia": json.RawMessage("{}")})
	assert.True(t, ok)
	_, ok = findNVGPUEntry(map[string]json.RawMessage{"other": json.RawMessage("{}")})
	assert.False(t, ok)

	_, err = buildNVGPUAdditionalEvidence("{not-json}", nil)
	assert.Error(t, err)
}
