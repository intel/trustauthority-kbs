/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"intel/kbs/v1/model"

	"github.com/google/uuid"
	"github.com/gowebpki/jcs"
	"github.com/pkg/errors"
)

const (
	nvidiaArchHopper    = "HOPPER"
	nvidiaArchBlackwell = "BLACKWELL"
)

// DCAPTEEEvidence models Trustee primary evidence payload.
// Quote, runtime_data, event logs and user_data are base64-encoded by Trustee.
type DCAPTEEEvidence struct {
	Quote       []byte `json:"quote"`
	RuntimeData []byte `json:"runtime_data,omitempty"`
	UserData    []byte `json:"user_data,omitempty"`
	EventLog    []byte `json:"event_log,omitempty"`
	CCEventLog  []byte `json:"cc_eventlog,omitempty"`
}

// Trustee Nvidia evidence shape (before ITA-specific transformation).
type NVDeviceEvidence struct {
	DeviceEvidenceList []NVDeviceReportAndCert `json:"device_evidence_list"`
}

type NVDeviceReportAndCert struct {
	Evidence    string `json:"evidence"`
	GPUNonce    string `json:"gpu_nonce,omitempty"`
	Certificate string `json:"certificate"`
	Arch        string `json:"arch"`
}

// ITA NVGPU request shape.
type NVGPURequest struct {
	GPUNonce     string              `json:"gpu_nonce"`
	Arch         string              `json:"arch"`
	EvidenceList []NVGPUEvidenceItem `json:"evidence_list"`
}

type NVGPUEvidenceItem struct {
	Evidence    string `json:"evidence"`
	Certificate string `json:"certificate"`
}

// AttestRequest is the full body sent to ITA /appraisal/v2/attest.
// SGX and TDX are mutually exclusive; NVGPU can only accompany TDX.
type AttestRequest struct {
	PolicyIds       []uuid.UUID      `json:"policy_ids,omitempty"`
	PolicyMustMatch bool             `json:"policy_must_match,omitempty"`
	TDX             *DCAPTEEEvidence `json:"tdx,omitempty"`
	SGX             *DCAPTEEEvidence `json:"sgx,omitempty"`
	NVGPU           *NVGPURequest    `json:"nvgpu,omitempty"`
}

func buildAttestRequest(req *model.RCARAttestationRequest, teeType model.Tee) (*AttestRequest, string, error) {
	primary, err := parseTrusteePrimaryEvidence(req.TEEEvidence.PrimaryEvidence)
	if err != nil {
		return nil, "", err
	}

	kbsEvidenceRuntimeData, err := json.Marshal(req.RuntimeData)
	if err != nil {
		return nil, "", errors.New("failed to serialize runtime-data")
	}

	nvgpu, err := buildNVGPUAdditionalEvidence(req.TEEEvidence.AdditionalEvidence, kbsEvidenceRuntimeData)
	if err != nil {
		return nil, "", err
	}

	runtimeData := struct {
		TeePubKey          model.JWK `json:"tee-pubkey"`
		Nonce              string    `json:"nonce"`
		AdditionalEvidence string    `json:"additional-evidence"`
	}{
		TeePubKey:          req.RuntimeData.TEEPubKey,
		Nonce:              req.RuntimeData.Nonce,
		AdditionalEvidence: req.TEEEvidence.AdditionalEvidence,
	}

	rawRuntimeData, err := json.Marshal(runtimeData)
	if err != nil {
		return nil, "", errors.New("failed to serialize primary runtime-data")
	}
	primaryRuntimeData, err := jcs.Transform(rawRuntimeData)
	if err != nil {
		return nil, "", errors.New("failed to canonicalize primary runtime-data")
	}

	reqBody := AttestRequest{}
	switch teeType {
	case model.TeeTDX:
		eventLog := primary.EventLog
		if len(eventLog) == 0 {
			eventLog = primary.CCEventLog
		}
		reqBody = AttestRequest{
			TDX: &DCAPTEEEvidence{
				Quote:       primary.Quote,
				RuntimeData: primaryRuntimeData,
				EventLog:    eventLog,
			},
			NVGPU: nvgpu,
		}
	case model.TeeSGX:
		if nvgpu != nil {
			return nil, "", errors.New("nvgpu evidence is not valid with sgx evidence")
		}
		if len(primary.EventLog) > 0 || len(primary.CCEventLog) > 0 {
			return nil, "", errors.New("sgx evidence is not valid with event log")
		}
		reqBody = AttestRequest{
			SGX: &DCAPTEEEvidence{
				Quote:       primary.Quote,
				RuntimeData: primaryRuntimeData,
			},
		}
	default:
		return nil, "", errors.New("unsupported tee evidence")
	}

	return &reqBody, req.RuntimeData.Nonce, nil
}

func parseTrusteePrimaryEvidence(raw json.RawMessage) (*DCAPTEEEvidence, error) {
	if len(raw) == 0 {
		return nil, errors.New("tee-evidence.primary_evidence is required")
	}

	// Compatibility with lightweight payloads where primary_evidence is a
	// base64 quote string rather than a JSON object.
	var quoteOnly string
	if err := json.Unmarshal(raw, &quoteOnly); err == nil {
		quote, err := base64.StdEncoding.DecodeString(quoteOnly)
		if err != nil {
			quote, err = base64.RawStdEncoding.DecodeString(quoteOnly)
			if err != nil {
				return nil, errors.New("failed to decode primary_evidence quote")
			}
		}
		if len(quote) == 0 {
			return nil, errors.New("primary_evidence quote is required")
		}
		return &DCAPTEEEvidence{Quote: quote}, nil
	}

	var ev DCAPTEEEvidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, errors.Wrap(err, "invalid primary_evidence")
	}
	if len(ev.Quote) == 0 {
		return nil, errors.New("primary_evidence quote is required")
	}

	return &ev, nil
}

func buildNVGPUAdditionalEvidence(additional string, runtimeData []byte) (*NVGPURequest, error) {
	if strings.TrimSpace(additional) == "" {
		return nil, nil
	}

	var mapEvidence map[string]json.RawMessage
	if err := json.Unmarshal([]byte(additional), &mapEvidence); err != nil {
		return nil, errors.New("invalid tee-evidence.additional_evidence")
	}

	nvgpuRaw, ok := findNVGPUEntry(mapEvidence)
	if !ok || len(nvgpuRaw) == 0 {
		return nil, nil
	}

	// If client already sends ITA nvgpu shape, pass it through after basic decode validation.
	var existing NVGPURequest
	if err := json.Unmarshal(nvgpuRaw, &existing); err == nil && len(existing.EvidenceList) > 0 {
		return &existing, nil
	}

	var trusteeNV NVDeviceEvidence
	if err := json.Unmarshal(nvgpuRaw, &trusteeNV); err != nil {
		return nil, errors.New("invalid nvgpu evidence")
	}
	if len(trusteeNV.DeviceEvidenceList) == 0 {
		return nil, nil
	}

	filtered := make([]NVDeviceReportAndCert, 0, len(trusteeNV.DeviceEvidenceList))
	for _, d := range trusteeNV.DeviceEvidenceList {
		arch := strings.ToUpper(strings.TrimSpace(d.Arch))
		if arch != nvidiaArchHopper && arch != nvidiaArchBlackwell {
			continue
		}
		d.Arch = arch
		filtered = append(filtered, d)
	}
	if len(filtered) == 0 {
		return nil, nil
	}

	h := sha512.Sum512(runtimeData)
	gpuNonce := hex.EncodeToString(h[:32])

	itaReq := NVGPURequest{
		GPUNonce:     gpuNonce,
		Arch:         filtered[0].Arch,
		EvidenceList: make([]NVGPUEvidenceItem, 0, len(filtered)),
	}
	for _, d := range filtered {
		itaReq.EvidenceList = append(itaReq.EvidenceList, NVGPUEvidenceItem{
			Evidence:    d.Evidence,
			Certificate: d.Certificate,
		})
	}

	return &itaReq, nil
}

func findNVGPUEntry(m map[string]json.RawMessage) (json.RawMessage, bool) {
	for k, v := range m {
		lower := strings.ToLower(strings.TrimSpace(k))
		if lower == "nvidia" || lower == "nvgpu" {
			return v, true
		}
	}
	return nil, false
}
