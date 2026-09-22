/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"encoding/json"
	"testing"
)

// sgxV2TokenPayload mirrors the decoded payload of a real ITA v2 SGX token
// (see sgx_v2_token in the repo root for the full sample).
const sgxV2TokenPayload = `{
  "eat_profile": "https://amber-dev02-user2.ita-dev.adsdcsp.com/eat_profile.html",
  "intuse": "generic",
  "sgx": {
    "attester_advisory_ids": [
      "INTEL-SA-00586",
      "INTEL-SA-00614"
    ],
    "attester_held_data": "AQABALUKAI9jz55+A22V+f0FPeinIJimJndmJ0BzAe0HddllZX6f1yOhmXHtJvZpbz0zzHXZ/xjQMa+z5yrVnfqp6hez5cmse0MOinOPjZUu6t/ro/T+5c0FK2Ay7r/AD4NPl+AfZJnq9kYa+aVMnbklHeyUmBhf2+sHkfaaL17pf7Wa+qRls4TQFGJ/5SV77CbySJR5DZxrRFvkDlmvapVu8eb8Z7cafA0uj44fSde9vZJ0/SvQUKGbZWz2oUZpmSDYzUuOrJef1xzONi9fgCxtK1a1UnJrPZnLfJgy2s2n0JBnzsMW5WqryGSCB3xdZw1Jq2RI0JIooOE7rraRzVibxZg2op7y8di23bsUK42SiwYCQICv3H4f3FC7ZDVFDNI6raSUD35equMHKqJhXArK2+CNHcd83MmdVHMj1dKDohe2R1OPL0oaSSpm8ojoaRmY9GFXp2SoA5yHBobxAITk5ZMzG/eRycT6Z/BhBeDgZtzsFOiXz7vISiakJP/pYoI/kQ==",
    "attester_tcb_date": "2021-11-10T00:00:00Z",
    "attester_tcb_status": "OutOfDate",
    "attester_type": "SGX",
    "dbgstat": "disabled",
    "pce_svn": 11,
    "platform_instance_id": "c58a8dfd2621b60aa38d24b13b7582f5",
    "sgx_collateral": {
      "qeidcerthash": "c550544e4442d9be583a5eddd48df8ba0149ddeef40efd3737ebe0f885dc3711",
      "qeidcrlhash":  "807f576950dcf1a807ae59e0ba8eac19664ec39896c1fe2de5cc8a9cc9d3375f",
      "qeidhash":     "2d594687cb11f23c3f27e5ab92d4578ac9372b58e0cd130d891e49d6a5269cc2",
      "quotehash":    "2fb3eee27472ef93f2bb6bfb674ba1c84ec7eee077941cc20d1f7aff1a066e5e",
      "tcbinfocerthash": "c550544e4442d9be583a5eddd48df8ba0149ddeef40efd3737ebe0f885dc3711",
      "tcbinfocrlhash":  "807f576950dcf1a807ae59e0ba8eac19664ec39896c1fe2de5cc8a9cc9d3375f",
      "tcbinfohash":     "8ba6562d44e54116a74db8429882780deb8d838057109846d009dfc3f220f710"
    },
    "sgx_is_debuggable": false,
    "sgx_isvprodid": 0,
    "sgx_isvsvn": 0,
    "sgx_mrenclave": "4ec22b0f50b1febe4f7cfb1612366c4b16e30760d622d5915bec9ae4af6232c1",
    "sgx_mrsigner":  "d412a4f07ef83892a5915fb2ab584be31e186e5a4f95ab5f6950fd4eb8694d7b",
    "sgx_report_data": "95d41098412a39cf7f9f607524e270db73a3007e5b593aaa7f13b5bdbecdc8fe0000000000000000000000000000000000000000000000000000000000000000"
  },
  "ver": "2.0.0",
  "verifier_instance_ids": [
    "9f07abc5-9b90-47a1-ac6d-4f5fa6732421",
    "cb2f8609-0a5e-446a-8f08-8712a8ad0978"
  ]
}`

// tdxV2TokenPayload mirrors the decoded payload of a real ITA v2 TDX token.
const tdxV2TokenPayload = `{
  "eat_profile": "https://portal.trustauthority.intel.com/eat_profile.html",
  "intuse": "generic",
  "tdx": {
    "attester_held_data": "dGVzdC1oZWxkLWRhdGE=",
    "attester_tcb_date": "2021-11-10T00:00:00Z",
    "attester_tcb_status": "UpToDate",
    "attester_advisory_ids": ["INTEL-SA-00001"],
    "dbgstat": "disabled",
    "tdx_mrenclave": "",
    "tdx_mrsignerseam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "tdx_mrseam": "489e585f1c54bc5a02066c8c6ec21619ff0334ec6f21e07e2a35202c59183789c8057e7d97dd591bb08314b185819e72",
    "tdx_mrtd": "5fa1e03ac82c81049423456878a624582b8ca199aea6f9227c3f7aca432701ea49f0fb19a4ae82b4d4e79b64359f107b",
    "tdx_mrconfigid": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "tdx_mrowner":    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "tdx_mrownerconfig": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "tdx_rtmr0": "c231b38689cb1e4314c0332ba722d14930c9917f93c3a6d61bbb43d86b72f7ff957357bf70744c9c40c8e314d52271e5",
    "tdx_rtmr1": "e6b2adf57939c1c7476a9e79e48b8c7dd4eff614c348ade4e0e2e987582d4c94796eeda6ddd1b50d11db9e1bceded942",
    "tdx_rtmr2": "f629c8341aae927f61d9cc0e0bee7ba34010f043058afb2612b1d5b5fc8d0a6d70ed0b8cc3aa09a8f87d274c8efa2858",
    "tdx_rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "tdx_seam_attributes": "0000000000000000",
    "tdx_seamsvn": 269,
    "tdx_tee_tcb_svn": "0d010400000000000000000000000000",
    "tdx_xfam": "e702060000000000",
    "tdx_td_attributes": "0000001000000000",
    "tdx_td_attributes_debug": false,
    "tdx_td_attributes_septve_disable": true,
    "tdx_td_attributes_protection_keys": false,
    "tdx_td_attributes_key_locker": false,
    "tdx_td_attributes_perfmon": false,
    "tdx_is_debuggable": false,
    "tdx_is_migratable": false,
    "tdx_report_data": "cab045bef41d70a1dcefc4c7c101acdb76051ff8c9111d89258dd075ee763d7d40cdf036fca1f4a019af48b0def3b1888ae2a82c2934a3bf0482ba1ca9a8f2fe"
  },
  "ver": "2.0.0",
  "verifier_instance_ids": [
    "9f07abc5-9b90-47a1-ac6d-4f5fa6732421"
  ]
}`

func TestToAttestationTokenClaim_SGXV2(t *testing.T) {
	var v2 AttestationTokenV2Claim
	if err := json.Unmarshal([]byte(sgxV2TokenPayload), &v2); err != nil {
		t.Fatalf("failed to unmarshal SGX V2 token: %v", err)
	}

	if v2.SGX == nil {
		t.Fatal("expected SGX sub-object to be present")
	}
	if v2.SGX.AttesterTcbStatus != "OutOfDate" {
		t.Errorf("sgx.attester_tcb_status: got %q, want %q", v2.SGX.AttesterTcbStatus, "OutOfDate")
	}
	if len(v2.SGX.AttesterAdvisoryIds) != 2 {
		t.Errorf("sgx.attester_advisory_ids: got %d entries, want 2", len(v2.SGX.AttesterAdvisoryIds))
	}
	if v2.SGX.DbgStat != "disabled" {
		t.Errorf("sgx.dbgstat: got %q, want %q", v2.SGX.DbgStat, "disabled")
	}

	flat := v2.ToAttestationTokenClaim()

	// AttesterType
	if flat.AttesterType != SGX {
		t.Errorf("AttesterType: got %v, want SGX", flat.AttesterType)
	}
	// attester_tcb_status must be lifted from sgx sub-object.
	if flat.AttesterTcbStatus != "OutOfDate" {
		t.Errorf("AttesterTcbStatus: got %q, want %q", flat.AttesterTcbStatus, "OutOfDate")
	}
	// attester_advisory_ids must be lifted from sgx sub-object.
	if len(flat.AttesterAdvisoryIds) != 2 {
		t.Errorf("AttesterAdvisoryIds: got %d, want 2", len(flat.AttesterAdvisoryIds))
	}
	// dbgstat lifted from sgx sub-object.
	if flat.DbgStat != "disabled" {
		t.Errorf("DbgStat: got %q, want %q", flat.DbgStat, "disabled")
	}
	// attester_held_data lifted from sgx sub-object.
	if flat.AttesterHeldData == "" {
		t.Error("AttesterHeldData must not be empty")
	}
	// SGX claims populated.
	if flat.SGXClaims == nil {
		t.Fatal("SGXClaims must not be nil")
	}
	if flat.SGXClaims.SgxMrEnclave != "4ec22b0f50b1febe4f7cfb1612366c4b16e30760d622d5915bec9ae4af6232c1" {
		t.Errorf("SgxMrEnclave: got %q", flat.SGXClaims.SgxMrEnclave)
	}
	if flat.SGXClaims.SgxIsDebuggable {
		t.Error("SgxIsDebuggable should be false")
	}
	// NVGPU fields must be nil (SGX cannot combine with NVGPU).
	if flat.NVGPUOverallAttResult != nil {
		t.Error("NVGPUOverallAttResult must be nil for SGX token")
	}
	// TDX claims must be nil.
	if flat.TDXClaims != nil {
		t.Error("TDXClaims must be nil for SGX token")
	}
	// Version and other top-level fields.
	if flat.Version != "2.0.0" {
		t.Errorf("Version: got %q, want %q", flat.Version, "2.0.0")
	}
	if len(flat.VerifierInstanceIds) != 2 {
		t.Errorf("VerifierInstanceIds: got %d, want 2", len(flat.VerifierInstanceIds))
	}
}

func TestToAttestationTokenClaim_TDXV2(t *testing.T) {
	var v2 AttestationTokenV2Claim
	if err := json.Unmarshal([]byte(tdxV2TokenPayload), &v2); err != nil {
		t.Fatalf("failed to unmarshal TDX V2 token: %v", err)
	}

	if v2.TDX == nil {
		t.Fatal("expected TDX sub-object to be present")
	}
	if v2.TDX.AttesterTcbStatus != "UpToDate" {
		t.Errorf("tdx.attester_tcb_status: got %q, want %q", v2.TDX.AttesterTcbStatus, "UpToDate")
	}

	flat := v2.ToAttestationTokenClaim()

	if flat.AttesterType != TDX {
		t.Errorf("AttesterType: got %v, want TDX", flat.AttesterType)
	}
	if flat.AttesterTcbStatus != "UpToDate" {
		t.Errorf("AttesterTcbStatus: got %q, want %q", flat.AttesterTcbStatus, "UpToDate")
	}
	if len(flat.AttesterAdvisoryIds) != 1 {
		t.Errorf("AttesterAdvisoryIds: got %d, want 1", len(flat.AttesterAdvisoryIds))
	}
	if flat.DbgStat != "disabled" {
		t.Errorf("DbgStat: got %q, want %q", flat.DbgStat, "disabled")
	}
	if flat.AttesterHeldData == "" {
		t.Error("AttesterHeldData must not be empty")
	}
	if flat.TDXClaims == nil {
		t.Fatal("TDXClaims must not be nil")
	}
	if flat.SGXClaims != nil {
		t.Error("SGXClaims must be nil for TDX token")
	}
	if flat.NVGPUOverallAttResult != nil {
		t.Error("NVGPUOverallAttResult must be nil (no nvgpu in this token)")
	}
}

func TestToAttestationTokenClaim_SGXV2_NoNVGPU(t *testing.T) {
	// Construct a token that has both sgx and nvgpu — should be treated as SGX-only.
	payload := `{
		"ver": "2.0.0",
		"sgx": {
			"attester_tcb_status": "UpToDate",
			"sgx_mrenclave": "aabbcc",
			"sgx_mrsigner": "ddeeff",
			"sgx_is_debuggable": false
		},
		"nvgpu": {
			"x-nvidia-overall-att-result": true
		}
	}`
	var v2 AttestationTokenV2Claim
	if err := json.Unmarshal([]byte(payload), &v2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	flat := v2.ToAttestationTokenClaim()
	if flat.AttesterType != SGX {
		t.Errorf("expected SGX, got %v", flat.AttesterType)
	}
	// NVGPU must NOT be populated when SGX is primary.
	if flat.NVGPUOverallAttResult != nil {
		t.Error("NVGPUOverallAttResult must be nil when SGX is present")
	}
}

// TestAttesterTypesMarshalJSON verifies backward-compatible serialization:
// single-element AttesterTypes must marshal as a plain string, not an array.
func TestAttesterTypesMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		in   AttesterTypes
		want string // expected JSON
	}{
		{"single SGX", AttesterTypes{SGX}, `"SGX"`},
		{"single TDX", AttesterTypes{TDX}, `"TDX"`},
		{"composite TDX+NVGPU", AttesterTypes{TDX, NVGPU}, `["TDX","NVGPU"]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			if string(b) != tc.want {
				t.Errorf("got %s, want %s", b, tc.want)
			}
		})
	}
}

// TestAttesterTypesMarshalUnmarshalRoundTrip verifies that a round-trip through
// JSON preserves both single-element (string form) and multi-element (array) policies.
func TestAttesterTypesMarshalUnmarshalRoundTrip(t *testing.T) {
	cases := []AttesterTypes{
		{SGX},
		{TDX},
		{TDX, NVGPU},
	}
	for _, original := range cases {
		b, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal %v: %v", original, err)
		}
		var got AttesterTypes
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if len(got) != len(original) {
			t.Errorf("length mismatch: got %d want %d", len(got), len(original))
			continue
		}
		for i := range original {
			if got[i] != original[i] {
				t.Errorf("element %d: got %s want %s", i, got[i], original[i])
			}
		}
	}
}

// TestKeyTransferRequestUnmarshalJSON_UnknownField verifies that the custom
// UnmarshalJSON rejects unknown fields, preserving the strict-decode contract.
func TestKeyTransferRequestUnmarshalJSON_UnknownField(t *testing.T) {
	bad := `{"quote":"dGVzdA==","unknown_field":"should-fail"}`
	var r KeyTransferRequest
	if err := json.Unmarshal([]byte(bad), &r); err == nil {
		t.Error("expected error for unknown field, got nil")
	}
}

// TestKeyTransferRequestUnmarshalJSON_NestedSGX verifies that a nested sgx object
// is correctly promoted to the flat fields and the V2SGX flag is set.
func TestKeyTransferRequestUnmarshalJSON_NestedSGX(t *testing.T) {
	body := `{"sgx":{"quote":"dGVzdA==","runtime_data":"cnVudGltZQ=="}}`
	var r KeyTransferRequest
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.V2SGX {
		t.Error("V2SGX must be true when sgx sub-object is present")
	}
	if string(r.Quote) != "test" {
		t.Errorf("Quote: got %q, want %q", r.Quote, "test")
	}
}

// TestKeyTransferRequestUnmarshalJSON_FlatFallback verifies that the legacy flat
// format (no tdx/sgx sub-object) still works and V2SGX is false.
func TestKeyTransferRequestUnmarshalJSON_FlatFallback(t *testing.T) {
	body := `{"quote":"dGVzdA==","event_log":"ZXZlbnQ="}`
	var r KeyTransferRequest
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.V2SGX {
		t.Error("V2SGX must be false for flat legacy format")
	}
	if string(r.Quote) != "test" {
		t.Errorf("Quote: got %q, want %q", r.Quote, "test")
	}
}
