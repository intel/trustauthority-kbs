/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package model

import "github.com/google/uuid"

type AttestationTokenClaim struct {
	AmberTrustScore         int                     `json:"amber_trust_score"`
	AmberTdxMrSeam          string                  `json:"amber_tdx_mrseam,omitempty"`
	AmberTdxMrSignerSeam    string                  `json:"amber_tdx_mrsignerseam,omitempty"`
	AmberTdxMRTD            string                  `json:"amber_tdx_mrtd,omitempty"`
	AmberTdxRTMR0           string                  `json:"amber_tdx_rtmr0,omitempty"`
	AmberTdxRTMR1           string                  `json:"amber_tdx_rtmr1,omitempty"`
	AmberTdxRTMR2           string                  `json:"amber_tdx_rtmr2,omitempty"`
	AmberTdxRTMR3           string                  `json:"amber_tdx_rtmr3,omitempty"`
	AmberTdxSeamSvn         *uint8                  `json:"amber_tdx_seamsvn,omitempty"`
	AmberReportData         string                  `json:"amber_report_data,omitempty"`
	AmberTeeHeldData        string                  `json:"amber_tee_held_data,omitempty"`
	AmberInittime           map[string]interface{}  `json:"amber_inittime,omitempty"`
	AmberRuntime            map[string]interface{}  `json:"amber_runtime,omitempty"`
	AmberSgxMrEnclave       string                  `json:"amber_sgx_mrenclave,omitempty"`
	AmberSgxMrSigner        string                  `json:"amber_sgx_mrsigner,omitempty"`
	AmberSgxIsvproductId    *uint16                 `json:"amber_sgx_isvprodid,omitempty"`
	AmberSgxIsvsvn          *uint16                 `json:"amber_sgx_isvsvn,omitempty"`
	AmberMatchedPolicyIds   []PolicyClaim           `json:"amber_matched_policy_ids,omitempty"`
	AmberUnmatchedPolicyIds []PolicyClaim           `json:"amber_unmatched_policy_ids,omitempty"`
	AmberFaithfulServiceIds []uuid.UUID             `json:"amber_faithful_service_ids"`
	AmberTcbStatus          string                  `json:"amber_tcb_status"`
	AmberTeeIsDebuggable    bool                    `json:"amber_tee_is_debuggable,omitempty"`
	AmberEvidenceType       AttestationType         `json:"amber_evidence_type"`
	AmberSignedNonce        bool                    `json:"amber_signed_nonce,omitempty"`
	AmberClientNonce        bool                    `json:"amber_client_nonce,omitempty"`
	AmberCustomPolicy       *map[string]interface{} `json:"amber_custom_policy,omitempty"`
	Version                 string                  `json:"ver"`
	AmberSgxConfigId        string                  `json:"amber_sgx_config_id,omitempty"`
}

type PolicyClaim struct {
	Id      uuid.UUID `json:"id"`
	Version string    `json:"version"`
}
