/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package model

import (
	"github.com/google/uuid"
	"intel/amber/kbs/v1/clients/as"
)

type AttestationTokenClaim struct {
	*SGXClaims
	*TDXClaims
	AttesterHeldData    string                  `json:"attester_held_data,omitempty"` // Is this finalized?
	AttesterInittime    map[string]interface{}  `json:"attester_inittime_data,omitempty"`
	AttesterRuntime     map[string]interface{}  `json:"attester_runtime_data,omitempty"`
	VerifierNonce       *as.VerifierNonce       `json:"verifier_nonce,omitempty"`
	PolicyIdsMatched    []PolicyClaim           `json:"policy_ids_matched,omitempty"`
	PolicyIdsUnmatched  []PolicyClaim           `json:"policy_ids_unmatched,omitempty"`
	PolicyDefinedClaims *map[string]interface{} `json:"policy_defined_claims,omitempty"`
	AttesterTcbStatus   string                  `json:"attester_tcb_status"`
	AttesterAdvisoryIds []string                `json:"attester_advisory_ids,omitempty"`
	AttesterType        AttesterType            `json:"attester_type"`
	VerifierInstanceIds []uuid.UUID             `json:"verifier_instance_ids"`
	DbgStat             string                  `json:"dbgstat,omitempty"`     // EAT claims
	EatProfile          string                  `json:"eat_profile,omitempty"` // EAT claims
	IntUse              string                  `json:"intuse,omitempty"`      // EAT claims
	Version             string                  `json:"ver"`
}

type SGXClaims struct {
	SgxMrEnclave    string                       `json:"sgx_mrenclave"`
	SgxMrSigner     string                       `json:"sgx_mrsigner"`
	SgxIsvProdId    uint16                       `json:"sgx_isvprodid"`
	SgxIsvSvn       uint16                       `json:"sgx_isvsvn"`
	SgxReportData   string                       `json:"sgx_report_data,omitempty"`
	SgxConfigId     string                       `json:"sgx_config_id,omitempty"`
	SgxIsDebuggable bool                         `json:"sgx_is_debuggable"`
	SgxCollateral   *QuoteVerificationCollateral `json:"sgx_collateral,omitempty"`
}

type TDXClaims struct {
	TdxTeeTcbSvn          string                       `json:"tdx_tee_tcb_svn"`
	TdxMrSeam             string                       `json:"tdx_mrseam"`
	TdxMrSignerSeam       string                       `json:"tdx_mrsignerseam"`
	TdxSeamAttributes     string                       `json:"tdx_seam_attributes"`
	TdxAttributes         string                       `json:"tdx_td_attributes"`
	TdxXfam               string                       `json:"tdx_xfam"`
	TdxMRTD               string                       `json:"tdx_mrtd"`
	TdxMrConfigId         string                       `json:"tdx_mrconfigid"`
	TdxMrOwner            string                       `json:"tdx_mrowner"`
	TdxMrOwnerConfig      string                       `json:"tdx_mrownerconfig"`
	TdxRTMR0              string                       `json:"tdx_rtmr0"`
	TdxRTMR1              string                       `json:"tdx_rtmr1"`
	TdxRTMR2              string                       `json:"tdx_rtmr2"`
	TdxRTMR3              string                       `json:"tdx_rtmr3"`
	TdxReportData         string                       `json:"tdx_report_data,omitempty"`
	TdxSeamSvn            uint8                        `json:"tdx_seamsvn"`
	TdxTDAttributeDebug   bool                         `json:"tdx_td_attributes_debug"`
	TdxTDAttributesSeptVe bool                         `json:"tdx_td_attributes_septve_disable"`
	TdxTDAttributePKS     bool                         `json:"tdx_td_attributes_protection_keys"`
	TdxTDAttributeKL      bool                         `json:"tdx_td_attributes_key_locker"`
	TdxTDAttributePerfmon bool                         `json:"tdx_td_attributes_perfmon"`
	TdxIsDebuggable       bool                         `json:"tdx_is_debuggable"`
	TdxCollateral         *QuoteVerificationCollateral `json:"tdx_collateral,omitempty"`
}

type PolicyClaim struct {
	Id      uuid.UUID `json:"id"`
	Version string    `json:"version"`
}

type QuoteVerificationCollateral struct {
	QeIdCertHash    string `json:"qeidcerthash"`
	QeIdCrlHash     string `json:"qeidcrlhash"`
	QeIdHash        string `json:"qeidhash"`
	QuoteHash       string `json:"quotehash"`
	TcbInfoCertHash string `json:"tcbinfocerthash"`
	TcbInfoCrlHash  string `json:"tcbinfocrlhash"`
	TcbInfoHash     string `json:"tcbinfohash"`
}
