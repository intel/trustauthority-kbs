/*
 *   Copyright (c) 2024-2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"intel/kbs/v1/constant"
	"intel/kbs/v1/model"
	"reflect"

	_ "github.com/shaj13/libcache/fifo"
	"github.com/sirupsen/logrus"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func validateAttestationTokenClaims(tokenClaims *model.AttestationTokenClaim, transferPolicy *model.KeyTransferPolicy) error {

	if len(transferPolicy.AttestationType) == 0 {
		return errors.New("attestation_type is empty in key-transfer policy")
	}

	for _, attType := range transferPolicy.AttestationType {
		switch attType {
		case model.SGX:
			if transferPolicy.SGX == nil {
				return errors.New("sgx policy details missing from key-transfer policy")
			}
			if tokenClaims.SGXClaims == nil {
				return errors.New("sgx claims missing from attestation token")
			}
			if transferPolicy.SGX.PolicyIds != nil {
				if !isPolicyIdMatched(tokenClaims.PolicyIdsMatched, transferPolicy.SGX.PolicyIds) {
					return errors.New("None of the policy-id in token claim policy_ids_matched matched with policy_ids attribute in key-transfer policy")
				}
			}
			if transferPolicy.SGX.Attributes != nil {
				if tokenClaims.SGXClaims == nil {
					return errors.New("sgx attributes missing from attestation token")
				}
				if err := validateSGXTokenClaims(tokenClaims, transferPolicy.SGX.Attributes); err != nil {
					return err
				}
			}

		case model.TDX:
			if transferPolicy.TDX == nil {
				return errors.New("tdx policy details missing from key-transfer policy")
			}
			if tokenClaims.TDXClaims == nil {
				return errors.New("tdx claims missing from attestation token")
			}
			if transferPolicy.TDX.PolicyIds != nil {
				if !isPolicyIdMatched(tokenClaims.PolicyIdsMatched, transferPolicy.TDX.PolicyIds) {
					return errors.New("None of the policy-id in token claim policy_ids_matched matched with policy_ids attribute in key-transfer policy")
				}
			}
			if transferPolicy.TDX.Attributes != nil {
				if tokenClaims.TDXClaims == nil {
					return errors.New("tdx attributes missing from attestation token")
				}
				if err := validateTDXTokenClaims(tokenClaims, transferPolicy.TDX.Attributes); err != nil {
					return err
				}
			}

		case model.NVGPU:
			if transferPolicy.NVGPU == nil {
				return errors.New("nvgpu policy details missing from key-transfer policy")
			}
			if err := validateNVGPUClaims(tokenClaims, transferPolicy.NVGPU); err != nil {
				return err
			}

		default:
			return errors.Errorf("unsupported attestation-type: %s", attType)
		}
	}

	// Require that the token's attester_type matches the key-wrapping TEE declared
	// in the policy (TDX or SGX).  Without this check, a policy with no
	// attributes/policy_ids could be satisfied by a token for the wrong TEE.
	kwAt, err := transferPolicy.AttestationType.KeyWrappingAttesterType()
	if err != nil {
		return errors.New("policy has no key-wrapping attester type (TDX/SGX)")
	}
	if tokenClaims.AttesterType != kwAt {
		return errors.Errorf("token attester_type %q does not match policy key-wrapping attester type %q",
			tokenClaims.AttesterType, kwAt)
	}

	return nil
}

func validateNVGPUClaims(tokenClaims *model.AttestationTokenClaim, nvgpuPolicy *model.NvgpuPolicy) error {
	// Mandatory baseline: any NVGPU policy requires the token to carry the
	// overall attestation result claim.  This prevents an empty policy
	// (no policy_ids, no attributes) from being satisfied by a token that
	// has no NVGPU claims at all.
	if tokenClaims.NVGPUOverallAttResult == nil {
		return errors.New("nvgpu overall attestation result is missing from attestation token")
	}

	// 1. Policy ID match (OR semantics)
	if len(nvgpuPolicy.PolicyIds) > 0 {
		if !isPolicyIdMatched(tokenClaims.PolicyIdsMatched, nvgpuPolicy.PolicyIds) {
			return errors.New("None of the policy-id in token claim policy_ids_matched matched with nvgpu policy_ids in key-transfer policy")
		}
	}

	if nvgpuPolicy.Attributes != nil {
		attrs := nvgpuPolicy.Attributes

		// 2. Overall attestation result
		if attrs.EnforceOverallAttestationResult != nil && *attrs.EnforceOverallAttestationResult {
			if tokenClaims.NVGPUOverallAttResult == nil || !*tokenClaims.NVGPUOverallAttResult {
				return errors.New("NVGPU overall attestation result is not true")
			}
		}

		// 3. Fail closed: per-GPU checks require non-empty claim_details
		perGPUChecksRequired := (attrs.RequireSecureBoot != nil && *attrs.RequireSecureBoot) ||
			len(attrs.HwModel) > 0
		if perGPUChecksRequired && len(tokenClaims.NVGPUClaimDetails) == 0 {
			return errors.New("nvgpu claim_details are missing from attestation token")
		}

		// 4. Per-GPU secure boot check
		if attrs.RequireSecureBoot != nil && *attrs.RequireSecureBoot {
			for gpuID, detail := range tokenClaims.NVGPUClaimDetails {
				if !detail.SecBoot {
					return errors.Errorf("GPU %s does not have secure boot enabled", gpuID)
				}
			}
		}

		// 5. HW model allowlist
		if len(attrs.HwModel) > 0 {
			allowed := make(map[string]bool, len(attrs.HwModel))
			for _, m := range attrs.HwModel {
				allowed[m] = true
			}
			for gpuID, detail := range tokenClaims.NVGPUClaimDetails {
				if !allowed[detail.HwModel] {
					return errors.Errorf("GPU %s hwmodel %q is not in the allowlist", gpuID, detail.HwModel)
				}
			}
		}
	}
	return nil
}

func isPolicyIdMatched(tokenPolicyIds []model.PolicyClaim, keyPolicyIds []uuid.UUID) bool {
	for _, tokenPolicyId := range tokenPolicyIds {
		if contains(keyPolicyIds, tokenPolicyId.Id) {
			return true
		}
	}
	return false
}

func validateSGXTokenClaims(tokenClaims *model.AttestationTokenClaim, sgxAttributes *model.SgxAttributes) error {

	if tokenClaims.SGXClaims == nil {
		return errors.New("sgx claims are missing from attestation token")
	}

	if validateMrSigner(tokenClaims.SgxMrSigner, sgxAttributes.MrSigner) &&
		validateIsvProdId(tokenClaims.SgxIsvProdId, sgxAttributes.IsvProductId) &&
		validateMrEnclave(tokenClaims.SgxMrEnclave, sgxAttributes.MrEnclave) &&
		validateIsvSvn(tokenClaims.SgxIsvSvn, sgxAttributes.IsvSvn) &&
		validateTcbStatus(tokenClaims.AttesterTcbStatus, sgxAttributes.EnforceTCBUptoDate) {
		logrus.Debug("All sgx attributes in attestation token matches with attributes in key transfer policy")
		return nil
	}
	return errors.New("sgx attributes in attestation token do not match with attributes in key transfer policy")
}

// validateMrSigner - Function to Validate SignerMeasurement
func validateMrSigner(tokenMrSigner string, policyMrSigner []string) bool {

	// if MrSigner is not provided in policy, it should not be evaluated
	if len(policyMrSigner) == 0 {
		logrus.Debug("MrSigner is not provided in key transfer policy, skipping MrSigner match against the token")
		return true
	}

	if contains(policyMrSigner, tokenMrSigner) {
		logrus.Debug("MrSigner in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("MrSigner in attestation token does not match with the key transfer policy")
	return false
}

// validateIsvProdId - Function to Validate IsvProdId
func validateIsvProdId(tokenIsvProdId uint16, policyIsvProdIds []uint16) bool {

	// if IsvProdId is not provided in policy, it should not be evaluated
	if len(policyIsvProdIds) == 0 {
		logrus.Debug("IsvProdIds is not provided in key transfer policy, skipping IsvProdId match against the token")
		return true
	}

	if contains(policyIsvProdIds, tokenIsvProdId) {
		logrus.Debug("Isv Product Id in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("Isv Product Id in attestation token does not match with the key transfer policy")
	return false
}

// validateMrEnclave - Function to Validate EnclaveMeasurement
func validateMrEnclave(tokenMrEnclave string, policyMrEnclave []string) bool {

	// if MrEnclave is not provided in policy, it should not be evaluated
	if len(policyMrEnclave) == 0 {
		logrus.Debug("MrEnclave is not provided in key transfer policy, skipping MrEnclave match against the token")
		return true
	}

	if contains(policyMrEnclave, tokenMrEnclave) {
		logrus.Debug("Enclave Measurement in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("Enclave Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateIsvSvn- Function to Validate isvSvn
func validateIsvSvn(tokenIsvSvn uint16, policyIsvSvn *uint16) bool {

	// if IsvSvn is not provided in policy, it should not be evaluated
	if policyIsvSvn == nil {
		logrus.Debug("IsvSvn is not provided in key transfer policy, skipping IsvSvn match against the token")
		return true
	}

	if tokenIsvSvn == *policyIsvSvn {
		logrus.Debug("IsvSvn in attestation token matches with the key transfer policy")
		return true
	}
	logrus.Error("IsvSvn in attestation token does not match with the key transfer policy")
	return false
}

// validateTcbStatus- Function to Validate tcbStatus
func validateTcbStatus(tcbStatus string, enforceTcbUptoDate *bool) bool {

	if enforceTcbUptoDate == nil {
		logrus.Debug("enforceTcbUptoDate is not provided in key transfer policy, skipping enforceTcbUptoDate match against the token")
		return true
	}

	if *enforceTcbUptoDate && tcbStatus != constant.TCBStatusUpToDate {
		logrus.Error("TCB is not Up-to-Date")
		return false
	}
	return true
}

func validateTDXTokenClaims(tokenClaims *model.AttestationTokenClaim, tdxAttributes *model.TdxAttributes) error {

	if tokenClaims.TDXClaims == nil {
		return errors.New("tdx claims are missing from attestation token")
	}

	if validateMrSignerSeam(tokenClaims.TdxMrSignerSeam, tdxAttributes.MrSignerSeam) &&
		validateMrSeam(tokenClaims.TdxMrSeam, tdxAttributes.MrSeam) &&
		validateSeamSvn(tokenClaims.TdxSeamSvn, tdxAttributes.SeamSvn) &&
		validateMrTD(tokenClaims.TdxMRTD, tdxAttributes.MRTD) &&
		validateRTMR(tokenClaims.TdxRTMR0, tdxAttributes.RTMR0) &&
		validateRTMR(tokenClaims.TdxRTMR1, tdxAttributes.RTMR1) &&
		validateRTMR(tokenClaims.TdxRTMR2, tdxAttributes.RTMR2) &&
		validateRTMR(tokenClaims.TdxRTMR3, tdxAttributes.RTMR3) &&
		validateTcbStatus(tokenClaims.AttesterTcbStatus, tdxAttributes.EnforceTCBUptoDate) {
		logrus.Debug("All tdx attributes in attestation token matches with attributes in key transfer policy")
		return nil
	}
	return errors.New("tdx attributes in attestation token do not match with attributes in key transfer policy")
}

// validateMrSignerSeam - Function to Validate MrSignerSeam
func validateMrSignerSeam(tokenMrSignerSeam string, policyMrSignerSeam []string) bool {

	// if MrSignerSeam is not provided in policy, it should not be evaluated
	if len(policyMrSignerSeam) == 0 {
		logrus.Debug("MrSignerSeam is not provided in key transfer policy, skipping MrSignerSeam match against the token")
		return true
	}

	if contains(policyMrSignerSeam, tokenMrSignerSeam) {
		logrus.Debug("MrSignerSeam in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("MrSignerSeam in attestation token does not match with the key transfer policy")
	return false
}

// validateMrSeam - Function to Validate SeamMeasurement
func validateMrSeam(tokenMrSeam string, policyMrSeam []string) bool {

	// if MrSeam is not provided in policy, it should not be evaluated
	if len(policyMrSeam) == 0 {
		logrus.Debug("MrSeam is not provided in key transfer policy, skipping MrSeam match against the token")
		return true
	}

	if contains(policyMrSeam, tokenMrSeam) {
		logrus.Debug("Seam Measurement in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("Seam Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateSeamSvn- Function to Validate seamSvn
func validateSeamSvn(tokenSeamSvn uint16, policySeamSvn *uint16) bool {

	// if SeamSvn is not provided in policy, it should not be evaluated
	if policySeamSvn == nil {
		logrus.Debug("SeamSvn is not provided in key transfer policy, skipping SeamSvn match against the token")
		return true
	}

	if tokenSeamSvn == *policySeamSvn {
		logrus.Debug("Seam Svn in attestation token matches with the key transfer policy")
		return true
	}
	logrus.Error("Seam Svn in attestation token does not match with the key transfer policy")
	return false
}

// validateMrTD - Function to Validate TDMeasurement
func validateMrTD(tokenMrTD string, policyMrTD []string) bool {

	// if MrTD is not provided in policy, it should not be evaluated
	if len(policyMrTD) == 0 {
		logrus.Debug("MrTD is not provided in key transfer policy, skipping MrTD match against the token")
		return true
	}

	if contains(policyMrTD, tokenMrTD) {
		logrus.Debug("TD Measurement in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("TD Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateRTMR - Function to Validate RTMR
func validateRTMR(tokenRTMR string, policyRTMR string) bool {

	// if RTMR is not provided in policy, it should not be evaluated
	if policyRTMR == "" {
		return true
	}

	if tokenRTMR == policyRTMR {
		logrus.Debug("RTMR in attestation token matches with the key transfer policy")
		return true
	}

	logrus.Error("RTMR in attestation token does not match with the key transfer policy")
	return false
}

func contains(s interface{}, elem interface{}) bool {
	slice := reflect.ValueOf(s)
	if slice.Kind() == reflect.Slice {
		for index := 0; index < slice.Len(); index++ {
			//panics if slice element points to an unexported struct field
			if slice.Index(index).Interface() == elem {
				return true
			}
		}
	}
	return false
}
