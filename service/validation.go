/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	_ "github.com/shaj13/libcache/fifo"
	"intel/kbs/v1/constant"
	"intel/kbs/v1/model"
	"reflect"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func validateAttestationTokenClaims(tokenClaims *model.AttestationTokenClaim, transferPolicy *model.KeyTransferPolicy) error {

	switch transferPolicy.AttestationType[0] {
	case model.SGX:
		if tokenClaims.PolicyIdsMatched != nil && transferPolicy.SGX.PolicyIds != nil {
			if isPolicyIdMatched(tokenClaims.PolicyIdsMatched, transferPolicy.SGX.PolicyIds) {
				return nil
			}
			if transferPolicy.SGX.Attributes == nil {
				return errors.New("None of the policy-id in token matched with policy-id in key-transfer policy")
			}
		}
		return validateSGXTokenClaims(tokenClaims, transferPolicy.SGX.Attributes)

	case model.TDX:
		if tokenClaims.PolicyIdsMatched != nil && transferPolicy.TDX.PolicyIds != nil {
			if isPolicyIdMatched(tokenClaims.PolicyIdsMatched, transferPolicy.TDX.PolicyIds) {
				return nil
			}
			if transferPolicy.TDX.Attributes == nil {
				return errors.New("None of the policy-id in token matched with policy-id in key-transfer policy")
			}
		}
		return validateTDXTokenClaims(tokenClaims, transferPolicy.TDX.Attributes)

	default:
		return errors.New("Unsupported attestation-type")
	}
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

	if validateMrSigner(tokenClaims.SgxMrSigner, sgxAttributes.MrSigner) &&
		validateIsvProdId(tokenClaims.SgxIsvProdId, sgxAttributes.IsvProductId) &&
		validateMrEnclave(tokenClaims.SgxMrEnclave, sgxAttributes.MrEnclave) &&
		validateIsvSvn(tokenClaims.SgxIsvSvn, *sgxAttributes.IsvSvn) &&
		validateTcbStatus(tokenClaims.AttesterTcbStatus, *sgxAttributes.EnforceTCBUptoDate) {
		log.Debug("All sgx attributes in attestation token matches with attributes in key transfer policy")
		return nil
	}
	return errors.New("sgx attributes in attestation token do not match with attributes in key transfer policy")
}

// validateMrSigner - Function to Validate SignerMeasurement
func validateMrSigner(tokenMrSigner string, policyMrSigner []string) bool {

	if tokenMrSigner == "" {
		log.Error("MrSigner is missing from attestation token")
		return false
	}

	if contains(policyMrSigner, tokenMrSigner) {
		log.Debug("MrSigner in attestation token matches with the key transfer policy")
		return true
	}

	log.Error("MrSigner in attestation token does not match with the key transfer policy")
	return false
}

// validateIsvProdId - Function to Validate IsvProdId
func validateIsvProdId(tokenIsvProdId uint16, policyIsvProdIds []uint16) bool {

	if contains(policyIsvProdIds, tokenIsvProdId) {
		log.Debug("Isv Product Id in attestation token matches with the key transfer policy")
		return true
	}

	log.Error("Isv Product Id in attestation token does not match with the key transfer policy")
	return false
}

// validateMrEnclave - Function to Validate EnclaveMeasurement
func validateMrEnclave(tokenMrEnclave string, policyMrEnclave []string) bool {

	if len(policyMrEnclave) == 0 {
		return true
	}

	if contains(policyMrEnclave, tokenMrEnclave) {
		log.Debug("Enclave Measurement in attestation token matches with the key transfer policy")
		return true
	}

	log.Error("Enclave Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateIsvSvn- Function to Validate isvSvn
func validateIsvSvn(tokenIsvSvn uint16, policyIsvSvn uint16) bool {

	if tokenIsvSvn == policyIsvSvn {
		log.Debug("IsvSvn in attestation token matches with the key transfer policy")
		return true
	}
	log.Error("IsvSvn in attestation token does not match with the key transfer policy")
	return false
}

// validateTcbStatus- Function to Validate tcbStatus
func validateTcbStatus(tcbStatus string, enforceTcbUptoDate bool) bool {

	if enforceTcbUptoDate && tcbStatus != constant.TCBStatusUpToDate {
		log.Error("TCB is not Up-to-Date")
		return false
	}
	return true
}

func validateTDXTokenClaims(tokenClaims *model.AttestationTokenClaim, tdxAttributes *model.TdxAttributes) error {

	if validateMrSignerSeam(tokenClaims.TdxMrSignerSeam, tdxAttributes.MrSignerSeam) &&
		validateMrSeam(tokenClaims.TdxMrSeam, tdxAttributes.MrSeam) &&
		validateSeamSvn(tokenClaims.TdxSeamSvn, *tdxAttributes.SeamSvn) &&
		validateMrTD(tokenClaims.TdxMRTD, tdxAttributes.MRTD) &&
		validateRTMR(tokenClaims.TdxRTMR0, tdxAttributes.RTMR0) &&
		validateRTMR(tokenClaims.TdxRTMR1, tdxAttributes.RTMR1) &&
		validateRTMR(tokenClaims.TdxRTMR2, tdxAttributes.RTMR2) &&
		validateRTMR(tokenClaims.TdxRTMR3, tdxAttributes.RTMR3) &&
		validateTcbStatus(tokenClaims.AttesterTcbStatus, *tdxAttributes.EnforceTCBUptoDate) {
		log.Debug("All tdx attributes in attestation token matches with attributes in key transfer policy")
		return nil
	}
	return errors.New("tdx attributes in attestation token do not match with attributes in key transfer policy")
}

// validateMrSignerSeam - Function to Validate MrSignerSeam
func validateMrSignerSeam(tokenMrSignerSeam string, policyMrSignerSeam []string) bool {

	if tokenMrSignerSeam == "" {
		log.Error("MrSignerSeam is missing from attestation token")
		return false
	}

	if contains(policyMrSignerSeam, tokenMrSignerSeam) {
		log.Debug("MrSignerSeam in attestation token matches with the key transfer policy")
		return true
	}

	log.Error("MrSignerSeam in attestation token does not match with the key transfer policy")
	return false
}

// validateMrSeam - Function to Validate SeamMeasurement
func validateMrSeam(tokenMrSeam string, policyMrSeam []string) bool {

	if tokenMrSeam == "" {
		log.Error("Seam Measurement is missing from attestation token")
		return false
	}

	if contains(policyMrSeam, tokenMrSeam) {
		log.Debug("Seam Measurement in attestation token matches with the key transfer policy")
		return true
	}

	log.Error("Seam Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateSeamSvn- Function to Validate seamSvn
func validateSeamSvn(tokenSeamSvn uint8, policySeamSvn uint8) bool {

	if tokenSeamSvn == policySeamSvn {
		log.Debug("Seam Svn in attestation token matches with the key transfer policy")
		return true
	}
	log.Error("Seam Svn in attestation token does not match with the key transfer policy")
	return false
}

// validateMrTD - Function to Validate TDMeasurement
func validateMrTD(tokenMrTD string, policyMrTD []string) bool {

	if len(policyMrTD) == 0 {
		return true
	}

	if contains(policyMrTD, tokenMrTD) {
		log.Debug("TD Measurement in attestation token matches with the key transfer policy")
		return true
	}

	log.Error("TD Measurement in attestation token does not match with the key transfer policy")
	return false
}

// validateRTMR - Function to Validate RTMR
func validateRTMR(tokenRTMR string, policyRTMR string) bool {

	if policyRTMR == "" {
		return true
	}

	if tokenRTMR == policyRTMR {
		log.Debug("RTMR in attestation token matches with the key transfer policy")
		return true
	}

	log.Error("RTMR in attestation token does not match with the key transfer policy")
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
