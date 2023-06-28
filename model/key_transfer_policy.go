/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package model

import (
	"github.com/google/uuid"
	"time"
)

type KeyTransferPolicy struct {
	// Universal Unique IDentifier of the Key Transfer Policy created
	// required: true
	// example: 4517534b-a758-4447-7d2f-3e5606152ed6
	ID uuid.UUID `json:"id,omitempty"`
	// Asset creation time
	// example: 0001-01-01T00:00:00Z
	CreatedAt time.Time `json:"created_at,omitempty"`
	// Defines if SGX\TDX Attributes need to be part of key Transfer Policy
	// required: true
	// example: [ { "SGX" } ]
	AttestationType []AttestationType `json:"attestation_type"`
	// List of SGX Enclave Attributes that are part of Enclave
	SGX *SgxPolicy `json:"sgx,omitempty"`
	// List of TDX TD Attributes that are part of TDX Policy
	TDX *TdxPolicy `json:"tdx,omitempty"`
}

type SgxPolicy struct {
	// Attributes that define SGX Enclave information
	Attributes *SgxAttributes `json:"attributes,omitempty"`
	// List of Policy IDs which are evaluated before key is distributed
	// example: [ 4517534b-a758-4447-7d2f-3e5606152ed6, 34568456-2398-3875-7453-395766152ed6 ]
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
}

type SgxAttributes struct {
	// Hash of the key used to sign the SGX Enclave
	// example: 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
	MrSigner []string `json:"mrsigner,omitempty"`
	// Product ID Specific to the workload running the SGX enclave
	// example: [ 0001, 0002 ]
	IsvProductId []uint16 `json:"isvprodid,omitempty"`
	// Hash of the Contents of the SGX Enclave
	// example: ad46749ed41ebaa2327252041ee746d3791a9f2431830fee0883f7993caf316a
	MrEnclave []string `json:"mrenclave,omitempty"`
	// The Security Version Number of the Enclave
	// example: 00
	IsvSvn *uint16 `json:"isvsvn,omitempty"`
	// List of permission set required by the workload
	// example: [ "nginx" , "US" ]
	ClientPermissions []string `json:"client_permissions,omitempty"`
	// Should policy engine enforce TCB upto-date status as part of SGX Attestation
	// example: true
	EnforceTCBUptoDate *bool `json:"enforce_tcb_upto_date,omitempty"`
}

type TdxPolicy struct {
	// Attributes that define TDX Trusted Domain
	Attributes *TdxAttributes `json:"attributes,omitempty"`
	// List of Policy IDs which are evaluated before key is distributed
	// example: [ 4517534b-a758-4447-7d2f-3e5606152ed6, 34568456-2398-3875-7453-395766152ed6 ]
	PolicyIds []uuid.UUID `json:"policy_ids,omitempty"`
}

type TdxAttributes struct {
	// Hash of the key used to sign the TDX SEAM Module
	// example: 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
	MrSignerSeam []string `json:"mrsignerseam,omitempty"`
	// Hash of the Contents of the TDX SEAM Module
	// example: 0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe
	MrSeam []string `json:"mrseam,omitempty"`
	// The Security Version Number of the TDX SEAM Module
	// example: 00
	SeamSvn *uint8 `json:"seamsvn,omitempty"`
	// SHA-384 measurement of a TD, accumulated during TD build.
	// example: df656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50
	MRTD []string `json:"mrtd,omitempty"`
	// A SHA-384 measurement register that can be updated during TD run-time
	// example: b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14
	RTMR0 string `json:"rtmr0,omitempty"`
	// A SHA-384 measurement register that can be updated during TD run-time
	// example: a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b
	RTMR1 string `json:"rtmr1,omitempty"`
	// A SHA-384 measurement register that can be updated during TD run-time
	// example: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	RTMR2 string `json:"rtmr2,omitempty"`
	// A SHA-384 measurement register that can be updated during TD run-time
	// example: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	RTMR3 string `json:"rtmr3,omitempty"`
	// Should policy engine enforce TCB upto-date status as part of TDX Attestation
	// example: true
	EnforceTCBUptoDate *bool `json:"enforce_tcb_upto_date,omitempty"`
}

type KeyTransferPolicyFilterCriteria struct {
}
