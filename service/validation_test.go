/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/onsi/gomega"
	"intel/amber/kbs/v1/model"
	cns "intel/amber/kbs/v1/repository/mocks/constants"
	"testing"
)

var zeroVal uint16 = 0
var oneVal uint16 = 1

var zeroVal8 uint8 = 0
var oneVal8 uint8 = 1

func TestValidateAttestationTokenClaimsSGX(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	tmpId := uuid.New().String()
	policyReqJsonStr := string(`{
					"id": "` + tmpId + `",
					"attestation_type":[
                                           "SGX"
                                        ],
                                        "sgx":{
                                           "attributes":{
                                                  "mrsigner":[
                                                         "` + cns.ValidMrSigner + `"
                                                  ],
                                                  "isvprodid":[
                                                         1
                                                  ],
                                                  "mrenclave":[
						  	"` + cns.ValidMrEnclave + `"
                                                  ],
                                                  "isvsvn":1,
                                                  "client_permissions":[
                                                         "nginx",
                                                         "USA"
                                                  ],
                                                  "enforce_tcb_upto_date":true
                                           }
                                        }
				}`)

	tokenClaims := &model.AttestationTokenClaim{
		AmberSgxMrEnclave:    cns.ValidMrEnclave,
		AmberSgxMrSigner:     cns.ValidMrSigner,
		AmberSgxIsvproductId: &oneVal,
		AmberSgxIsvsvn:       &oneVal,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "SGX",
		Version:              "1",
	}
	transferPolicy := &model.KeyTransferPolicy{}

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberSgxMrEnclave:    "11c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
		AmberSgxMrSigner:     cns.ValidMrSigner,
		AmberSgxIsvproductId: &oneVal,
		AmberSgxIsvsvn:       &oneVal,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "SGX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberSgxMrEnclave:    cns.ValidMrEnclave,
		AmberSgxMrSigner:     "dd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
		AmberSgxIsvproductId: &oneVal,
		AmberSgxIsvsvn:       &oneVal,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "SGX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberSgxMrEnclave:    cns.ValidMrEnclave,
		AmberSgxMrSigner:     cns.ValidMrSigner,
		AmberSgxIsvproductId: &zeroVal,
		AmberSgxIsvsvn:       &oneVal,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "SGX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberSgxMrEnclave:    cns.ValidMrEnclave,
		AmberSgxMrSigner:     cns.ValidMrSigner,
		AmberSgxIsvproductId: &oneVal,
		AmberSgxIsvsvn:       &zeroVal,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "SGX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberSgxMrEnclave:    cns.ValidMrEnclave,
		AmberSgxMrSigner:     cns.ValidMrSigner,
		AmberSgxIsvproductId: &oneVal,
		AmberSgxIsvsvn:       &oneVal,
		AmberTcbStatus:       "OUT_OF_DATE",
		AmberEvidenceType:    "SGX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	policyReqJsonStr = string(`{
					"id": "` + tmpId + `",
					"attestation_type":[
                                           "SGX"
                                        ],
					"sgx":
					    "attributes" : {}
				}`)

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestValidateAttestationTokenClaimsTDX(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	policyReqJsonStr := `{
			"id": "3b9d565a-6ff5-4e5a-a0a8-64f3183d1722",
			"attestation_type": [
			  "TDX"
			],
			"tdx": {
				  "attributes": {
					    "mrsignerseam": ["` + cns.ValidMrSignerSeam + `"],
					    "mrseam": ["` + cns.ValidMrSeam + `"],
					    "seamsvn": 0,
					    "mrtd": ["` + cns.ValidMRTD + `"],
					    "rtmr0": "` + cns.ValidRTMR0 + `",
					    "rtmr1": "` + cns.ValidRTMR1 + `",
					    "rtmr2": "` + cns.ValidRTMR2 + `",
					    "rtmr3": "` + cns.ValidRTMR3 + `",
					    "enforce_tcb_upto_date": true
				    }
			}
		}`

	tokenClaims := &model.AttestationTokenClaim{
		AmberTdxMrSignerSeam: cns.ValidMrSignerSeam,
		AmberTdxMrSeam:       cns.ValidMrSeam,
		AmberTdxSeamSvn:      &zeroVal8,
		AmberTdxMRTD:         cns.ValidMRTD,
		AmberTdxRTMR0:        cns.ValidRTMR0,
		AmberTdxRTMR1:        cns.ValidRTMR1,
		AmberTdxRTMR2:        cns.ValidRTMR2,
		AmberTdxRTMR3:        cns.ValidRTMR3,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "TDX",
		Version:              "1",
	}
	transferPolicy := &model.KeyTransferPolicy{}

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberTdxMrSignerSeam: "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		AmberTdxMrSeam:       cns.ValidMrSeam,
		AmberTdxSeamSvn:      &zeroVal8,
		AmberTdxMRTD:         cns.ValidMRTD,
		AmberTdxRTMR0:        cns.ValidRTMR0,
		AmberTdxRTMR1:        cns.ValidRTMR1,
		AmberTdxRTMR2:        cns.ValidRTMR2,
		AmberTdxRTMR3:        cns.ValidRTMR3,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "TDX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberTdxMrSignerSeam: cns.ValidMrSignerSeam,
		AmberTdxMrSeam:       "1f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
		AmberTdxSeamSvn:      &zeroVal8,
		AmberTdxMRTD:         cns.ValidMRTD,
		AmberTdxRTMR0:        cns.ValidRTMR0,
		AmberTdxRTMR1:        cns.ValidRTMR1,
		AmberTdxRTMR2:        cns.ValidRTMR2,
		AmberTdxRTMR3:        cns.ValidRTMR3,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "TDX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberTdxMrSignerSeam: cns.ValidMrSignerSeam,
		AmberTdxMrSeam:       cns.ValidMrSeam,
		AmberTdxSeamSvn:      &oneVal8,
		AmberTdxMRTD:         cns.ValidMRTD,
		AmberTdxRTMR0:        cns.ValidRTMR0,
		AmberTdxRTMR1:        cns.ValidRTMR1,
		AmberTdxRTMR2:        cns.ValidRTMR2,
		AmberTdxRTMR3:        cns.ValidRTMR3,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "TDX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberTdxMrSignerSeam: cns.ValidMrSignerSeam,
		AmberTdxMrSeam:       cns.ValidMrSeam,
		AmberTdxSeamSvn:      &zeroVal8,
		AmberTdxMRTD:         "df656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
		AmberTdxRTMR0:        cns.ValidRTMR0,
		AmberTdxRTMR1:        cns.ValidRTMR1,
		AmberTdxRTMR2:        cns.ValidRTMR2,
		AmberTdxRTMR3:        cns.ValidRTMR3,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "TDX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberTdxMrSignerSeam: cns.ValidMrSignerSeam,
		AmberTdxMrSeam:       cns.ValidMrSeam,
		AmberTdxSeamSvn:      &zeroVal8,
		AmberTdxMRTD:         cns.ValidMRTD,
		AmberTdxRTMR0:        "d90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
		AmberTdxRTMR1:        cns.ValidRTMR1,
		AmberTdxRTMR2:        cns.ValidRTMR2,
		AmberTdxRTMR3:        cns.ValidRTMR3,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "TDX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberTdxMrSignerSeam: cns.ValidMrSignerSeam,
		AmberTdxMrSeam:       cns.ValidMrSeam,
		AmberTdxSeamSvn:      &zeroVal8,
		AmberTdxMRTD:         cns.ValidMRTD,
		AmberTdxRTMR0:        cns.ValidRTMR0,
		AmberTdxRTMR1:        "b53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9e",
		AmberTdxRTMR2:        cns.ValidRTMR2,
		AmberTdxRTMR3:        cns.ValidRTMR3,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "TDX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberTdxMrSignerSeam: cns.ValidMrSignerSeam,
		AmberTdxMrSeam:       cns.ValidMrSeam,
		AmberTdxSeamSvn:      &zeroVal8,
		AmberTdxMRTD:         cns.ValidMRTD,
		AmberTdxRTMR0:        cns.ValidRTMR0,
		AmberTdxRTMR1:        cns.ValidRTMR1,
		AmberTdxRTMR2:        "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		AmberTdxRTMR3:        cns.ValidRTMR3,
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "TDX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberTdxMrSignerSeam: cns.ValidMrSignerSeam,
		AmberTdxMrSeam:       cns.ValidMrSeam,
		AmberTdxSeamSvn:      &zeroVal8,
		AmberTdxMRTD:         cns.ValidMRTD,
		AmberTdxRTMR0:        cns.ValidRTMR0,
		AmberTdxRTMR1:        cns.ValidRTMR1,
		AmberTdxRTMR2:        cns.ValidRTMR2,
		AmberTdxRTMR3:        "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		AmberTcbStatus:       "OK",
		AmberEvidenceType:    "TDX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		AmberTdxMrSignerSeam: cns.ValidMrSignerSeam,
		AmberTdxMrSeam:       cns.ValidMrSeam,
		AmberTdxSeamSvn:      &zeroVal8,
		AmberTdxMRTD:         cns.ValidMRTD,
		AmberTdxRTMR0:        cns.ValidRTMR0,
		AmberTdxRTMR1:        cns.ValidRTMR1,
		AmberTdxRTMR2:        cns.ValidRTMR2,
		AmberTdxRTMR3:        cns.ValidRTMR3,
		AmberTcbStatus:       "OUT_OF_DATE",
		AmberEvidenceType:    "TDX",
		Version:              "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	policyReqJsonStr = `{
		"id": "3b9d565a-6ff5-4e5a-a0a8-64f3183d1722",
		"attestation_type": [
		  "TDX"
		],
		"tdx": {
			  "attributes": {}
		}
	}`

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestValidateAttestationTokenClaims(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	policyReqJsonStr := string(`{
		"attestation_type":[
							   "TPM"
							]
	}`)

	tokenClaims := &model.AttestationTokenClaim{}
	transferPolicy := &model.KeyTransferPolicy{}

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())
}
