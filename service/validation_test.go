/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/onsi/gomega"
	"intel/kbs/v1/model"
	cns "intel/kbs/v1/repository/mocks/constants"
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
					"attestation_type": "SGX",
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
                                                  "enforce_tcb_upto_date":true
                                           }
                                        }
				}`)

	tokenClaims := &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}
	transferPolicy := &model.KeyTransferPolicy{}

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: "11c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953",
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  "dd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f",
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: zeroVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    zeroVal,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "SGX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		SGXClaims: &model.SGXClaims{
			SgxMrEnclave: cns.ValidMrEnclave,
			SgxMrSigner:  cns.ValidMrSigner,
			SgxIsvProdId: oneVal,
			SgxIsvSvn:    oneVal,
		},
		AttesterTcbStatus: "OUT_OF_DATE",
		AttesterType:      "SGX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	policyReqJsonStr = string(`{
					"id": "` + tmpId + `",
					"attestation_type":"SGX",
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
			"attestation_type": "TDX",
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
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal8,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}
	transferPolicy := &model.KeyTransferPolicy{}

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal8,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       "1f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe",
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal8,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      oneVal8,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         "df656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50",
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal8,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        "d90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal8,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        "b53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9e",
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal8,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal8,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			TdxSeamSvn:      zeroVal8,
		},
		AttesterTcbStatus: "OK",
		AttesterType:      "TDX",
		Version:           "1",
	}

	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	tokenClaims = &model.AttestationTokenClaim{
		TDXClaims: &model.TDXClaims{
			TdxMrSeam:       cns.ValidMrSeam,
			TdxMrSignerSeam: cns.ValidMrSignerSeam,
			TdxMRTD:         cns.ValidMRTD,
			TdxRTMR0:        cns.ValidRTMR0,
			TdxRTMR1:        cns.ValidRTMR1,
			TdxRTMR2:        cns.ValidRTMR2,
			TdxRTMR3:        cns.ValidRTMR3,
			TdxSeamSvn:      zeroVal8,
		},
		AttesterTcbStatus: "OUT_OF_DATE",
		AttesterType:      "TDX",
		Version:           "1",
	}
	err = validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())

	policyReqJsonStr = `{
		"id": "3b9d565a-6ff5-4e5a-a0a8-64f3183d1722",
		"attestation_type": "TDX",
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
		"attestation_type":"TPM"
	}`)

	tokenClaims := &model.AttestationTokenClaim{}
	transferPolicy := &model.KeyTransferPolicy{}

	json.Unmarshal([]byte(policyReqJsonStr), transferPolicy)
	err := validateAttestationTokenClaims(tokenClaims, transferPolicy)
	g.Expect(err).To(gomega.HaveOccurred())
}
