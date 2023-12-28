/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/onsi/gomega"
	"intel/kbs/v1/model"
	cns "intel/kbs/v1/repository/mocks/constants"
	"testing"
)

var transferPolicyId uuid.UUID

func TestTransferPolicyCreate(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

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
                                                  "enforce_tcb_upto_date":false
                                           }
                                        }
				}`)

	request := model.KeyTransferPolicy{}
	json.Unmarshal([]byte(policyReqJsonStr), &request)
	response, err := svc.CreateKeyTransferPolicy(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	transferPolicyId = response.ID
}
func TestTransferPolicySearch(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := &model.KeyTransferPolicyFilterCriteria{}
	_, err := svc.SearchKeyTransferPolicies(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestTransferPolicyRetrieve(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	_, err := svc.RetrieveKeyTransferPolicy(context.Background(), transferPolicyId)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
func TestTransferPolicyRetrieveInvalidId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	tmpId := uuid.New()
	_, err := svc.RetrieveKeyTransferPolicy(context.Background(), tmpId)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestTransferPolicyDelete(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	_, err := svc.DeleteKeyTransferPolicy(context.Background(), transferPolicyId)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestTransferPolicyDeleteInvalidId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	tmpId := uuid.New()
	_, err := svc.DeleteKeyTransferPolicy(context.Background(), tmpId)
	g.Expect(err).To(gomega.HaveOccurred())
}
