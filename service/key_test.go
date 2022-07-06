/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"intel/amber/kbs/v1/clients/as"
	"intel/amber/kbs/v1/jwt"
	"intel/amber/kbs/v1/keymanager"
	"intel/amber/kbs/v1/kmipclient"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/repository"
	"intel/amber/kbs/v1/repository/mocks"
	"testing"
)

var gKeyId uuid.UUID
var rsaKeyId uuid.UUID
var asClient *as.MockClient = as.NewMockClient()
var jwtVerifier *jwt.MockVerifier = jwt.NewMockVerifier()
var keyStore *mocks.MockKeyStore = mocks.NewFakeKeyStore()
var keyTransPolicyStore *mocks.MockKeyTransferPolicyStore = mocks.NewFakeKeyTransferPolicyStore()
var kmipClient kmipclient.MockKmipClient = kmipclient.MockKmipClient{}
var kmipKeyManager *keymanager.MockKmipManager = keymanager.NewMockKmipManager(kmipClient)
var kRemoteManager *keymanager.RemoteManager = keymanager.NewRemoteManager(keyStore, kmipKeyManager)
var svcInstance Service = service{
	asClient:    asClient,
	jwtVerifier: jwtVerifier,
	repository: &repository.Repository{
		KeyStore:               keyStore,
		KeyTransferPolicyStore: keyTransPolicyStore,
	},
	remoteManager: kRemoteManager,
}
var key = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

func TestKeyRegister(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyId := uuid.New()
	keyAttr := model.KeyAttributes{
		ID:               keyId,
		Algorithm:        "AES",
		KeyLength:        128,
		KmipKeyID:        "6",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "/kbs/v1/keys/" + keyId.String() + "/transfer",
	}
	kmipKeyManager.On("RegisterKey", mock.Anything).Return(&keyAttr, nil).Once()

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.KeyRequest{}
	keyJson := `{
                 "key_information": {
		      "kmip_key_id": "6",
                      "algorithm": "AES",
                      "key_length": 128
                  }
        }`

	json.Unmarshal([]byte(keyJson), &request)
	keyResponse, err := svc.CreateKey(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	gKeyId = keyResponse.ID
}

func TestKeyAES256Create(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	keyAttr := model.KeyAttributes{
		ID:               uuid.MustParse("186d560f-95d5-4d39-92cc-f67e989d2e55"),
		Algorithm:        "AES",
		KeyLength:        256,
		KmipKeyID:        "1",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "/kbs/v1/keys/186d560f-95d5-4d39-92cc-f67e989d2e55/transfer",
	}
	kmipKeyManager.On("CreateKey", mock.Anything).Return(&keyAttr, nil).Once()

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.KeyRequest{}
	keyJson := `{
                 "key_information": {
                      "algorithm": "AES",
                      "key_length": 256
                  }
        }`

	json.Unmarshal([]byte(keyJson), &request)
	_, err := svc.CreateKey(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestKeyRetrieve(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	_, err := svc.RetrieveKey(context.Background(), gKeyId)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestKeyDelete(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	kmipKeyManager.On("DeleteKey", mock.Anything).Return(nil).Once()

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	_, err := svc.DeleteKey(context.Background(), gKeyId)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestKeySearchWithNilCriteriaObject(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	_, err := svc.SearchKeys(context.Background(), nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
func TestKeySearch(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	crit := model.KeyFilterCriteria{
		Algorithm: "AES",
		KeyLength: 256,
	}

	_, err := svc.SearchKeys(context.Background(), &crit)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestKeyRSARegister(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyId := uuid.New()

	keyAttr := model.KeyAttributes{
		ID:               keyId,
		Algorithm:        "RSA",
		KeyLength:        3072,
		KmipKeyID:        "5",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "/kbs/v1/keys/" + keyId.String() + "/transfer",
	}
	kmipKeyManager.On("RegisterKey", mock.Anything).Return(&keyAttr, nil).Once()

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.KeyRequest{}
	keyJson := `{
                 "key_information": {
		      "kmip_key_id": "5",
                      "algorithm": "RSA",
                      "key_length": 3072,
		      "key_data": ""
                  }
        }`

	json.Unmarshal([]byte(keyJson), &request)
	keyResponse, err := svc.CreateKey(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	rsaKeyId = keyResponse.ID
}

func TestKeyECRegister(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyId := uuid.New()

	keyAttr := model.KeyAttributes{
		ID:               keyId,
		Algorithm:        "EC",
		CurveType:        "secp256r1",
		KmipKeyID:        "6",
		TransferPolicyId: uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		TransferLink:     "/kbs/v1/keys/" + keyId.String() + "/transfer",
	}
	kmipKeyManager.On("RegisterKey", mock.Anything).Return(&keyAttr, nil).Once()

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.KeyRequest{}
	keyJson := `{
                 "key_information": {
		      "kmip_key_id": "6",
                      "algorithm": "EC",
                      "curve_type": "secp256r1"
                  }
        }`

	json.Unmarshal([]byte(keyJson), &request)
	_, err := svc.CreateKey(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
func TestKeyRetrieveInvalidKey(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	keyId := uuid.New()
	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	_, err := svc.RetrieveKey(context.Background(), keyId)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestKeyDeleteInvalidKey(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	keyId := uuid.New()
	kmipKeyManager.On("DeleteKey", mock.Anything).Return(nil).Once()

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	_, err := svc.DeleteKey(context.Background(), keyId)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestKeyRegisterInvalidTransferPolicy(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	tPolicyid := uuid.New()

	keyAttr := model.KeyAttributes{
		Algorithm:        "AES",
		KeyLength:        256,
		KmipKeyID:        "1",
		TransferPolicyId: tPolicyid,
		TransferLink:     "/kbs/v1/keys/186d560f-95d5-4d39-92cc-f67e989d2e55/transfer",
	}
	kmipKeyManager.On("RegisterKey", mock.Anything).Return(&keyAttr, nil).Once()

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.KeyRequest{}
	keyJson := `{
		"transfer_policy_id": "` + tPolicyid.String() + `",
                 "key_information": {
		      "kmip_key_id": "1",
                      "algorithm": "AES",
                      "key_length": 256
                  }
        }`

	json.Unmarshal([]byte(keyJson), &request)
	_, err := svc.CreateKey(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}