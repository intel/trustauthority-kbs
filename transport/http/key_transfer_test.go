/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"intel/kbs/v1/constant"
	"intel/kbs/v1/service"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/onsi/gomega"
	"github.com/shaj13/go-guardian/v2/auth"
	jwtStrategy "github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	"github.com/stretchr/testify/mock"
)

func TestKeyTransferWithEvidenceHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKeyWithEvidence", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String()+"/transfer", nil)
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Attestion-type", "SGX")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusOK))
}

func TestKeyTransferWithEvidenceRequiresTransferPermission(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyID := uuid.New()

	keyCreateOnlyUser := auth.NewUserInfo("keyCreator", "keyCreator", nil, nil)
	scopes := jwtStrategy.SetNamedScopes(constant.KeyCreate)
	expiration := jwtStrategy.SetExpDuration(time.Duration(constant.DefaultTokenExpiration) * time.Minute)
	keyCreateOnlyToken, err := jwtStrategy.IssueAccessToken(keyCreateOnlyUser, jwtAuth.JwtSecretKeeper, scopes, expiration)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	handler := createMockHandler(&MockService{})
	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyID.String()+"/transfer", nil)
	req.Header.Set("Authorization", "Bearer "+keyCreateOnlyToken)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-Type", HTTPMediaTypeJson)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnauthorized))
}

func TestKeyTransferWithInvalidAcceptHeader(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKeyWithEvidence", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	transferJson := `{
		"quote": "",
		"nonce": "",
		"user_data": ""
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String()+"/transfer", bytes.NewReader([]byte(transferJson)))
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", "plain/text")
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Attestion-type", "SGX")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestKeyTransferWithInvalidContentTypeHeader(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKeyWithEvidence", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	transferJson := `{
		"quote": "",
		"nonce": "",
		"user_data": ""
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String()+"/transfer", bytes.NewReader([]byte(transferJson)))
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", "plain/text")
	req.Header.Set("Attestion-type", "SGX")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestKeyTransferInvalidAttestionType(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKeyWithEvidence", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	transferJson := `{
		"quote": "",
		"user_data": ""
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String()+"/transfer", bytes.NewReader([]byte(transferJson)))
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Attestation-Type", "invalid")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyTransferwithNilPostData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKeyWithEvidence", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	transferJson := `{
		"quote": "",
		"user_data": ""
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String()+"/transfer", bytes.NewReader([]byte(transferJson)))
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	//req.Header.Set("Attestation-Type", "SGX")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyTransferInvalidPostData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKeyWithEvidence", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	transferJson := `{indfsafdas:"dfasdfsddf"}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String()+"/transfer", bytes.NewReader([]byte(transferJson)))
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Attestation-Type", "SGX")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}
