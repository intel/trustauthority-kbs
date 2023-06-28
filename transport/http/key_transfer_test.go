/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package http

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"intel/amber/kbs/v1/service"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/onsi/gomega"
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
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Attestion-type", "SGX")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusOK))
}

func TestKeyTransferWithInvalidHeader(t *testing.T) {
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
		"signed_nonce": "",
		"user_data": ""
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String()+"/transfer", bytes.NewReader([]byte(transferJson)))
	req.Header.Set("Accept", "plain/text")
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Attestion-type", "SGX")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
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
		"signed_nonce": "",
		"user_data": ""
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String()+"/transfer", bytes.NewReader([]byte(transferJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Attestation-Type", "invalid")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
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
		"signed_nonce": "",
		"user_data": ""
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String()+"/transfer", bytes.NewReader([]byte(transferJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Attestation-Type", "SGX")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
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
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Attestation-Type", "SGX")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	t.Log("Response: ", string(data))
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}
