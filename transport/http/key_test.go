/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package http

import (
	"bytes"
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/service"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

var jwtAuth = service.SetupGoguardianForTest()
var authToken = getTokenForTesting()

func TestKeyDeleteHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.KeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("RetrieveKey", mock.Anything, mock.Anything).Return(resp, nil)
	mockService.On("DeleteKey", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setKeyHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodDelete, "/kbs/v1/keys/"+keyId.String(), nil)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusNoContent))
}

func TestKeySearchHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var resp []*model.KeyResponse

	mockService := &MockService{}
	mockService.On("SearchKeys", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/keys", nil)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)
	q := req.URL.Query()
	q.Add(Algorithm, "AES")
	q.Add(KeyLength, "128")
	req.URL.RawQuery = q.Encode()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusOK))
}

func TestKeyCreateHandlerInvalidContReq(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyCreateRes := &model.KeyResponse{}

	mockService := &MockService{}
	mockService.On("CreateKey", mock.Anything, mock.Anything).Return(keyCreateRes, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}
	err := setKeyHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys", bytes.NewReader([]byte("")))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", "plain/text")
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestKeyCreateHandlerEmptyReq(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyCreateRes := &model.KeyResponse{}

	mockService := &MockService{}
	mockService.On("CreateKey", mock.Anything, mock.Anything).Return(keyCreateRes, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys", bytes.NewReader([]byte("")))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyCreateHandlerInvalidReq(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyCreateRes := &model.KeyResponse{}

	mockService := &MockService{}
	mockService.On("CreateKey", mock.Anything, mock.Anything).Return(keyCreateRes, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{
		"key_information":{
                      "algorithm": "invalidalgo",
                      "key_length": 128
		}
        }`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
	keyJson = `{
		"key_information":{
                      "algorithm": "AES",
                      "key_length": 1284
		}
        }`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/keys", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
	keyJson = `{
		"key_information":{
                      "algorithm": "EC",
                      "curve_type": "secp256",
		      "kmip_key_id": "111",
		      "key_data": "invalidddddddddkeydata"
		}
        }`

	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/keys", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res = recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyCreateHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyCreateRes := &model.KeyResponse{}

	mockService := &MockService{}
	mockService.On("CreateKey", mock.Anything, mock.Anything).Return(keyCreateRes, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{
		"key_information":{
                      "algorithm": "AES",
                      "key_length": 128
		}
        }`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusCreated))
}

func TestKeyCreateInvalidKeyData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyCreateRes := &model.KeyResponse{}

	mockService := &MockService{}
	mockService.On("CreateKey", mock.Anything, mock.Anything).Return(keyCreateRes, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyJson := `{
		"key_information":{
		      "algorithm": "RSA",
		      "key_length": 3072,
		      "key_data": "invalidpemdata$$$$%"
		}
        }`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys", bytes.NewReader([]byte(keyJson)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeySearchHandlerInvalidECCriteria(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var resp []*model.KeyResponse

	mockService := &MockService{}
	mockService.On("SearchKeys", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/keys", nil)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	q := req.URL.Query()
	q.Add(Algorithm, "EC")
	q.Add(KeyLength, "sepc256")
	req.URL.RawQuery = q.Encode()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeySearchHandlerInvalidECData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var resp []*model.KeyResponse

	mockService := &MockService{}
	mockService.On("SearchKeys", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setKeyHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/keys", nil)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	q := req.URL.Query()
	q.Add(Algorithm, "EC")
	q.Add(CurveType, "sepc256")
	req.URL.RawQuery = q.Encode()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyRetrieveHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.KeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("RetrieveKey", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setKeyHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/keys/"+keyId.String(), nil)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusOK))
}
