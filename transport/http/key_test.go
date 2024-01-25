/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"bytes"
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/onsi/gomega"
	jwtStrategy "github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	"github.com/stretchr/testify/mock"
	"intel/kbs/v1/model"
	"intel/kbs/v1/service"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var (
	keeper = jwtStrategy.StaticSecret{
		ID:        "secret-id",
		Secret:    []byte("testSecret@#12"),
		Algorithm: jwtStrategy.HS384,
	}

	jwtAuth, _  = service.SetupAuthZ(&keeper)
	authToken   = getTokenForTesting()
	envelopeKey = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAr9Kz+bYryBDw4L9+sgpS
pGuQw+Nnk6FT7h6qpr35QgqmZgx5sK4+E3mbdQ5xGrc5sR7CxsAPHWjPf8ScFclK
KlfPG+8A/M7CpsJ9hJ7mLY7oNlTX1FBZOByTE1FtsNoR8nQBe9NMRL2PQF5dSO08
0J1vqOB+/hkZ1XCO/Pqiybg8VFPZiN7bLrx+Cii+3Wfsja1bxG2+IxWMtk949jBN
wKnctO2cKObF/KzQo7EDF3xiS/CeYRdKqh8k3i6HvjLibgmwT1S50EmytURDvPue
54Rhcr3xhHae++2pIZ0Fv8XJE9TiMUz2/L5jP3ipJxry6F/6kr/eAETaMeumsTiD
u0mDClZtWJQ+ewwWq3xrvj68/Qpub7aw+2Kus4JbzZG0BgiDd2aU2Smmg3UMq4QJ
MzMsWEYYiA/c1TDRXHAKeq+3oKjbUVlrmPUyMl0HX40am2FWdODBcw7qfb6RuSzw
hyYcKxrzDNcMfD+XUN5nNbEXQEnh6kyfw4mDS+XIb69nAgMBAAE=
-----END PUBLIC KEY-----`
)

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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusCreated))
}

func TestKeyCreateValidKeyData(t *testing.T) {
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
		      "key_length": 256,
		      "key_data": "YG2UtIG6OtaPjIIHQXJGxRmR0ozqiF3iQoVztc74ijo="
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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
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

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusOK))
}

func TestKeyTransferHandlerInvalidContReq(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyTransferRes := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKey", mock.Anything, mock.Anything).Return(keyTransferRes, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}
	err := setKeyHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String(), bytes.NewReader([]byte("")))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", "plain/text")
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestKeyTransferHandlerEmptyReq(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyTransferRes := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKey", mock.Anything, mock.Anything).Return(keyTransferRes, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String(), bytes.NewReader([]byte("")))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypePem)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyTransferHandlerInvalidReq(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyTransferRes := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKey", mock.Anything, mock.Anything).Return(keyTransferRes, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyPem := strings.Replace(strings.Replace(string(envelopeKey), "-----BEGIN PUBLIC KEY-----\n", "", 1), "-----END PUBLIC KEY-----", "", 1)

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String(), bytes.NewReader([]byte(keyPem)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypePem)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyTransferHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyTransferRes := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKey", mock.Anything, mock.Anything).Return(keyTransferRes, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String(), bytes.NewReader([]byte(envelopeKey)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypePem)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusOK))
}

func TestKeyTransferInvalidKeyData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	keyTransferRes := &service.TransferKeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("TransferKey", mock.Anything, mock.Anything).Return(keyTransferRes, nil)
	handler := createMockHandler(mockService)

	err := setKeyHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	keyPem := `-----BEGIN PUBLIC KEY-----
	-----END PUBLIC KEY-----`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/keys/"+keyId.String(), bytes.NewReader([]byte(keyPem)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypePem)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyUpdateHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.KeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("UpdateKey", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setKeyHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	updateReqBody := `{
		"transfer_policy_id" : "43972e48-67c6-4b00-bd01-924f62751d1d"
        }`
	req, _ := http.NewRequest(http.MethodPut, "/kbs/v1/keys/"+keyId.String(), bytes.NewReader([]byte(updateReqBody)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusCreated))
}

func TestKeyUpdateHandlerInvalidPolicy(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.KeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("UpdateKey", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setKeyHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	updateReqBody := `{
		"transfer_policy_id" : "43972e48-67c6-4b00"
        }`
	req, _ := http.NewRequest(http.MethodPut, "/kbs/v1/keys/"+keyId.String(), bytes.NewReader([]byte(updateReqBody)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestKeyUpdateHandlerInvalidContentTypeHeader(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.KeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("UpdateKey", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setKeyHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	updateReqBody := `{
		"transfer_policy_id" : "43972e48-67c6-4b00-bd01-924f62751d1d"
        }`
	req, _ := http.NewRequest(http.MethodPut, "/kbs/v1/keys/"+keyId.String(), bytes.NewReader([]byte(updateReqBody)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestKeyUpdateHandlerInvalidAcceptHeader(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.KeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("UpdateKey", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setKeyHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	updateReqBody := `{
		"transfer_policy_id" : "43972e48-67c6-4b00-bd01-924f62751d1d"
        }`
	req, _ := http.NewRequest(http.MethodPut, "/kbs/v1/keys/"+keyId.String(), bytes.NewReader([]byte(updateReqBody)))
	req.Header.Set("Content-Type", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestKeyUpdateHandlerInvalidTokenHeader(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.KeyResponse{}

	keyId := uuid.New()

	mockService := &MockService{}
	mockService.On("UpdateKey", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setKeyHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	updateReqBody := `{
		"transfer_policy_id" : "43972e48-67c6-4b00-bd01-924f62751d1d"
        }`
	req, _ := http.NewRequest(http.MethodPut, "/kbs/v1/keys/"+keyId.String(), bytes.NewReader([]byte(updateReqBody)))
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Content-type", HTTPMediaTypeJson)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	res := recorder.Result()
	defer res.Body.Close()

	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnauthorized))
}
