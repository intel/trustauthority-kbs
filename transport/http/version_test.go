/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package http

import (
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"intel/kbs/v1/version"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/version", nil)

	recorder := httptest.NewRecorder()

	mockService := &MockService{}
	handler := createMockHandler(mockService)
	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	resp := &version.ServiceVersion{}
	mockService.On("GetVersion", mock.Anything).Return(resp, nil)
	err := setGetVersionHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())
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
