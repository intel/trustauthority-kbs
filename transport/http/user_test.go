/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */

package http

import (
	"bytes"
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"intel/kbs/v1/model"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserDeleteHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.UserResponse{}

	userId := uuid.New()

	mockService := &MockService{}
	mockService.On("RetrieveUser", mock.Anything, mock.Anything).Return(resp, nil)
	mockService.On("DeleteUser", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setUserHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodDelete, "/kbs/v1/users/"+userId.String(), nil)
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

func TestUserSearchHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var resp []model.UserResponse

	mockService := &MockService{}
	mockService.On("SearchUser", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setUserHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/users", nil)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)
	q := req.URL.Query()
	q.Add(Username, "admin")
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

func TestUserSearchHandlerInvalidHeaders(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var resp []model.UserResponse

	mockService := &MockService{}
	mockService.On("SearchUser", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setUserHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/users", nil)
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Authorization", "Bearer "+authToken)
	q := req.URL.Query()
	q.Add(Username, "admin")
	req.URL.RawQuery = q.Encode()

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

func TestUserSearchHandlerInvalidQueryParam(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	var resp []model.UserResponse

	mockService := &MockService{}
	mockService.On("SearchUser", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	err := setUserHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/users", nil)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+authToken)
	q := req.URL.Query()
	// invalid query param
	q.Add("Usernames", "admin")
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

func TestUserCreateHandlerInvalidHeaders(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	userInfo := &model.UserResponse{}

	mockService := &MockService{}
	mockService.On("CreateUser", mock.Anything, mock.Anything).Return(userInfo, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}
	err := setUserHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/users", bytes.NewReader([]byte("")))
	// invalid Content-type header
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

	// invalid Accept header
	req.Header.Set("Accept", "plain/text")
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
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestUserCreateHandlerEmptyRequest(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	userCreateRes := &model.UserResponse{}

	mockService := &MockService{}
	mockService.On("CreateUser", mock.Anything, mock.Anything).Return(userCreateRes, nil)
	handler := createMockHandler(mockService)

	err := setUserHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/users", bytes.NewReader([]byte("")))
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

func TestUserCreateHandlerInvalidRequest(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	userCreateRes := &model.UserResponse{}

	mockService := &MockService{}
	mockService.On("CreateUser", mock.Anything, mock.Anything).Return(userCreateRes, nil)
	handler := createMockHandler(mockService)

	err := setUserHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// invalid permissions
	user := `{
               "username": "123",
               "password": "password",
               "permissions": ["userss:create"]
             }`
	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/users", bytes.NewReader([]byte(user)))
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

	// invalid permissions format
	user = `{
              "username": "123",
              "password": "password",
              "permissions": ["users"]
             }`
	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/users", bytes.NewReader([]byte(user)))
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

	// invalid username
	user = `{
              "username": "#####",
              "password": "password",
              "permissions": ["users:create"]
            }`
	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/users", bytes.NewReader([]byte(user)))
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

	// invalid password
	user = `{
              "username" : "adminUsername",
              "password": "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",
              "permissions" : ["keys:create"]
            }`
	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/users", bytes.NewReader([]byte(user)))
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

	// invalid json body
	user = `{
              "username": "adminUsername",
              "password": "password",
              "permission": ["users:create"]
            }`
	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/users", bytes.NewReader([]byte(user)))
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

func TestUserCreateHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	userInfo := &model.UserResponse{}

	mockService := &MockService{}
	mockService.On("CreateUser", mock.Anything, mock.Anything).Return(userInfo, nil)
	handler := createMockHandler(mockService)

	err := setUserHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	user := `{
               "username": "userName",
               "password": "password@123",
                "permissions": ["users:create"]
             }`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/users", bytes.NewReader([]byte(user)))
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

func TestUserUpdateHandlerInvalidHeaders(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	userInfo := &model.UserResponse{}

	mockService := &MockService{}
	mockService.On("UpdateUser", mock.Anything, mock.Anything).Return(userInfo, nil)
	handler := createMockHandler(mockService)

	userId := uuid.New()
	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}
	err := setUserHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPut, "/kbs/v1/users/"+userId.String(), bytes.NewReader([]byte("")))
	// invalid Content-type header
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

	// invalid Accept header
	req.Header.Set("Accept", "plain/text")
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
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))
}

func TestUpdateHandlerEmptyUserId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	userCreateRes := &model.UserResponse{}

	mockService := &MockService{}
	mockService.On("UpdateUser", mock.Anything, mock.Anything).Return(userCreateRes, nil)
	handler := createMockHandler(mockService)

	err := setUserHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPut, "/kbs/v1/users/", bytes.NewReader([]byte("")))
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
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusNotFound))
}

func TestUserUpdateHandlerInvalidRequest(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	userCreateRes := &model.UserResponse{}

	mockService := &MockService{}
	mockService.On("UpdateUser", mock.Anything, mock.Anything).Return(userCreateRes, nil)
	handler := createMockHandler(mockService)
	userId := uuid.New().String()

	err := setUserHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// invalid permissions
	user := `
			{
				"permissions": ["userss:create"]
			}`
	req, _ := http.NewRequest(http.MethodPut, "/kbs/v1/users/"+userId, bytes.NewReader([]byte(user)))
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

	// invalid password
	user = `{
               "password": "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"
            }`
	req, _ = http.NewRequest(http.MethodPut, "/kbs/v1/users/"+userId, bytes.NewReader([]byte(user)))
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

	// invalid username
	user = `{
               "username": "###"
            }`
	req, _ = http.NewRequest(http.MethodPut, "/kbs/v1/users/"+userId, bytes.NewReader([]byte(user)))
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

	// invalid json body
	user = `{
               "permission": ["users:create"]
            }`
	req, _ = http.NewRequest(http.MethodPost, "/kbs/v1/users", bytes.NewReader([]byte(user)))
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

func TestUserUpdateHandlerEmptyRequest(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	userInfo := &model.UserResponse{}

	mockService := &MockService{}
	mockService.On("UpdateUser", mock.Anything, mock.Anything).Return(userInfo, nil)
	handler := createMockHandler(mockService)
	userId := uuid.New().String()

	err := setUserHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPut, "/kbs/v1/users/"+userId, bytes.NewReader([]byte("")))
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

func TestUserUpdateHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	userInfo := &model.UserResponse{}

	mockService := &MockService{}
	mockService.On("UpdateUser", mock.Anything, mock.Anything).Return(userInfo, nil)
	handler := createMockHandler(mockService)
	userId := uuid.New().String()

	err := setUserHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	user := `{
               "username": "UpdatedUsername"
             }`

	req, _ := http.NewRequest(http.MethodPut, "/kbs/v1/users/"+userId, bytes.NewReader([]byte(user)))
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

func TestUserRetrieveHandler(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.UserResponse{}

	userId := uuid.New()

	mockService := &MockService{}
	mockService.On("RetrieveUser", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setUserHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/users/"+userId.String(), nil)
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

func TestUserRetrieveHandlerWithNoAuth(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.UserResponse{}

	userId := uuid.New()

	mockService := &MockService{}
	mockService.On("RetrieveUser", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setUserHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/users/"+userId.String(), nil)
	req.Header.Set("Accept", HTTPMediaTypeJson)
	req.Header.Set("Authorization", "Bearer "+"")

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

func TestUserRetrieveHandlerWithInvalidHeader(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	resp := &model.UserResponse{}

	userId := uuid.New()

	mockService := &MockService{}
	mockService.On("RetrieveUser", mock.Anything, mock.Anything).Return(resp, nil)
	handler := createMockHandler(mockService)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	err := setUserHandler(mockService, mux.NewRouter(), options, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodGet, "/kbs/v1/users/"+userId.String(), nil)
	req.Header.Set("Accept", HTTPMediaTypeJWT)
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
