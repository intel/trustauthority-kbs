/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package http

import (
	"bytes"
	"github.com/gorilla/mux"
	"github.com/onsi/gomega"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/service"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateJWTToken(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mockService := &MockService{}
	mockService.On("CreateAuthToken", mock.Anything, mock.Anything).Return("eyJhbGciOiJQUzM4NCIsImtpZCI6InNlY3JldC1pZCIsInR5cCI6IkpXVCJ9.eyJFeHRlbnNpb25zIjpudWxsLCJHcm91cHMiOm51bGwsIklEIjoiMTk0ZmE4NTItMzk1Ny00YzU4LThjZTYtMGU5ZjUzNmJlYWViIiwiTmFtZSI6ImFkbWluIiwiYXVkIjpbIiJdLCJleHAiOjE2NTg1MzYwNDgsImlhdCI6MTY1ODUzMjQ0OCwibmJmIjoxNjU4NTMyNDQ4LCJzY29wZSI6WyJrZXlzOnNlYXJjaCIsImtleXM6Y3JlYXRlIiwia2V5czpkZWxldGUiLCJrZXlfdHJhbnNmZXJfcG9saWNpZXM6Y3JlYXRlIiwia2V5X3RyYW5zZmVyX3BvbGljaWVzOnNlYXJjaCIsImtleV90cmFuc2Zlcl9wb2xpY2llczpkZWxldGUiLCJ1c2VyczpkZWxldGUiLCJ1c2VyczpzZWFyY2giLCJ1c2VyczpjcmVhdGUiLCJ1c2Vyczp1cGRhdGUiXSwic3ViIjoiMTk0ZmE4NTItMzk1Ny00YzU4LThjZTYtMGU5ZjUzNmJlYWViIn0.BeN32PkOb8L7o4hpbONP1VCFT4WjKkBcAhZ6AsXAoV061z_HpELnLDcGqQvwwVdn95o99n5WMhq1HnSuUlpsWb-YrTcL5cYlHgFZkpKE3FA2y_owagxvtMSdlsTPmEa6g8DIoFX0HgWi7ZIXQOwmzefOmvIOrkjfVv18JOyu12AE6-HpAvmhRcWEQOZdMUjEjIcINvWIialVG1L7Re2HJngbZL1EEVt1ow_giBMkUiIrnImQQ6eoasW063trVQNjdDowlfrDpCPBX026vfRl9666DnsHVHRPMH6HSpiMx34aIWPDaP9LkZE_Z-BZaIlrhV9EJ3UguAnGXhvCt8JRrc9eKGfjQ7t4PL998XtekssHxu0W9KpyyclclFbdQPZ_6ErlqRLC14Hzex1LYfE-Es-0KrA1GVM06FMWZ6Y4ge3acQ8OxVKPZagBaJ5d5S4-PiRKZU_aYCzqcdtd1rrg9aWgNv7UCAV7uVnBgklw8Obat_4FjSU4ECzqlkxkap2j", nil)
	handler := createMockHandler(mockService)

	err := setCreateAuthTokenHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	userCreds := `{
		"username": "admin",
		"password": "password"
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/token", bytes.NewReader([]byte(userCreds)))
	req.Header.Set("Accept", HTTPMediaTypeJWT)
	req.Header.Set("Content-type", HTTPMediaTypeJson)

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

func TestCreateJWTTokenInvalidHeaders(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mockService := &MockService{}
	mockService.On("CreateAuthToken", mock.Anything, mock.Anything).Return("eyJhbGciOiJQUzM4NCIsImtpZCI6InNlY3JldC1pZCIsInR5cCI6IkpXVCJ9.eyJFeHRlbnNpb25zIjpudWxsLCJHcm91cHMiOm51bGwsIklEIjoiMTk0ZmE4NTItMzk1Ny00YzU4LThjZTYtMGU5ZjUzNmJlYWViIiwiTmFtZSI6ImFkbWluIiwiYXVkIjpbIiJdLCJleHAiOjE2NTg1MzYwNDgsImlhdCI6MTY1ODUzMjQ0OCwibmJmIjoxNjU4NTMyNDQ4LCJzY29wZSI6WyJrZXlzOnNlYXJjaCIsImtleXM6Y3JlYXRlIiwia2V5czpkZWxldGUiLCJrZXlfdHJhbnNmZXJfcG9saWNpZXM6Y3JlYXRlIiwia2V5X3RyYW5zZmVyX3BvbGljaWVzOnNlYXJjaCIsImtleV90cmFuc2Zlcl9wb2xpY2llczpkZWxldGUiLCJ1c2VyczpkZWxldGUiLCJ1c2VyczpzZWFyY2giLCJ1c2VyczpjcmVhdGUiLCJ1c2Vyczp1cGRhdGUiXSwic3ViIjoiMTk0ZmE4NTItMzk1Ny00YzU4LThjZTYtMGU5ZjUzNmJlYWViIn0.BeN32PkOb8L7o4hpbONP1VCFT4WjKkBcAhZ6AsXAoV061z_HpELnLDcGqQvwwVdn95o99n5WMhq1HnSuUlpsWb-YrTcL5cYlHgFZkpKE3FA2y_owagxvtMSdlsTPmEa6g8DIoFX0HgWi7ZIXQOwmzefOmvIOrkjfVv18JOyu12AE6-HpAvmhRcWEQOZdMUjEjIcINvWIialVG1L7Re2HJngbZL1EEVt1ow_giBMkUiIrnImQQ6eoasW063trVQNjdDowlfrDpCPBX026vfRl9666DnsHVHRPMH6HSpiMx34aIWPDaP9LkZE_Z-BZaIlrhV9EJ3UguAnGXhvCt8JRrc9eKGfjQ7t4PL998XtekssHxu0W9KpyyclclFbdQPZ_6ErlqRLC14Hzex1LYfE-Es-0KrA1GVM06FMWZ6Y4ge3acQ8OxVKPZagBaJ5d5S4-PiRKZU_aYCzqcdtd1rrg9aWgNv7UCAV7uVnBgklw8Obat_4FjSU4ECzqlkxkap2j", nil)
	handler := createMockHandler(mockService)

	err := setCreateAuthTokenHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	userCreds := `{
		"username": "admin",
		"password": "password"
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/token", bytes.NewReader([]byte(userCreds)))
	// invalid accept header
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
	g.Expect(recorder.Code).To(gomega.Equal(http.StatusUnsupportedMediaType))

	// invalid content-type header
	req.Header.Set("Accept", HTTPMediaTypeJWT)
	req.Header.Set("Content-type", "txt/plain")

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

func TestCreateJWTTokenEmptyRequest(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mockService := &MockService{}
	mockService.On("CreateAuthToken", mock.Anything, mock.Anything).Return("eyJhbGciOiJQUzM4NCIsImtpZCI6InNlY3JldC1pZCIsInR5cCI6IkpXVCJ9.eyJFeHRlbnNpb25zIjpudWxsLCJHcm91cHMiOm51bGwsIklEIjoiMTk0ZmE4NTItMzk1Ny00YzU4LThjZTYtMGU5ZjUzNmJlYWViIiwiTmFtZSI6ImFkbWluIiwiYXVkIjpbIiJdLCJleHAiOjE2NTg1MzYwNDgsImlhdCI6MTY1ODUzMjQ0OCwibmJmIjoxNjU4NTMyNDQ4LCJzY29wZSI6WyJrZXlzOnNlYXJjaCIsImtleXM6Y3JlYXRlIiwia2V5czpkZWxldGUiLCJrZXlfdHJhbnNmZXJfcG9saWNpZXM6Y3JlYXRlIiwia2V5X3RyYW5zZmVyX3BvbGljaWVzOnNlYXJjaCIsImtleV90cmFuc2Zlcl9wb2xpY2llczpkZWxldGUiLCJ1c2VyczpkZWxldGUiLCJ1c2VyczpzZWFyY2giLCJ1c2VyczpjcmVhdGUiLCJ1c2Vyczp1cGRhdGUiXSwic3ViIjoiMTk0ZmE4NTItMzk1Ny00YzU4LThjZTYtMGU5ZjUzNmJlYWViIn0.BeN32PkOb8L7o4hpbONP1VCFT4WjKkBcAhZ6AsXAoV061z_HpELnLDcGqQvwwVdn95o99n5WMhq1HnSuUlpsWb-YrTcL5cYlHgFZkpKE3FA2y_owagxvtMSdlsTPmEa6g8DIoFX0HgWi7ZIXQOwmzefOmvIOrkjfVv18JOyu12AE6-HpAvmhRcWEQOZdMUjEjIcINvWIialVG1L7Re2HJngbZL1EEVt1ow_giBMkUiIrnImQQ6eoasW063trVQNjdDowlfrDpCPBX026vfRl9666DnsHVHRPMH6HSpiMx34aIWPDaP9LkZE_Z-BZaIlrhV9EJ3UguAnGXhvCt8JRrc9eKGfjQ7t4PL998XtekssHxu0W9KpyyclclFbdQPZ_6ErlqRLC14Hzex1LYfE-Es-0KrA1GVM06FMWZ6Y4ge3acQ8OxVKPZagBaJ5d5S4-PiRKZU_aYCzqcdtd1rrg9aWgNv7UCAV7uVnBgklw8Obat_4FjSU4ECzqlkxkap2j", nil)
	handler := createMockHandler(mockService)

	err := setCreateAuthTokenHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/token", bytes.NewReader([]byte("")))
	req.Header.Set("Accept", HTTPMediaTypeJWT)
	req.Header.Set("Content-type", HTTPMediaTypeJson)

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

func TestCreateJWTTokenInvalidContent(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mockService := &MockService{}
	mockService.On("CreateAuthToken", mock.Anything, mock.Anything).Return("eyJhbGciOiJQUzM4NCIsImtpZCI6InNlY3JldC1pZCIsInR5cCI6IkpXVCJ9.eyJFeHRlbnNpb25zIjpudWxsLCJHcm91cHMiOm51bGwsIklEIjoiMTk0ZmE4NTItMzk1Ny00YzU4LThjZTYtMGU5ZjUzNmJlYWViIiwiTmFtZSI6ImFkbWluIiwiYXVkIjpbIiJdLCJleHAiOjE2NTg1MzYwNDgsImlhdCI6MTY1ODUzMjQ0OCwibmJmIjoxNjU4NTMyNDQ4LCJzY29wZSI6WyJrZXlzOnNlYXJjaCIsImtleXM6Y3JlYXRlIiwia2V5czpkZWxldGUiLCJrZXlfdHJhbnNmZXJfcG9saWNpZXM6Y3JlYXRlIiwia2V5X3RyYW5zZmVyX3BvbGljaWVzOnNlYXJjaCIsImtleV90cmFuc2Zlcl9wb2xpY2llczpkZWxldGUiLCJ1c2VyczpkZWxldGUiLCJ1c2VyczpzZWFyY2giLCJ1c2VyczpjcmVhdGUiLCJ1c2Vyczp1cGRhdGUiXSwic3ViIjoiMTk0ZmE4NTItMzk1Ny00YzU4LThjZTYtMGU5ZjUzNmJlYWViIn0.BeN32PkOb8L7o4hpbONP1VCFT4WjKkBcAhZ6AsXAoV061z_HpELnLDcGqQvwwVdn95o99n5WMhq1HnSuUlpsWb-YrTcL5cYlHgFZkpKE3FA2y_owagxvtMSdlsTPmEa6g8DIoFX0HgWi7ZIXQOwmzefOmvIOrkjfVv18JOyu12AE6-HpAvmhRcWEQOZdMUjEjIcINvWIialVG1L7Re2HJngbZL1EEVt1ow_giBMkUiIrnImQQ6eoasW063trVQNjdDowlfrDpCPBX026vfRl9666DnsHVHRPMH6HSpiMx34aIWPDaP9LkZE_Z-BZaIlrhV9EJ3UguAnGXhvCt8JRrc9eKGfjQ7t4PL998XtekssHxu0W9KpyyclclFbdQPZ_6ErlqRLC14Hzex1LYfE-Es-0KrA1GVM06FMWZ6Y4ge3acQ8OxVKPZagBaJ5d5S4-PiRKZU_aYCzqcdtd1rrg9aWgNv7UCAV7uVnBgklw8Obat_4FjSU4ECzqlkxkap2j", nil)
	handler := createMockHandler(mockService)

	err := setCreateAuthTokenHandler(mockService, mux.NewRouter(), nil, jwtAuth)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	userCreds := `{
		"username": "admin",
	}`

	req, _ := http.NewRequest(http.MethodPost, "/kbs/v1/token", bytes.NewReader([]byte(userCreds)))
	// invalid accept header
	req.Header.Set("Accept", HTTPMediaTypeJWT)
	req.Header.Set("Content-type", HTTPMediaTypeJson)

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

func getTokenForTesting() string {
	jwtAuthz := service.SetupGoguardianForTest()
	u := auth.NewUserInfo("testAdmin", "testAdmin", nil, nil)
	ns := jwt.SetNamedScopes(constant.AdminPermissions...)
	exp := jwt.SetExpDuration(constant.DefaultTokenExpiration)
	token, err := jwt.IssueAccessToken(u, jwtAuthz.JwtSecretKeeper, ns, exp)
	if err != nil {
		log.WithError(err).Error("Error while generating a token")
		return ""
	}
	return token
}
