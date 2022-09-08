/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package http

import (
	"context"
	"net/http"

	"intel/amber/kbs/v1/config"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/service"
	"intel/amber/kbs/v1/version"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

const (
	HTTPMediaTypeJson = "application/json"
	HTTPMediaTypeJWT  = "application/jwt"
	HTTPMediaTypePem  = "application/x-pem-file"
)

func init() {
	log.SetReportCaller(true)
	log.SetLevel(log.DebugLevel)
}

//-------------------------------------------------------------------------------------------------
// MockService
//-------------------------------------------------------------------------------------------------
type MockService struct {
	mock.Mock
}

func (svc *MockService) DeleteKeyTransferPolicy(ctx context.Context, id uuid.UUID) (interface{}, error) {
	args := svc.Called(ctx, id)
	return args.Get(0).(interface{}), args.Error(1)
}

func (svc *MockService) DeleteKey(ctx context.Context, keyId uuid.UUID) (interface{}, error) {
	args := svc.Called(ctx)
	return args.Get(0).(interface{}), args.Error(1)
}

func (svc *MockService) CreateKeyTransferPolicy(ctx context.Context, ktp model.KeyTransferPolicy) (*model.KeyTransferPolicy, error) {
	args := svc.Called(ctx, ktp)
	return args.Get(0).(*model.KeyTransferPolicy), args.Error(1)
}

func (svc *MockService) RetrieveKeyTransferPolicy(ctx context.Context, id uuid.UUID) (interface{}, error) {
	args := svc.Called(ctx, id)
	return args.Get(0).(interface{}), args.Error(1)
}

func (svc *MockService) CreateKey(ctx context.Context, req model.KeyRequest) (*model.KeyResponse, error) {
	args := svc.Called(ctx)
	return args.Get(0).(*model.KeyResponse), args.Error(1)
}

func (svc *MockService) RetrieveKey(ctx context.Context, keyId uuid.UUID) (interface{}, error) {
	args := svc.Called(ctx)
	return args.Get(0).(interface{}), args.Error(1)
}

func (svc *MockService) GetVersion(ctx context.Context) (*version.ServiceVersion, error) {
	args := svc.Called(ctx)
	return args.Get(0).(*version.ServiceVersion), args.Error(1)
}

func (svc *MockService) SearchKeyTransferPolicies(ctx context.Context, filter *model.KeyTransferPolicyFilterCriteria) ([]model.KeyTransferPolicy, error) {
	args := svc.Called(ctx, filter)
	return args.Get(0).([]model.KeyTransferPolicy), args.Error(1)
}

func (svc *MockService) TransferKey(ctx context.Context, req service.TransferKeyRequest) (*service.TransferKeyResponse, error) {
	args := svc.Called(ctx)
	return args.Get(0).(*service.TransferKeyResponse), args.Error(1)
}

func (svc *MockService) TransferKeyWithEvidence(ctx context.Context, req service.TransferKeyRequest) (*service.TransferKeyResponse, error) {
	args := svc.Called(ctx)
	return args.Get(0).(*service.TransferKeyResponse), args.Error(1)
}

func (svc *MockService) SearchKeys(ctx context.Context, filter *model.KeyFilterCriteria) ([]*model.KeyResponse, error) {
	args := svc.Called(ctx)
	return args.Get(0).([]*model.KeyResponse), args.Error(1)
}

func (svc *MockService) CreateUser(ctx context.Context, user *model.User) (*model.UserResponse, error) {
	args := svc.Called(ctx)
	return args.Get(0).(*model.UserResponse), args.Error(1)
}

func (svc *MockService) UpdateUser(ctx context.Context, request *model.UpdateUserRequest) (*model.UserResponse, error) {
	args := svc.Called(ctx)
	return args.Get(0).(*model.UserResponse), args.Error(1)
}

func (svc *MockService) SearchUser(ctx context.Context, criteria *model.UserFilterCriteria) ([]model.UserResponse, error) {
	args := svc.Called(ctx)
	return args.Get(0).([]model.UserResponse), args.Error(1)
}

func (svc *MockService) DeleteUser(ctx context.Context, u uuid.UUID) (interface{}, error) {
	args := svc.Called(ctx)
	return args.Get(0).(interface{}), args.Error(1)
}

func (svc *MockService) RetrieveUser(ctx context.Context, u uuid.UUID) (interface{}, error) {
	args := svc.Called(ctx)
	return args.Get(0).(interface{}), args.Error(1)
}

func (svc *MockService) CreateAuthToken(ctx context.Context, request model.AuthTokenRequest, authz *model.JwtAuthz) (string, error) {
	args := svc.Called(ctx)
	return args.Get(0).(string), args.Error(1)
}

func createMockHandler(mockService *MockService) http.Handler {
	cfg := config.Configuration{
		ServicePort: 12780,
		LogCaller:   true,
		LogLevel:    "debug",
	}

	handler, _ := NewHTTPHandler(mockService, &cfg, service.SetupGoguardianForTest())
	return handler
}
