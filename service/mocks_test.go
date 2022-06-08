/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"context"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"intel/amber/kbs/v1/model"
)

type serviceTest struct {
	svc         service
	shouldErr   bool
	description string
}

type mockService struct {
	mock.Mock
}

func (mock *mockService) CreateKey(ctx context.Context, req model.KeyRequest) (*model.KeyResponse, error) {
	args := mock.Called(ctx, req)
	return args.Get(0).(*model.KeyResponse), args.Error(1)
}

func (mock *mockService) SearchKeys(ctx context.Context, criteria *model.KeyFilterCriteria) ([]*model.KeyResponse, error) {
	args := mock.Called(ctx, criteria)
	return args.Get(0).([]*model.KeyResponse), args.Error(1)
}

func (mock *mockService) DeleteKey(ctx context.Context, uuid uuid.UUID) (interface{}, error) {
	args := mock.Called(ctx, uuid)
	return args.Get(0).(interface{}), args.Error(1)
}

func (mock *mockService) RetrieveKey(ctx context.Context, uuid uuid.UUID) (interface{}, error) {
	args := mock.Called(ctx, uuid)
	return args.Get(0).(interface{}), args.Error(1)
}

func (mock *mockService) TransferKey(ctx context.Context, req TransferKeyRequest) (*TransferKeyResponse, error) {
	args := mock.Called(ctx, req)
	return args.Get(0).(*TransferKeyResponse), args.Error(1)
}
