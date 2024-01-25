/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"github.com/stretchr/testify/mock"
	"intel/kbs/v1/kmipclient"
	"intel/kbs/v1/model"
)

type MockKmipManager struct {
	client kmipclient.MockKmipClient
	mock.Mock
}

func NewMockKmipManager(c kmipclient.MockKmipClient) *MockKmipManager {
	return &MockKmipManager{c, mock.Mock{}}
}
func (mock *MockKmipManager) CreateKey(request *model.KeyRequest) (*model.KeyAttributes, error) {
	args := mock.Called(request)
	return args.Get(0).(*model.KeyAttributes), args.Error(1)
}

func (mock *MockKmipManager) DeleteKey(attributes *model.KeyAttributes) error {
	args := mock.Called(attributes)
	return args.Error(0)
}

func (mock *MockKmipManager) RegisterKey(request *model.KeyRequest) (*model.KeyAttributes, error) {
	args := mock.Called(request)
	return args.Get(0).(*model.KeyAttributes), args.Error(1)
}

func (mock *MockKmipManager) TransferKey(attributes *model.KeyAttributes) ([]byte, error) {
	args := mock.Called(attributes)
	return args.Get(0).([]byte), args.Error(1)
}
