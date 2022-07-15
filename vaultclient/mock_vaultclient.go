/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package vaultclient

import (
	"github.com/stretchr/testify/mock"
	"intel/amber/kbs/v1/model"
)

// MockVaultClient is a mock of VaultClient interface
type MockVaultClient struct {
	mock.Mock
}

// NewMockVaultClient creates a new mock instance
func NewMockVaultClient() *MockVaultClient {
	return &MockVaultClient{}
}

// InitializeClient mocks base method
func (m *MockVaultClient) InitializeClient(serverIP, serverPort, clientToken string) error {
	args := m.Called(serverIP, serverPort, clientToken)
	return args.Error(0)
}

// CreateKey mocks base method
func (m *MockVaultClient) CreateKey(keyAttrib *model.KeyAttributes) error {
	args := m.Called(keyAttrib)
	return args.Error(0)
}

// DeleteKey mocks base method
func (m *MockVaultClient) DeleteKey(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

// GetKey mocks base method
func (m *MockVaultClient) GetKey(id string) ([]byte, error) {
	args := m.Called(id)
	return args.Get(0).([]byte), args.Error(1)
}

// ListKeys mocks base method
func (m *MockVaultClient) ListKeys() ([]interface{}, error) {
	args := m.Called()
	return args.Get(0).([]interface{}), args.Error(1)
}
