/*
 *   Copyright (c) 2024 Oracle Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package ociclient

import (
	"intel/kbs/v1/model"

	"github.com/stretchr/testify/mock"
)

// MockOCIClient is a mock of OCIClient interface
type MockOCIClient struct {
	mock.Mock
}

// NewMockOCIClient creates a new mock instance
func NewMockOCIClient() *MockOCIClient {
	return &MockOCIClient{}
}

// InitializeClient mocks base method
func (m *MockOCIClient) InitializeClient(serverIP, serverPort, clientToken string) error {
	args := m.Called(serverIP, serverPort, clientToken)
	return args.Error(0)
}

// CreateKey mocks base method
func (m *MockOCIClient) CreateKey(keyAttrib *model.KeyAttributes) error {
	args := m.Called(keyAttrib)
	return args.Error(0)
}

// DeleteKey mocks base method
func (m *MockOCIClient) DeleteKey(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

// GetKey mocks base method
func (m *MockOCIClient) GetKey(id string) ([]byte, error) {
	args := m.Called(id)
	return args.Get(0).([]byte), args.Error(1)
}