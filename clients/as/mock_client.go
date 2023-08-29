/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package as

import (
	"github.com/stretchr/testify/mock"
)

// MockClient is a mock of ASClient interface
type MockClient struct {
	mock.Mock
}

// NewMockClient creates a new mock instance
func NewMockClient() *MockClient {
	return &MockClient{}
}

// GetAttestationToken mocks base method
func (m *MockClient) GetAttestationToken(req *AttestationTokenRequest) (string, error) {
	args := m.Called(req)
	return args.Get(0).(string), args.Error(1)
}

// GetNonce mocks base method
func (m *MockClient) GetNonce() (*VerifierNonce, error) {
	args := m.Called()
	return args.Get(0).(*VerifierNonce), args.Error(1)
}
