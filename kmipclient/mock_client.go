/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package kmipclient

import (
	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
	"github.com/stretchr/testify/mock"
)

// MockKmipClient is a mock of KmipClient interface
type MockKmipClient struct {
	mock.Mock
}

// NewMockKmipClient creates a new mock instance
func NewMockKmipClient() *MockKmipClient {
	return &MockKmipClient{}
}

// InitializeClient mocks base method
func (m *MockKmipClient) InitializeClient(version, serverIP, serverPort, hostname, username, password, clientKey, clientCert, rootCert string) error {
	args := m.Called(version, serverIP, serverPort, clientKey, clientCert, rootCert, username, password)
	return args.Error(0)
}

// CreateSymmetricKey mocks base method
func (m *MockKmipClient) CreateSymmetricKey(length int) (string, error) {
	args := m.Called(length)
	return args.Get(0).(string), args.Error(1)
}

// CreateAsymmetricKeyPair mocks base method
func (m *MockKmipClient) CreateAsymmetricKeyPair(algorithm, curveType string, length int) (string, error) {
	args := m.Called(length)
	return args.Get(0).(string), args.Error(1)
}

// DeleteSymmetricKey mocks base method
func (m *MockKmipClient) DeleteKey(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

// GetSymmetricKey mocks base method
func (m *MockKmipClient) GetKey(id string, algorithm string) ([]byte, error) {
	args := m.Called(id)
	return args.Get(0).([]byte), args.Error(1)
}

// SendRequest mocks base method
func (m *MockKmipClient) SendRequest(requestPayload interface{}, Operation kmip14.Operation) (*kmip.ResponseBatchItem, *ttlv.Decoder, error) {
	args := m.Called(requestPayload, Operation)
	return args.Get(0).(*kmip.ResponseBatchItem), args.Get(1).(*ttlv.Decoder), args.Error(2)
}
