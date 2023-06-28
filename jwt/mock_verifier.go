/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package jwt

import (
	"github.com/stretchr/testify/mock"
)

// MockVerifier is a mock of Verifier interface
type MockVerifier struct {
	mock.Mock
}

// NewMockVerifier creates a new mock instance
func NewMockVerifier() *MockVerifier {
	return &MockVerifier{}
}

func (v *MockVerifier) ValidateTokenAndGetClaims(tokenString string, customClaims interface{}) (*Token, error) {
	args := v.Called(tokenString, customClaims)
	return args.Get(0).(*Token), args.Error(1)
}
