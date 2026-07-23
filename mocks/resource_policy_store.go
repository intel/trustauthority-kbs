/*
 * Copyright(C) 2026 Intel Corporation. All Rights Reserved.
 */
package mocks

import "intel/kbs/v1/model"

type MockResourcePolicyStore struct {
	LastPolicy *model.ResourcePolicy
	Err        error
}

func NewMockResourcePolicyStore() *MockResourcePolicyStore {
	return &MockResourcePolicyStore{}
}

func (m *MockResourcePolicyStore) Set(policy *model.ResourcePolicy) error {
	m.LastPolicy = policy
	return m.Err
}

func (m *MockResourcePolicyStore) Get() (*model.ResourcePolicy, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.LastPolicy, nil
}
