/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import "testing"

func TestResourcePolicyValidate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *ResourcePolicy
		wantErr bool
	}{
		{name: "valid", policy: &ResourcePolicy{Policy: "cG9saWN5"}, wantErr: false},
		{name: "nil policy", policy: nil, wantErr: true},
		{name: "empty policy", policy: &ResourcePolicy{Policy: ""}, wantErr: true},
		{name: "invalid base64", policy: &ResourcePolicy{Policy: "not-base64@"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}