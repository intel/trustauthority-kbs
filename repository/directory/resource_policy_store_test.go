/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package directory

import (
	"os"
	"path/filepath"
	"testing"

	"intel/kbs/v1/model"
)

func TestResourcePolicyStoreSet(t *testing.T) {
	dir := t.TempDir()
	store := NewResourcePolicyStore(filepath.Join(dir, "resource-policy"))

	policy := &model.ResourcePolicy{Policy: "cG9saWN5"}
	if err := store.Set(policy); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	policyFile := filepath.Join(dir, "resource-policy", resourcePolicyFileName)
	if _, err := os.Stat(policyFile); err != nil {
		t.Fatalf("expected policy file to exist, stat error = %v", err)
	}
}
