/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package directory

import (
	"encoding/json"
	"os"
	"path/filepath"

	"intel/kbs/v1/model"

	"github.com/pkg/errors"
)

const resourcePolicyFileName = "default"

type resourcePolicyStore struct {
	dir string
}

func NewResourcePolicyStore(dir string) *resourcePolicyStore {
	return &resourcePolicyStore{dir: dir}
}

func (rps *resourcePolicyStore) Set(policy *model.ResourcePolicy) error {
	bytes, err := json.Marshal(policy)
	if err != nil {
		return errors.Wrap(err, "directory/resource_policy_store:Set() failed to marshal resource policy")
	}

	if err := os.MkdirAll(rps.dir, 0700); err != nil {
		return errors.Wrap(err, "directory/resource_policy_store:Set() failed to create policy directory")
	}

	if err := os.WriteFile(filepath.Clean(filepath.Join(rps.dir, resourcePolicyFileName)), bytes, 0600); err != nil {
		return errors.Wrap(err, "directory/resource_policy_store:Set() failed to persist resource policy")
	}

	return nil
}