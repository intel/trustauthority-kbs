/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	"encoding/base64"
	"strings"

	"github.com/pkg/errors"
)

// ResourcePolicy represents the payload for POST /kbs/v0/resource-policy.
type ResourcePolicy struct {
	Policy string `json:"policy"`
}

func (rp *ResourcePolicy) Validate() error {
	if rp == nil {
		return errors.New("request cannot be nil")
	}

	if strings.TrimSpace(rp.Policy) == "" {
		return errors.New("policy is required")
	}

	if _, err := base64.StdEncoding.DecodeString(rp.Policy); err != nil {
		return errors.Wrap(err, "policy must be base64 encoded")
	}

	return nil
}