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

type ResourcePolicy struct {
	// Base64-encoded Rego policy module content.
	// required: true
	Policy string `json:"policy"`
}

func (rp *ResourcePolicy) Validate() error {
	if rp == nil {
		return errors.New("request cannot be nil")
	}

	if strings.TrimSpace(rp.Policy) == "" {
		return errors.New("policy is required")
	}

	if _, err := decodePolicyValue(rp.Policy); err != nil {
		return errors.Wrap(err, "policy must be base64 encoded")
	}

	return nil
}

func decodePolicyValue(policy string) ([]byte, error) {
	decoders := []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
	}

	for _, decode := range decoders {
		decoded, err := decode(policy)
		if err == nil {
			return decoded, nil
		}
	}

	return nil, errors.New("unsupported base64 encoding")
}
