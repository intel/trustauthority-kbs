/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"encoding/base64"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/pkg/errors"
)

// ResourcePolicyInput carries both Trustee policy data and claims.
// During evaluation:
//   - token claims are passed as OPA input
//   - plugin/path/query are passed as OPA data
type ResourcePolicyInput struct {
	// Plugin is the first path segment used by Trustee-style policies.
	Plugin string `json:"plugin,omitempty"`
	// ResourcePathSegments are the remaining path segments after the plugin name.
	ResourcePathSegments []string `json:"resource-path,omitempty"`
	// Query contains request query parameters for plugin-aware policies.
	Query map[string]string `json:"query,omitempty"`
	// ResourcePath keeps the legacy flattened RCAR path alias.
	ResourcePath string `json:"resource_path,omitempty"`
	// TokenClaims holds the attestation token claims for policy decisions.
	TokenClaims map[string]interface{} `json:"token_claims,omitempty"`
}

func (input ResourcePolicyInput) policyDataMap() map[string]interface{} {
	data := map[string]interface{}{}
	if input.Plugin != "" {
		data["plugin"] = input.Plugin
	}
	if len(input.ResourcePathSegments) > 0 {
		data["resource-path"] = input.ResourcePathSegments
	}
	if len(input.Query) > 0 {
		query := make(map[string]interface{}, len(input.Query))
		for key, value := range input.Query {
			query[key] = value
		}
		data["query"] = query
	}
	if input.ResourcePath != "" {
		data["resource_path"] = input.ResourcePath
	}
	return data
}

func (input ResourcePolicyInput) claimsInputMap() map[string]interface{} {
	claims := map[string]interface{}{}
	for key, value := range input.TokenClaims {
		claims[key] = value
	}
	return claims
}

// PolicyEvaluator evaluates a resource-policy against a ResourcePolicyInput.
type PolicyEvaluator interface {
	Allow(ctx context.Context, input ResourcePolicyInput) (bool, error)
}

// regoEvaluator is an OPA-backed PolicyEvaluator.
type regoEvaluator struct {
	policyText string
}

// NewOPAEvaluator constructs a PolicyEvaluator from decoded (plain-text) Rego policy content.
func NewOPAEvaluator(policyText string) PolicyEvaluator {
	return &regoEvaluator{policyText: policyText}
}

// Allow evaluates `data.policy.allow == true` against the provided input.
func (re *regoEvaluator) Allow(ctx context.Context, input ResourcePolicyInput) (bool, error) {
	r := rego.New(
		rego.Query("data.policy.allow == true"),
		rego.Module("resource_policy.rego", re.policyText),
		rego.Store(inmem.NewFromObject(input.policyDataMap())),
		rego.Input(input.claimsInputMap()),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return false, errors.Wrap(err, "rego evaluation failed")
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false, nil
	}

	allowed, ok := rs[0].Expressions[0].Value.(bool)
	return ok && allowed, nil
}

// buildEvaluatorFromPolicy decodes the base64-encoded policy and constructs an evaluator.
// Returns (nil, nil) when no policy has been configured (allow-by-default).
func buildEvaluatorFromPolicy(policyB64 string) (PolicyEvaluator, error) {
	if policyB64 == "" {
		return nil, nil
	}
	decoded, err := decodePolicyBytes(policyB64)
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64-decode resource policy")
	}
	return NewOPAEvaluator(string(decoded)), nil
}

func decodePolicyBytes(policyB64 string) ([]byte, error) {
	decoders := []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
	}

	for _, decode := range decoders {
		decoded, err := decode(policyB64)
		if err == nil {
			return decoded, nil
		}
	}

	return nil, errors.New("unsupported base64 encoding")
}
