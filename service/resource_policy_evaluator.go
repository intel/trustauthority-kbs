/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"intel/kbs/v1/model"

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

// ExtractTEEPubKeyFromToken retrieves the tee-pubkey from attester_runtime_data in the token claims.
// Handles both v1 (top-level) and v2 (nested under tdx/sgx) token layouts.
func ExtractTEEPubKeyFromToken(token string) (*model.JWK, error) {
	claims, err := parseTokenClaims(token)
	if err != nil {
		return nil, err
	}

	runtimeRaw := runtimeDataFromClaims(claims)
	if runtimeRaw == nil {
		return nil, errors.New("attester_runtime_data not found in token claims")
	}

	var runtimeBytes []byte
	switch v := runtimeRaw.(type) {
	case string:
		for _, dec := range []func(string) ([]byte, error){
			base64.RawURLEncoding.DecodeString,
			base64.URLEncoding.DecodeString,
			base64.StdEncoding.DecodeString,
			base64.RawStdEncoding.DecodeString,
		} {
			if runtimeBytes, err = dec(v); err == nil {
				break
			}
		}
		if runtimeBytes == nil {
			return nil, errors.New("failed to base64-decode attester_runtime_data")
		}
	case map[string]interface{}:
		if runtimeBytes, err = json.Marshal(v); err != nil {
			return nil, errors.Wrap(err, "failed to marshal attester_runtime_data")
		}
	default:
		return nil, errors.Errorf("unexpected attester_runtime_data type %T", runtimeRaw)
	}

	var rtd struct {
		TEEPubKey model.JWK `json:"tee-pubkey"`
	}
	if err := json.Unmarshal(runtimeBytes, &rtd); err != nil {
		return nil, errors.Wrap(err, "failed to parse runtime data")
	}
	if err := rtd.TEEPubKey.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid tee-pubkey in runtime data")
	}
	return &rtd.TEEPubKey, nil
}

// runtimeDataFromClaims finds attester_runtime_data at top level (v1) or under tdx/sgx (v2).
func runtimeDataFromClaims(claims map[string]interface{}) interface{} {
	if v, ok := claims["attester_runtime_data"]; ok {
		return v
	}
	for _, key := range []string{"tdx", "sgx"} {
		if sub, ok := claims[key].(map[string]interface{}); ok {
			if v, ok := sub["attester_runtime_data"]; ok {
				return v
			}
		}
	}
	return nil
}

// parseTokenClaims extracts the JWT payload claims from a raw JWT string without
// re-verifying the signature (signature already verified during /attest).
func parseTokenClaims(token string) (map[string]interface{}, error) {
	if token == "" {
		return nil, nil
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT structure")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode JWT payload")
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JWT claims")
	}

	return claims, nil
}
