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
	"fmt"
	"net/http"
	"time"

	"intel/kbs/v1/model"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (mw loggingMiddleware) GetRCARResource(ctx context.Context, token string, addr *model.ResourceAddress) (*model.JWEFlattened, error) {
	var err error
	defer func(begin time.Time) {
		logrus.Tracef("GetRCARResource took %s since %s", time.Since(begin), begin)
		if err != nil {
			logrus.WithError(err)
		}
	}(time.Now())

	resp, err := mw.next.GetRCARResource(ctx, token, addr)
	return resp, err
}

// GetRCARResource resolves a RCAR resource path to resource bytes.
// If a resource policy has been configured it is evaluated using OPA/Rego against the
// attestation token claims stored in the context; the resource is only released when the
// policy returns allow = true.  When no policy is configured the resource is released for
// any attested session (backwards-compatible default).
func (svc service) getRawRCARResource(ctx context.Context, claims jwt.MapClaims, addr *model.ResourceAddress) ([]byte, error) {
	// --- Resource resolution ---
	if addr == nil {
		return nil, &HandledError{Code: http.StatusBadRequest, Message: "resource address is required"}
	}

	if addr.Type != "key" {
		return nil, &HandledError{Code: http.StatusNotFound, Message: "resource type not found"}
	}

	id, err := uuid.Parse(addr.Tag)
	if err != nil {
		return nil, &HandledError{Code: http.StatusNotFound, Message: "resource not found"}
	}

	// --- Resource policy evaluation ---
	storedPolicy, err := svc.repository.ResourcePolicyStore.Get()
	if err != nil {
		logrus.WithError(err).Error("failed to load resource policy")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "failed to load resource policy"}
	}

	if storedPolicy != nil {
		evaluator, err := buildEvaluatorFromPolicy(storedPolicy.Policy)
		if err != nil {
			logrus.WithError(err).Error("resource policy is malformed")
			return nil, &HandledError{Code: http.StatusInternalServerError, Message: "resource policy is malformed"}
		}

		if evaluator != nil {
			resourcePath := fmt.Sprintf("%s/%s/%s", addr.Repository, addr.Type, addr.Tag)
			input := ResourcePolicyInput{
				Plugin:               "resource",
				ResourcePathSegments: []string{addr.Repository, addr.Type, addr.Tag},
				ResourcePath:         resourcePath,
				Query:                map[string]string{},
			}

			if claims != nil {
				input.TokenClaims = map[string]interface{}(claims)
			}

			allowed, err := evaluator.Allow(ctx, input)
			if err != nil {
				logrus.WithError(err).Error("resource policy evaluation failed")
				return nil, &HandledError{Code: http.StatusInternalServerError, Message: "resource policy evaluation failed"}
			}

			if !allowed {
				logrus.WithField("resource", resourcePath).Info("resource policy denied access")
				return nil, &HandledError{Code: http.StatusForbidden, Message: "resource policy denied access to this resource"}
			}
		}
	}

	secret, err := svc.remoteManager.TransferKey(id)
	if err != nil {
		logrus.WithError(err).Error("failed to retrieve resource from remote manager")
		if err.Error() == RecordNotFound {
			return nil, &HandledError{Code: http.StatusNotFound, Message: "resource not found"}
		}
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "failed to retrieve resource"}
	}

	return secret, nil
}

func (svc service) GetRCARResource(ctx context.Context, token string, addr *model.ResourceAddress) (*model.JWEFlattened, error) {
	verifiedToken, err := svc.itaClient.VerifyToken(token)
	if err != nil {
		logrus.WithError(err).Error("attestation token verification failed")
		return nil, &HandledError{Code: http.StatusUnauthorized, Message: "attestation token verification failed"}
	}
	claims, _ := verifiedToken.Claims.(jwt.MapClaims)

	resource, err := svc.getRawRCARResource(ctx, claims, addr)
	if err != nil {
		logrus.WithError(err).Error("failed to retrieve resource")
		return nil, err
	}

	teePubKey, err := extractTEEPubKeyFromToken(claims)
	if err != nil {
		logrus.WithError(err).Error("failed to extract tee-pubkey from attestation token")
		return nil, &HandledError{Code: http.StatusBadRequest, Message: "invalid tee pub key in token"}
	}

	jweResp, err := encryptResourceAsFlattenedJWE(teePubKey, resource)
	if err != nil {
		logrus.WithError(err).Error("failed to encrypt resource response")
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "failed to encrypt resource response"}
	}

	return jweResp, nil
}

// extractTEEPubKeyFromToken retrieves the tee-pubkey from attester_runtime_data in the token claims.
// Handles both v1 (top-level) and v2 (nested under tdx/sgx) token layouts.
func extractTEEPubKeyFromToken(claims jwt.MapClaims) (*model.JWK, error) {
	runtimeRaw := runtimeDataFromClaims(map[string]interface{}(claims))
	if runtimeRaw == nil {
		return nil, errors.New("attester_runtime_data not found in token claims")
	}

	var (
		runtimeBytes []byte
		err          error
	)
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
