/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"intel/kbs/v1/model"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func (mw loggingMiddleware) GetRCARResource(ctx context.Context, addr *model.ResourceAddress) ([]byte, error) {
	var err error
	defer func(begin time.Time) {
		logrus.Tracef("GetRCARResource took %s since %s", time.Since(begin), begin)
		if err != nil {
			logrus.WithError(err)
		}
	}(time.Now())

	resp, err := mw.next.GetRCARResource(ctx, addr)
	return resp, err
}

// GetRCARResource resolves a RCAR resource path to resource bytes.
// If a resource policy has been configured it is evaluated using OPA/Rego against the
// attestation token claims stored in the context; the resource is only released when the
// policy returns allow = true.  When no policy is configured the resource is released for
// any attested session (backwards-compatible default).
func (svc service) GetRCARResource(ctx context.Context, addr *model.ResourceAddress) ([]byte, error) {
	if addr == nil {
		return nil, &HandledError{Code: http.StatusBadRequest, Message: "resource address is required"}
	}

	// --- Trustee resource policy evaluation ---
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

			if token, ok := rcarAttestationTokenFromContext(ctx); ok {
				claims, err := parseTokenClaims(token)
				if err != nil {
					logrus.WithError(err).Warn("failed to parse attestation token claims for policy evaluation")
				}
				input.TokenClaims = claims
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

	// --- Resource resolution ---
	if addr.Type != "key" {
		return nil, &HandledError{Code: http.StatusNotFound, Message: "resource type not found"}
	}

	id, err := uuid.Parse(addr.Tag)
	if err != nil {
		return nil, &HandledError{Code: http.StatusNotFound, Message: "resource not found"}
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
