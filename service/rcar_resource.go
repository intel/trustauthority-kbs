/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
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
// Phase 3 scope supports key resources at /resource/{repository}/key/{uuid}.
func (svc service) GetRCARResource(_ context.Context, addr *model.ResourceAddress) ([]byte, error) {
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

	secret, err := svc.remoteManager.TransferKey(id)
	if err != nil {
		if err.Error() == RecordNotFound {
			return nil, &HandledError{Code: http.StatusNotFound, Message: "resource not found"}
		}
		return nil, &HandledError{Code: http.StatusInternalServerError, Message: "failed to retrieve resource"}
	}

	return secret, nil
}
