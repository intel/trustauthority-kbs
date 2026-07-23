/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"intel/kbs/v1/constant"
	"net/http"
	"time"

	"intel/kbs/v1/model"

	"github.com/sirupsen/logrus"
)

func (mw loggingMiddleware) SetResourcePolicy(ctx context.Context, policy model.ResourcePolicy) error {
	log = logrus.WithField("user", ctx.Value(constant.LogUserID))
	var err error
	defer func(begin time.Time) {
		log.Tracef("SetResourcePolicy took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	err = mw.next.SetResourcePolicy(ctx, policy)
	return err
}

func (svc service) SetResourcePolicy(_ context.Context, policy model.ResourcePolicy) error {
	err := svc.repository.ResourcePolicyStore.Set(&policy)
	if err != nil {
		log.WithError(err).Error("Resource policy set failed")
		return &HandledError{Code: http.StatusInternalServerError, Message: "Failed to set resource policy"}
	}

	return nil
}