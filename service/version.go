/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"github.com/sirupsen/logrus"
	"time"

	"intel/kbs/v1/version"
)

func (mw loggingMiddleware) GetVersion(ctx context.Context) (*version.ServiceVersion, error) {
	var err error
	defer func(begin time.Time) {
		logrus.Infof("GetVersion took %s since %s", time.Since(begin), begin)
		if err != nil {
			logrus.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.GetVersion(ctx)
	return resp, err
}

func (svc service) GetVersion(ctx context.Context) (*version.ServiceVersion, error) {
	return version.GetVersion(), nil
}
