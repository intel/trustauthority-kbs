/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"context"
	"time"

	"intel/kbs/v1/version"

	log "github.com/sirupsen/logrus"
)

func (mw loggingMiddleware) GetVersion(ctx context.Context) (*version.ServiceVersion, error) {
	var err error
	defer func(begin time.Time) {
		log.Infof("GetVersion took %s since %s", time.Since(begin), begin)
		if err != nil {
			log.WithError(err)
		}
	}(time.Now())
	resp, err := mw.next.GetVersion(ctx)
	return resp, err
}

func (svc service) GetVersion(ctx context.Context) (*version.ServiceVersion, error) {
	return version.GetVersion(), nil
}
