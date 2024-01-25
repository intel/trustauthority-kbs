/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

type Middleware func(Service) Service

func LoggingMiddleware() Middleware {
	return func(next Service) Service {
		return loggingMiddleware{next}
	}
}

type loggingMiddleware struct {
	next Service
}
