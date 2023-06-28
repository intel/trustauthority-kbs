/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
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
