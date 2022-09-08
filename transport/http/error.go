/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package http

import (
	"errors"
)

var (
	ErrInvalidRequest           = errors.New("Invalid request body")
	ErrJsonDecodeFailed         = errors.New("Failed to JSON-decode request body")
	ErrEmptyRequestBody         = errors.New("Request body was not provided")
	ErrReadRequestFailed        = errors.New("Failed to read request body")
	ErrInvalidContentTypeHeader = errors.New("Invalid Content-type header")
	ErrInvalidAcceptHeader      = errors.New("Invalid Accept header")
	ErrBase64DecodeFailed       = errors.New("Failed to base64-decode request header")
	ErrTooManyQueryParams       = errors.New("Invalid query parameters provided. Number of query parameters exceeded maximum value")
	ErrInvalidQueryParam        = errors.New("Invalid query parameter provided. Refer to API doc for details.")
	ErrInvalidFilterCriteria    = errors.New("Invalid filter criteria")
	ErrInvalidAttestationType   = errors.New("Invalid attestion type header")
)
