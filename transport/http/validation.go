/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package http

import (
	"fmt"
	"intel/amber/kbs/v1/constant"
	"net/url"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

var (
	idReg              = fmt.Sprintf("{id:%s}", constant.UUIDReg)
	stringReg          = regexp.MustCompile("(^[a-zA-Z0-9_ \\/.-]*$)")
	pemEncodedKeyReg   = regexp.MustCompile("(^[-a-zA-Z0-9//=+\012 ]*$)")
	sha256HexStringReg = regexp.MustCompile("^[a-fA-F0-9]{64}$")
	sha384HexStringReg = regexp.MustCompile("^[a-fA-F0-9]{96}$")
)

// ValidateStrings method is used to validate input strings
func ValidateStrings(strings []string) error {
	for _, stringValue := range strings {
		if !stringReg.MatchString(stringValue) {
			return errors.New("Invalid string formatted input")
		}
	}
	return nil
}

// ValidatePemEncodedKey method is used to validate input keys in PEM format
func ValidatePemEncodedKey(key string) error {
	in := strings.TrimSpace(key)
	if in == "" || !pemEncodedKeyReg.MatchString(in) {
		return errors.New("Invalid pem format")
	}
	return nil
}

// ValidateSha256HexString method checks if a string is a valid hex string of 32 bytes
func ValidateSha256HexString(value string) error {
	in := strings.TrimSpace(value)
	if in == "" || !sha256HexStringReg.MatchString(in) {
		return errors.New("invalid SHA256 hex string format")
	}
	return nil
}

// ValidateSha384HexString method checks if a string is a valid hex string of 48 bytes
func ValidateSha384HexString(value string) error {
	in := strings.TrimSpace(value)
	if in == "" || !sha384HexStringReg.MatchString(value) {
		return errors.New("invalid SHA384 hex string format")
	}
	return nil
}

func ValidateQueryParamKeys(params url.Values, validQueries map[string]bool) error {
	if len(params) > constant.MaxQueryParamsLength {
		return ErrTooManyQueryParams
	}
	for param := range params {
		if _, hasQuery := validQueries[param]; !hasQuery {
			return ErrInvalidQueryParam
		}
	}
	return nil
}
